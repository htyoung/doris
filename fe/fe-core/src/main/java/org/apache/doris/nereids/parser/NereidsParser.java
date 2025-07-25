// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package org.apache.doris.nereids.parser;

import org.apache.doris.analysis.ExplainOptions;
import org.apache.doris.analysis.StatementBase;
import org.apache.doris.catalog.Env;
import org.apache.doris.common.Pair;
import org.apache.doris.nereids.DorisLexer;
import org.apache.doris.nereids.DorisParser;
import org.apache.doris.nereids.DorisParser.NonReservedContext;
import org.apache.doris.nereids.StatementContext;
import org.apache.doris.nereids.analyzer.UnboundSlot;
import org.apache.doris.nereids.glue.LogicalPlanAdapter;
import org.apache.doris.nereids.parser.plsql.PLSqlLogicalPlanBuilder;
import org.apache.doris.nereids.trees.expressions.Expression;
import org.apache.doris.nereids.trees.plans.commands.ExplainCommand.ExplainLevel;
import org.apache.doris.nereids.trees.plans.logical.LogicalPlan;
import org.apache.doris.nereids.types.DataType;
import org.apache.doris.plugin.DialectConverterPlugin;
import org.apache.doris.plugin.PluginMgr;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.qe.GlobalVariable;
import org.apache.doris.qe.OriginStatement;
import org.apache.doris.qe.SessionVariable;
import org.apache.doris.qe.SqlModeHelper;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.Recognizer;
import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.TokenSource;
import org.antlr.v4.runtime.atn.PredictionMode;
import org.antlr.v4.runtime.misc.ParseCancellationException;
import org.antlr.v4.runtime.tree.TerminalNode;
import org.apache.commons.collections.CollectionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.lang.reflect.Method;
import java.util.BitSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import javax.annotation.Nullable;

/**
 * Sql parser, convert sql DSL to logical plan.
 */
public class NereidsParser {
    public static final Logger LOG = LogManager.getLogger(NereidsParser.class);
    private static final ParseErrorListener PARSE_ERROR_LISTENER = new ParseErrorListener();
    private static final PostProcessor POST_PROCESSOR = new PostProcessor();

    private static final BitSet EXPLAIN_TOKENS = new BitSet();

    private static final Set<String> NON_RESERVED_KEYWORDS;
    private static final Map<String, Integer> LITERAL_TOKENS;

    static {
        EXPLAIN_TOKENS.set(DorisLexer.EXPLAIN);
        EXPLAIN_TOKENS.set(DorisLexer.PARSED);
        EXPLAIN_TOKENS.set(DorisLexer.ANALYZED);
        EXPLAIN_TOKENS.set(DorisLexer.LOGICAL);
        EXPLAIN_TOKENS.set(DorisLexer.REWRITTEN);
        EXPLAIN_TOKENS.set(DorisLexer.PHYSICAL);
        EXPLAIN_TOKENS.set(DorisLexer.OPTIMIZED);
        EXPLAIN_TOKENS.set(DorisLexer.PLAN);
        EXPLAIN_TOKENS.set(DorisLexer.PROCESS);

        ImmutableSet.Builder<String> nonReserveds = ImmutableSet.builder();
        for (Method declaredMethod : NonReservedContext.class.getDeclaredMethods()) {
            if (TerminalNode.class.equals(declaredMethod.getReturnType())
                    && declaredMethod.getName().toUpperCase().equals(declaredMethod.getName())
                    && declaredMethod.getParameterTypes().length == 0) {
                String nonReserved = declaredMethod.getName();
                nonReserveds.add(nonReserved);
            }
        }
        NON_RESERVED_KEYWORDS = nonReserveds.build();

        ImmutableMap.Builder<String, Integer> literalToTokenType = ImmutableMap.builder();
        for (int tokenType = 0; tokenType <= DorisLexer.VOCABULARY.getMaxTokenType(); tokenType++) {
            String literalName = DorisLexer.VOCABULARY.getLiteralName(tokenType);
            if (literalName != null) {
                literalToTokenType.put(literalName.substring(1, literalName.length() - 1), tokenType);
            }
        }
        LITERAL_TOKENS = literalToTokenType.build();
    }

    /**
     * In MySQL protocol, client could send multi-statement in a single packet.
     * see <a href="https://dev.mysql.com/doc/internals/en/com-set-option.html">docs</a> for more information.
     */
    public List<StatementBase> parseSQL(String originStr) {
        return parseSQL(originStr, (LogicalPlanBuilder) null);
    }

    /**
     * ParseSQL with dialect.
     */
    public List<StatementBase> parseSQL(String sql, SessionVariable sessionVariable) {
        return parseSQLWithDialect(sql, sessionVariable);
    }

    /**
     * ParseSQL with logicalPlanBuilder.
     */
    public List<StatementBase> parseSQL(String originStr, @Nullable LogicalPlanBuilder logicalPlanBuilder) {
        List<Pair<LogicalPlan, StatementContext>> logicalPlans = parseMultiple(originStr, logicalPlanBuilder);
        List<StatementBase> statementBases = Lists.newArrayList();
        for (Pair<LogicalPlan, StatementContext> parsedPlanToContext : logicalPlans) {
            statementBases.add(new LogicalPlanAdapter(parsedPlanToContext.first, parsedPlanToContext.second));
        }
        return statementBases;
    }

    /**
     * scan to token
     * for example: select id from tbl return Tokens: ['select', 'id', 'from', 'tbl']
     */
    public static TokenSource scan(String sql) {
        return new DorisLexer(new CaseInsensitiveStream(CharStreams.fromString(sql)));
    }

    /**
     * tryParseExplainPlan
     * @param sql sql
     * @return key: ExplainOptions, value: explain body
     */
    public static Optional<Pair<ExplainOptions, String>> tryParseExplainPlan(String sql) {
        try {
            TokenSource tokenSource = scan(sql);
            if (expect(tokenSource, DorisLexer.EXPLAIN) == null) {
                return Optional.empty();
            }

            Token token = readUntilNonComment(tokenSource);
            if (token == null) {
                return Optional.empty();
            }

            int tokenType = token.getType();
            ExplainLevel explainLevel = ExplainLevel.ALL_PLAN;
            if (tokenType == DorisLexer.PARSED) {
                explainLevel = ExplainLevel.PARSED_PLAN;
                token = readUntilNonComment(tokenSource);
            } else if (tokenType == DorisLexer.ANALYZED) {
                explainLevel = ExplainLevel.ANALYZED_PLAN;
                token = readUntilNonComment(tokenSource);
            } else if (tokenType == DorisLexer.LOGICAL || tokenType == DorisLexer.REWRITTEN) {
                explainLevel = ExplainLevel.REWRITTEN_PLAN;
                token = readUntilNonComment(tokenSource);
            } else if (tokenType == DorisLexer.PHYSICAL || tokenType == DorisLexer.OPTIMIZED) {
                explainLevel = ExplainLevel.OPTIMIZED_PLAN;
                token = readUntilNonComment(tokenSource);
            }

            if (token == null) {
                return Optional.empty();
            }
            tokenType = token.getType();
            if (tokenType != DorisLexer.PLAN) {
                return Optional.empty();
            }

            token = readUntilNonComment(tokenSource);
            Token explainPlanBody;
            boolean showPlanProcess = false;
            if (token.getType() == DorisLexer.PROCESS) {
                showPlanProcess = true;
                explainPlanBody = readUntilNonComment(tokenSource);
            } else {
                explainPlanBody = token;
            }

            if (explainPlanBody == null) {
                return Optional.empty();
            }
            ExplainOptions explainOptions = new ExplainOptions(explainLevel, showPlanProcess);
            return Optional.of(Pair.of(explainOptions, sql.substring(explainPlanBody.getStartIndex())));
        } catch (Throwable t) {
            return Optional.empty();
        }
    }

    private static Token expect(TokenSource tokenSource, int tokenType) {
        Token nextToken = readUntilNonComment(tokenSource);
        if (nextToken == null) {
            return null;
        }
        return nextToken.getType() == tokenType ? nextToken : null;
    }

    private static Token readUntilNonComment(TokenSource tokenSource) {
        Token token = tokenSource.nextToken();
        while (token != null) {
            int tokenType = token.getType();
            if (tokenType == DorisLexer.BRACKETED_COMMENT
                    || tokenType == DorisLexer.SIMPLE_COMMENT
                    || tokenType == DorisLexer.WS) {
                token = tokenSource.nextToken();
                continue;
            }
            break;
        }
        return token;
    }

    private List<StatementBase> parseSQLWithDialect(String sql,
                                                    SessionVariable sessionVariable) {
        @Nullable Dialect sqlDialect = Dialect.getByName(sessionVariable.getSqlDialect());
        if (sqlDialect == null) {
            return parseSQL(sql);
        }

        PluginMgr pluginMgr = Env.getCurrentEnv().getPluginMgr();
        List<DialectConverterPlugin> plugins = pluginMgr.getActiveDialectPluginList(sqlDialect);
        for (DialectConverterPlugin plugin : plugins) {
            try {
                List<StatementBase> statementBases = plugin.parseSqlWithDialect(sql, sessionVariable);
                if (CollectionUtils.isNotEmpty(statementBases)) {
                    return statementBases;
                }
            } catch (Throwable throwable) {
                LOG.warn("Parse sql with dialect {} failed, plugin: {}, sql: {}.",
                            sqlDialect, plugin.getClass().getSimpleName(), sql, throwable);
            }
        }

        if (ConnectContext.get().isRunProcedure()) {
            return parseSQL(sql, new PLSqlLogicalPlanBuilder());
        }
        // fallback if any exception occurs before
        return parseSQL(sql);
    }

    /**
     * parse sql DSL string.
     *
     * @param sql sql string
     * @return logical plan
     */
    public LogicalPlan parseSingle(String sql) {
        return parseSingle(sql, null);
    }

    /**
     * parse sql DSL string.
     *
     * @param sql sql string
     * @return logical plan
     */
    public LogicalPlan parseSingle(String sql, @Nullable LogicalPlanBuilder logicalPlanBuilder) {
        return parse(sql, logicalPlanBuilder, DorisParser::singleStatement);
    }

    public List<Pair<LogicalPlan, StatementContext>> parseMultiple(String sql) {
        return parseMultiple(sql, null);
    }

    /**
     * parse multiple sql statements.
     *
     * @param sql sql string
     * @param logicalPlanBuilder logical plan builder
     * @return logical plan
     */
    public List<Pair<LogicalPlan, StatementContext>> parseMultiple(String sql,
                                                                   @Nullable LogicalPlanBuilder logicalPlanBuilder) {
        List<Pair<LogicalPlan, StatementContext>> result = parse(sql, logicalPlanBuilder, DorisParser::multiStatements);
        // ensure each StatementContext has complete OriginStatement information
        for (int i = 0; i < result.size(); i++) {
            Pair<LogicalPlan, StatementContext> pair = result.get(i);
            StatementContext statementContext = pair.second;
            if (statementContext.getOriginStatement() == null) {
                statementContext.setOriginStatement(new OriginStatement(sql, i));
            }
        }
        return result;
    }

    public Expression parseExpression(String expression) {
        if (isSimpleIdentifier(expression)) {
            return new UnboundSlot(expression);
        }
        return parse(expression, DorisParser::expressionWithEof);
    }

    private static boolean isSimpleIdentifier(String expression) {
        if (expression == null || expression.isEmpty()) {
            return false;
        }

        boolean hasLetter = false;
        for (int i = 0; i < expression.length(); i++) {
            char c = expression.charAt(i);
            if ((('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || c == '_' || c == '$')) {
                hasLetter = true;
            } else if (!('0' <= c && c <= '9')) {
                return false;
            }
        }
        if (!hasLetter) {
            return false;
        }
        String upperCase = expression.toUpperCase();
        return (NON_RESERVED_KEYWORDS.contains(upperCase) || !LITERAL_TOKENS.containsKey(upperCase));
    }

    public DataType parseDataType(String dataType) {
        return parse(dataType, DorisParser::dataType);
    }

    public Map<String, String> parseProperties(String properties) {
        return parse(properties, DorisParser::propertyItemList);
    }

    private <T> T parse(String sql, Function<DorisParser, ParserRuleContext> parseFunction) {
        return parse(sql, null, parseFunction);
    }

    private <T> T parse(String sql, @Nullable LogicalPlanBuilder logicalPlanBuilder,
                        Function<DorisParser, ParserRuleContext> parseFunction) {
        CommonTokenStream tokenStream = parseAllTokens(sql);
        ParserRuleContext tree = toAst(tokenStream, parseFunction);
        LogicalPlanBuilder realLogicalPlanBuilder = logicalPlanBuilder == null
                    ? new LogicalPlanBuilder(getHintMap(sql, tokenStream, DorisParser::selectHint))
                    : logicalPlanBuilder;
        return (T) realLogicalPlanBuilder.visit(tree);
    }

    public LogicalPlan parseForCreateView(String sql) {
        CommonTokenStream tokenStream = parseAllTokens(sql);
        ParserRuleContext tree = toAst(tokenStream, DorisParser::singleStatement);
        LogicalPlanBuilder realLogicalPlanBuilder = new LogicalPlanBuilderForCreateView(
                getHintMap(sql, tokenStream, DorisParser::selectHint));
        return (LogicalPlan) realLogicalPlanBuilder.visit(tree);
    }

    public LogicalPlan parseForEncryption(String sql, Map<Pair<Integer, Integer>, String> indexInSqlToString) {
        CommonTokenStream tokenStream = parseAllTokens(sql);
        ParserRuleContext tree = toAst(tokenStream, DorisParser::singleStatement);
        LogicalPlanBuilder realLogicalPlanBuilder = new LogicalPlanBuilderForEncryption(
                getHintMap(sql, tokenStream, DorisParser::selectHint), indexInSqlToString);
        return (LogicalPlan) realLogicalPlanBuilder.visit(tree);
    }

    /** parseForSyncMv */
    public Optional<String> parseForSyncMv(String sql) {
        CommonTokenStream tokenStream = parseAllTokens(sql);
        ParserRuleContext tree = toAst(tokenStream, DorisParser::singleStatement);
        LogicalPlanBuilderForSyncMv logicalPlanBuilderForSyncMv = new LogicalPlanBuilderForSyncMv(
                getHintMap(sql, tokenStream, DorisParser::selectHint));
        logicalPlanBuilderForSyncMv.visit(tree);
        return logicalPlanBuilderForSyncMv.getQuerySql();
    }

    /** get hint map */
    public static Map<Integer, ParserRuleContext> getHintMap(String sql, CommonTokenStream hintTokenStream,
                                                             Function<DorisParser, ParserRuleContext> parseFunction) {
        // parse hint first round
        Map<Integer, ParserRuleContext> selectHintMap = Maps.newHashMap();

        Iterator<Token> tokenIterator = hintTokenStream.getTokens().iterator();
        Token hintToken = tokenIterator.hasNext() ? tokenIterator.next() : null;
        while (hintToken != null && hintToken.getType() != DorisLexer.EOF) {
            if (hintToken.getChannel() == 2 && sql.charAt(hintToken.getStartIndex() + 2) == '+') {
                String hintSql = sql.substring(hintToken.getStartIndex() + 3, hintToken.getStopIndex() + 1);
                DorisLexer newHintLexer = new DorisLexer(new CaseInsensitiveStream(CharStreams.fromString(hintSql)));
                CommonTokenStream newHintTokenStream = new CommonTokenStream(newHintLexer);
                DorisParser hintParser = new DorisParser(newHintTokenStream);
                ParserRuleContext hintContext = parseFunction.apply(hintParser);
                selectHintMap.put(hintToken.getStartIndex(), hintContext);
            }
            hintToken = tokenIterator.hasNext() ? tokenIterator.next() : null;
        }
        return selectHintMap;
    }

    public static ParserRuleContext toAst(
            String sql, Function<DorisParser, ParserRuleContext> parseFunction) {
        return toAst(parseAllTokens(sql), parseFunction);
    }

    /** toAst */
    public static ParserRuleContext toAst(
            CommonTokenStream tokenStream, Function<DorisParser, ParserRuleContext> parseFunction) {
        DorisParser parser = new DorisParser(tokenStream);
        parser.ansiSQLSyntax = GlobalVariable.enable_ansi_query_organization_behavior;
        parser.addParseListener(POST_PROCESSOR);
        parser.removeErrorListeners();
        parser.addErrorListener(PARSE_ERROR_LISTENER);

        ParserRuleContext tree;
        try {
            // first, try parsing with potentially faster SLL mode
            parser.getInterpreter().setPredictionMode(PredictionMode.SLL);
            tree = parseFunction.apply(parser);
        } catch (ParseCancellationException ex) {
            // if we fail, parse with LL mode
            tokenStream.seek(0); // rewind input stream
            parser.reset();

            parser.getInterpreter().setPredictionMode(PredictionMode.LL);
            tree = parseFunction.apply(parser);
        }
        return tree;
    }

    /**
     * removeCommentAndTrimBlank
     *
     * for example: select   \/*+SET_VAR(key=value)*\/ \/* trace_id: 1234 *\/ *,   a, \n b from table
     *
     * will be normalized to: select \/*+SET_VAR(key=value)*\/ * , a, b from table
     */
    public static String removeCommentAndTrimBlank(String sql) {
        CommonTokenStream tokenStream = parseAllTokens(sql);

        // maybe add more space char
        StringBuilder newSql = new StringBuilder((int) (sql.length() * 1.2));

        for (Token token : tokenStream.getTokens()) {
            int tokenType = token.getType();
            switch (tokenType) {
                case DorisLexer.SIMPLE_COMMENT:
                case DorisLexer.WS:
                case Recognizer.EOF:
                    break;
                case DorisLexer.BRACKETED_COMMENT:
                    String bracketedComment = token.getText();
                    // append hint
                    if (bracketedComment.startsWith("/*+")) {
                        newSql.append(bracketedComment);
                        newSql.append(" ");
                    }
                    break;
                default:
                    newSql.append(token.getText());
                    newSql.append(" ");
            }
        }
        return newSql.toString().trim();
    }

    private static CommonTokenStream parseAllTokens(String sql) {
        DorisLexer lexer = new DorisLexer(new CaseInsensitiveStream(CharStreams.fromString(sql)));
        lexer.isNoBackslashEscapes = SqlModeHelper.hasNoBackSlashEscapes();
        CommonTokenStream tokenStream = new CommonTokenStream(lexer);
        tokenStream.fill();
        return tokenStream;
    }
}
