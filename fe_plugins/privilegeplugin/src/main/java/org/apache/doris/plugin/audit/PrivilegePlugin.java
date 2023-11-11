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

package org.apache.doris.plugin.audit;

import org.apache.doris.analysis.CreateTableAsSelectStmt;
import org.apache.doris.analysis.CreateTableLikeStmt;
import org.apache.doris.analysis.CreateTableStmt;
import org.apache.doris.analysis.SqlParser;
import org.apache.doris.analysis.SqlScanner;
import org.apache.doris.analysis.StatementBase;
import org.apache.doris.analysis.UserIdentity;
import org.apache.doris.catalog.AccessPrivilege;
import org.apache.doris.catalog.Env;
import org.apache.doris.common.AnalysisException;
import org.apache.doris.common.util.SqlParserUtils;
import org.apache.doris.plugin.AuditEvent;
import org.apache.doris.plugin.AuditEvent.EventType;
import org.apache.doris.plugin.AuditPlugin;
import org.apache.doris.plugin.Plugin;
import org.apache.doris.plugin.PluginContext;
import org.apache.doris.plugin.PluginException;
import org.apache.doris.plugin.PluginInfo;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.qe.StmtExecutor;
import org.apache.doris.system.SystemInfoService;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class PrivilegePlugin extends Plugin implements AuditPlugin {
    private static final Logger LOG = LogManager.getLogger(PrivilegePlugin.class);
    private static final Pattern CREATE_TABLE_NAME_PATTERN = Pattern.compile(
            "^\\s*CREATE\\s+TABLE\\s+(`?(\\w+:)?(\\w+)`?\\.)?`?(\\w+)`?\\s*\\(.*$",
            Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

    private PrivilegePluginConf conf;
    private volatile boolean isClosed = false;
    private volatile boolean isInit = false;
    private BlockingQueue<AuditEvent> auditEventQueue;
    private Thread privilegeThread;

    @Override
    public void init(PluginInfo info, PluginContext ctx) throws PluginException {
        super.init(info, ctx);
        synchronized (this) {
            if (isInit) {
                return;
            }
            loadConfig(ctx, info.getProperties());
            this.auditEventQueue = new LinkedBlockingQueue<>(conf.maxQueueSize);
            this.privilegeThread = new Thread(() -> {
                while (!isClosed) {
                    try {
                        AuditEvent event = auditEventQueue.poll(5, TimeUnit.SECONDS);
                        if (event != null) {
                            parseCreateStmt(event);
                        }
                    } catch (InterruptedException ie) {
                        LOG.debug("encounter exception when loading current audit batch", ie);
                    } catch (Exception e) {
                        LOG.error("run audit logger error:", e);
                    }
                }
            }, "privilege-plugin-thread");
            this.privilegeThread.start();
            isInit = true;
        }
    }

    private void loadConfig(PluginContext ctx, Map<String, String> pluginInfoProperties) throws PluginException {
        Path pluginPath = FileSystems.getDefault().getPath(ctx.getPluginPath());
        if (!Files.exists(pluginPath)) {
            throw new PluginException("plugin path does not exist: " + pluginPath);
        }

        Path confFile = pluginPath.resolve("plugin.conf");
        if (!Files.exists(confFile)) {
            throw new PluginException("plugin conf file does not exist: " + confFile);
        }

        final Properties props = new Properties();
        try (InputStream stream = Files.newInputStream(confFile)) {
            props.load(stream);
        } catch (IOException e) {
            throw new PluginException(e.getMessage());
        }

        for (Map.Entry<String, String> entry : pluginInfoProperties.entrySet()) {
            props.setProperty(entry.getKey(), entry.getValue());
        }

        final Map<String, String> properties = props.stringPropertyNames().stream()
                .collect(Collectors.toMap(Function.identity(), props::getProperty));
        conf = new PrivilegePluginConf();
        conf.init(properties);
    }

    @Override
    public void close() throws IOException {
        super.close();
        isClosed = true;
        if (privilegeThread != null) {
            try {
                privilegeThread.join();
            } catch (InterruptedException e) {
                LOG.debug("encounter exception when closing the privilege plugin", e);
            }
        }
        LOG.info("this is privilege plugin close");
    }

    public boolean eventFilter(AuditEvent.EventType type) {
        return type == EventType.AFTER_QUERY;
    }

    public void exec(AuditEvent event) {
        try {
            auditEventQueue.add(event);
        } catch (Exception e) {
            // In order to ensure that the system can run normally, here we directly
            // discard the current audit_event. If this problem occurs frequently,
            // improvement can be considered.
            LOG.debug("encounter exception when putting current audit batch, discard current audit event", e);
        }
    }

    public void parseCreateStmt(AuditEvent event) {
        LOG.debug("privilege plugin log exec, event_state={}, event_type={},stmt_id={},query_id={}", event.state,
                event.type, event.stmtId, event.queryId);
        if (!"ERR".equals(event.state) && !event.isQuery) {
            SqlScanner input = new SqlScanner(new StringReader(event.stmt));
            SqlParser parser = new SqlParser(input);
            String dbName = event.db;
            try {
                StatementBase parsedStmt = SqlParserUtils.getStmt(parser, 0);
                String tableName;
                if (parsedStmt instanceof CreateTableStmt) {
                    CreateTableStmt createTableStmt = ((CreateTableStmt) parsedStmt);
                    if (StringUtils.isNotEmpty(createTableStmt.getDbName())) {
                        dbName = createTableStmt.getDbName();
                    }
                    tableName = createTableStmt.getTableName();
                    grantPrivilege(event.user, dbName, tableName, conf.privilegeList);
                } else if (parsedStmt instanceof CreateTableLikeStmt) {
                    CreateTableLikeStmt createTableLikeStmt = ((CreateTableLikeStmt) parsedStmt);
                    if (StringUtils.isNotEmpty(createTableLikeStmt.getDbName())) {
                        dbName = createTableLikeStmt.getDbName();
                    }
                    tableName = createTableLikeStmt.getTableName();
                    grantPrivilege(event.user, dbName, tableName, conf.privilegeList);
                } else if (parsedStmt instanceof CreateTableAsSelectStmt) {
                    CreateTableAsSelectStmt ctas = ((CreateTableAsSelectStmt) parsedStmt);
                    if (StringUtils.isNotEmpty(ctas.getCreateTableStmt().getDbName())) {
                        dbName = ctas.getCreateTableStmt().getDbName();
                    }
                    tableName = ctas.getCreateTableStmt().getTableName();
                    grantPrivilege(event.user, dbName, tableName, conf.privilegeList);
                } else {
                    LOG.info("stmt [{}] is not create table sql, skip", parsedStmt.toSql());
                }
            } catch (AnalysisException e) {
                //org.apache.doris.common.AnalysisException: errCode = 2, detailMessage = Syntax error
                if (e.getMessage().contains("Syntax error")) {
                    String[] fullTableName = getFullTableNameWithRegex(event.stmt);
                    if (StringUtils.isNotEmpty(fullTableName[1])) {
                        grantPrivilege(event.user, StringUtils.isNotEmpty(dbName) ? dbName : fullTableName[0],
                                fullTableName[1], conf.privilegeList);
                    }
                }
            } catch (Throwable e) {
                //catch SqlScanner throw new Error();
                LOG.error("parse create stmt error, stmt_id={},query_id={}", event.stmtId, event.queryId, e);
            }
        }
    }

    private void grantPrivilege(String user, String dbName, String tableName, List<AccessPrivilege> privilegeList) {
        if (StringUtils.isEmpty(dbName) || StringUtils.isEmpty(tableName)) {
            LOG.info("grant dbName={} or tableName={} is empty, skip", dbName, tableName);
            return;
        }
        try {
            UserIdentity toGrantUserIdentity = new UserIdentity(user, "%");
            toGrantUserIdentity.analyze(SystemInfoService.DEFAULT_CLUSTER);
            if (toGrantUserIdentity.isAdminUser() || toGrantUserIdentity.isRootUser()) {
                LOG.info("to grant user is {}, skip", user);
                return;
            }
        } catch (Exception e) {
            LOG.error("parsed to grant user={} error, can't grant", user, e);
            return;
        }
        try {
            String sql = "grant " + privilegeList.stream().map(Enum::name).collect(Collectors.joining(",")) + " on "
                    + dbName + "." + tableName + " to `" + user + "`";
            LOG.info("privilege plugin exec grant sql={}", sql);
            ConnectContext connectContext = getConnectContext();
            StmtExecutor stmtExecutor = new StmtExecutor(connectContext, sql);
            stmtExecutor.execute();
        } catch (Exception e) {
            LOG.error("grant {} on {}.{} to {} error", privilegeList, dbName, tableName, user, e);
        } finally {
            ConnectContext.remove();
        }
    }

    private ConnectContext getConnectContext() throws AnalysisException {
        // 新建一个ConnectContext对象，并放到threadLocal中;
        ConnectContext connectContext = new ConnectContext();
        connectContext.setThreadLocalInfo();
        //指定集群
        connectContext.setCluster(SystemInfoService.DEFAULT_CLUSTER);
        connectContext.setEnv(Env.getCurrentEnv());
        //指定操作授权的用户
        UserIdentity execGrantUserIdentity = new UserIdentity(conf.execGrantUser, "%");
        execGrantUserIdentity.analyze(SystemInfoService.DEFAULT_CLUSTER);
        connectContext.setCurrentUserIdentity(execGrantUserIdentity);
        connectContext.setQualifiedUser(execGrantUserIdentity.getQualifiedUser());
        return connectContext;
    }

    private static class PrivilegePluginConf {
        public static final String PRIVILEGES = "privileges";
        public static final String PROP_MAX_QUEUE_SIZE = "max_queue_size";
        public static final String EXEC_GRANT_USER = "exec_grant_user";
        private List<AccessPrivilege> privilegeList = Stream.of(AccessPrivilege.SELECT_PRIV, AccessPrivilege.LOAD_PRIV,
                AccessPrivilege.ALTER_PRIV, AccessPrivilege.DROP_PRIV).collect(Collectors.toList());
        private int maxQueueSize = 1000;
        private String execGrantUser = "admin";

        public void init(Map<String, String> properties) throws PluginException {
            try {
                if (properties.containsKey(PRIVILEGES)) {
                    String[] privilegeArray = properties.get(PRIVILEGES).split(",");
                    privilegeList = Arrays.stream(privilegeArray).map(AccessPrivilege::fromName)
                            .filter(Objects::nonNull).collect(Collectors.toList());
                }
                if (properties.containsKey(PROP_MAX_QUEUE_SIZE)) {
                    maxQueueSize = Integer.parseInt(properties.get(PROP_MAX_QUEUE_SIZE));
                }
                if (properties.containsKey(EXEC_GRANT_USER)) {
                    execGrantUser = properties.get(EXEC_GRANT_USER);
                }
            } catch (Exception e) {
                throw new PluginException(e.getMessage());
            }
        }
    }

    public static String[] getFullTableNameWithRegex(String stmt) {
        Matcher matcher = CREATE_TABLE_NAME_PATTERN.matcher(stmt);
        if (matcher.matches()) {
            return new String[] {Optional.ofNullable(matcher.group(3)).orElse(""), matcher.group(4)};
        } else {
            return new String[] {"", ""};
        }
    }
}
