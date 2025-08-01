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


suite("test_cast_to_decimal64_from_float_overflow_const") {

    // This test case is generated from the correspoinding be UT test case,
    // update this case if the correspoinding be UT test case is updated,
    // e.g.: ../run-be-ut.sh --run --filter=FunctionCastToDecimalTest.* --gen_regression_case
    sql "set debug_skip_fold_constant = true;"
    sql "set debug_skip_fold_constant = true;"
    def test_cast_to_decimal_18_0_from_float_invalid_0_test_data = ["""1.1e+18""","""-1.1e+18""","""inf""","""-inf""","""nan""","""-nan"""]
    sql "set enable_strict_cast=true;"

    for (b in ["false", "true"]) {
        sql """set debug_skip_fold_constant = "${b}";"""
        for (test_str in test_cast_to_decimal_18_0_from_float_invalid_0_test_data) {
            test {
                sql """select cast(cast("${test_str}" as float) as decimalv3(18, 0));"""
                exception ""
            }
        }
    }
    sql "set enable_strict_cast=false;"

    for (test_str in test_cast_to_decimal_18_0_from_float_invalid_0_test_data) {
        qt_sql_test_cast_to_decimal_18_0_from_float_invalid_0 """select cast(cast("${test_str}" as float) as decimalv3(18, 0));"""
        testFoldConst("""select cast(cast("${test_str}" as float) as decimalv3(18, 0));""")
    }
    sql "set debug_skip_fold_constant = true;"
    def test_cast_to_decimal_18_9_from_float_invalid_1_test_data = ["""1100000000""","""-1100000000""","""inf""","""-inf""","""nan""","""-nan"""]
    sql "set enable_strict_cast=true;"

    for (b in ["false", "true"]) {
        sql """set debug_skip_fold_constant = "${b}";"""
        for (test_str in test_cast_to_decimal_18_9_from_float_invalid_1_test_data) {
            test {
                sql """select cast(cast("${test_str}" as float) as decimalv3(18, 9));"""
                exception ""
            }
        }
    }
    sql "set enable_strict_cast=false;"

    for (test_str in test_cast_to_decimal_18_9_from_float_invalid_1_test_data) {
        qt_sql_test_cast_to_decimal_18_9_from_float_invalid_1 """select cast(cast("${test_str}" as float) as decimalv3(18, 9));"""
        testFoldConst("""select cast(cast("${test_str}" as float) as decimalv3(18, 9));""")
    }
    sql "set debug_skip_fold_constant = true;"
    def test_cast_to_decimal_18_17_from_float_invalid_2_test_data = ["""10""","""-10""","""inf""","""-inf""","""nan""","""-nan"""]
    sql "set enable_strict_cast=true;"

    for (b in ["false", "true"]) {
        sql """set debug_skip_fold_constant = "${b}";"""
        for (test_str in test_cast_to_decimal_18_17_from_float_invalid_2_test_data) {
            test {
                sql """select cast(cast("${test_str}" as float) as decimalv3(18, 17));"""
                exception ""
            }
        }
    }
    sql "set enable_strict_cast=false;"

    for (test_str in test_cast_to_decimal_18_17_from_float_invalid_2_test_data) {
        qt_sql_test_cast_to_decimal_18_17_from_float_invalid_2 """select cast(cast("${test_str}" as float) as decimalv3(18, 17));"""
        testFoldConst("""select cast(cast("${test_str}" as float) as decimalv3(18, 17));""")
    }
}