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


suite("test_cast_to_float_from_decimal64_18_0") {

    // This test case is generated from the correspoinding be UT test case,
    // update this case if the correspoinding be UT test case is updated,
    // e.g.: ../run-be-ut.sh --run --filter=FunctionCastToDecimalTest.* --gen_regression_case
    sql "drop table if exists test_cast_to_float_from_decimal64_18_0_0_nullable;"
    sql "create table test_cast_to_float_from_decimal64_18_0_0_nullable(f1 int, f2 decimalv3(18, 0)) properties('replication_num'='1');"
    sql """insert into test_cast_to_float_from_decimal64_18_0_0_nullable values (0, "0"),(1, "0"),(2, "1"),(3, "-1"),(4, "9"),(5, "-9"),(6, "99999999999999999"),(7, "-99999999999999999"),(8, "900000000000000000"),(9, "-900000000000000000"),(10, "900000000000000001"),(11, "-900000000000000001"),(12, "999999999999999998"),(13, "-999999999999999998"),(14, "999999999999999999"),(15, "-999999999999999999")
      ,(16, null);
    """

    sql "set enable_strict_cast=true;"
    qt_sql_0_strict 'select f1, cast(f2 as float) from test_cast_to_float_from_decimal64_18_0_0_nullable order by 1;'

    sql "set enable_strict_cast=false;"
    qt_sql_0_non_strict 'select f1, cast(f2 as float) from test_cast_to_float_from_decimal64_18_0_0_nullable order by 1;'

    sql "drop table if exists test_cast_to_float_from_decimal64_18_0_0_not_nullable;"
    sql "create table test_cast_to_float_from_decimal64_18_0_0_not_nullable(f1 int, f2 decimalv3(18, 0)) properties('replication_num'='1');"
    sql """insert into test_cast_to_float_from_decimal64_18_0_0_not_nullable values (0, "0"),(1, "0"),(2, "1"),(3, "-1"),(4, "9"),(5, "-9"),(6, "99999999999999999"),(7, "-99999999999999999"),(8, "900000000000000000"),(9, "-900000000000000000"),(10, "900000000000000001"),(11, "-900000000000000001"),(12, "999999999999999998"),(13, "-999999999999999998"),(14, "999999999999999999"),(15, "-999999999999999999");
    """

    sql "set enable_strict_cast=true;"
    qt_sql_0_strict 'select f1, cast(f2 as float) from test_cast_to_float_from_decimal64_18_0_0_not_nullable order by 1;'

    sql "set enable_strict_cast=false;"
    qt_sql_0_non_strict 'select f1, cast(f2 as float) from test_cast_to_float_from_decimal64_18_0_0_not_nullable order by 1;'

}