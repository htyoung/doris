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

import org.junit.Assert

suite("test_flexible_partial_update_publish_conflict") {
    if (isCloudMode()) {
        logger.info("skip test_flexible_partial_update_publish_conflict in cloud mode")
        return
    }
    def dbName = context.config.getDbNameByFile(context.file)
    def tableName = "test_flexible_partial_update_publish_conflict"
    sql """ DROP TABLE IF EXISTS ${tableName} FORCE;"""
    sql """ CREATE TABLE ${tableName} (
        `k` int(11) NULL, 
        `v1` BIGINT NULL,
        `v2` BIGINT NULL DEFAULT "9876",
        `v3` BIGINT NOT NULL,
        `v4` BIGINT NOT NULL DEFAULT "1234",
        `v5` BIGINT NULL
        ) UNIQUE KEY(`k`) DISTRIBUTED BY HASH(`k`) BUCKETS 1
        PROPERTIES(
        "replication_num" = "1",
        "enable_unique_key_merge_on_write" = "true",
        "light_schema_change" = "true",
        "enable_unique_key_skip_bitmap_column" = "true",
        "store_row_column" = "false"); """
    def show_res = sql "show create table ${tableName}"
    assertTrue(show_res.toString().contains('"enable_unique_key_skip_bitmap_column" = "true"'))
    sql """insert into ${tableName} select number, number, number, number, number, number from numbers("number" = "6"); """
    order_qt_sql "select k,v1,v2,v3,v4,v5,BITMAP_TO_STRING(__DORIS_SKIP_BITMAP_COL__) from ${tableName};"

    def do_streamload_2pc_commit = { txnId ->
        def command = "curl -X PUT --location-trusted -u ${context.config.feHttpUser}:${context.config.feHttpPassword}" +
                " -H txn_id:${txnId}" +
                " -H txn_operation:commit" +
                " http://${context.config.feHttpAddress}/api/${dbName}/${tableName}/_stream_load_2pc"
        log.info("http_stream execute 2pc: ${command}")

        def process = command.execute()
        def code = process.waitFor()
        def out = process.text
        def json2pc = parseJson(out)
        log.info("http_stream 2pc result: ${out}".toString())
        assertEquals(code, 0)
        assertEquals("success", json2pc.status.toLowerCase())
    }

    def wait_for_publish = {txnId, waitSecond ->
        String st = "PREPARE"
        while (!st.equalsIgnoreCase("VISIBLE") && !st.equalsIgnoreCase("ABORTED") && waitSecond > 0) {
            Thread.sleep(1000)
            waitSecond -= 1
            def result = sql_return_maparray "show transaction from ${dbName} where id = ${txnId}"
            assertNotNull(result)
            st = result[0].TransactionStatus
        }
        log.info("Stream load with txn ${txnId} is ${st}")
        assertEquals(st, "VISIBLE")
    }

    // block the partial update in publish phase
    def txnId1, txnId2
    streamLoad {
        table "${tableName}"
        set 'format', 'json'
        set 'read_json_by_line', 'true'
        set 'strict_mode', 'false'
        set 'two_phase_commit', 'true'
        set 'unique_key_update_mode', 'UPDATE_FLEXIBLE_COLUMNS'
        file "test1.json"
        time 40000
        check { result, exception, startTime, endTime ->
            if (exception != null) {
                throw exception
            }
            
            def json = parseJson(result)
            txnId1 = json.TxnId
            assertEquals("success", json.Status.toLowerCase())
        }
    }

    streamLoad {
        table "${tableName}"
        set 'format', 'json'
        set 'read_json_by_line', 'true'
        set 'strict_mode', 'false'
        set 'two_phase_commit', 'true'
        set 'unique_key_update_mode', 'UPDATE_FLEXIBLE_COLUMNS'
        file "test2.json"
        time 40000
        check { result, exception, startTime, endTime ->
            if (exception != null) {
                throw exception
            }
            
            def json = parseJson(result)
            txnId2 = json.TxnId
            assertEquals("success", json.Status.toLowerCase())
        }
    }

    do_streamload_2pc_commit(txnId1)
    wait_for_publish(txnId1, 60)
    do_streamload_2pc_commit(txnId2)
    wait_for_publish(txnId2, 60)

    order_qt_sql "select k,v1,v2,v3,v4,v5,BITMAP_TO_STRING(__DORIS_SKIP_BITMAP_COL__) from ${tableName};"


    // ==================================================================================================
    // publish alignment read from rowsets which have multi-segments
    sql "truncate table ${tableName}"

    def txnId3, txnId4, txnId5

    String load3 = """1,1,1,1,1,1
2,2,2,2,2,2"""
    streamLoad {
        table "${tableName}"
        set 'column_separator', ','
        set 'format', 'csv'
        set 'two_phase_commit', 'true'
        inputStream new ByteArrayInputStream(load3.getBytes())
        time 60000 // limit inflight 60s
        check { result, exception, startTime, endTime ->
            if (exception != null) {
                throw exception
            }
            
            def json = parseJson(result)
            txnId3 = json.TxnId
            assertEquals("success", json.Status.toLowerCase())
        }
    }

    String load4 = """1,99,99,99"""
    streamLoad {
        table "${tableName}"
        set 'column_separator', ','
        set 'format', 'csv'
        set 'columns', 'k,v1,v2,v3'
        set 'strict_mode', "false"
        set 'two_phase_commit', 'true'
        set 'unique_key_update_mode', 'UPDATE_FIXED_COLUMNS'
        inputStream new ByteArrayInputStream(load4.getBytes())
        time 40000
        check { result, exception, startTime, endTime ->
            if (exception != null) {
                throw exception
            }
            
            def json = parseJson(result)
            txnId4 = json.TxnId
            assertEquals("success", json.Status.toLowerCase())
        }
    }

    streamLoad {
        table "${tableName}"
        set 'format', 'json'
        set 'read_json_by_line', 'true'
        set 'strict_mode', 'false'
        set 'two_phase_commit', 'true'
        set 'unique_key_update_mode', 'UPDATE_FLEXIBLE_COLUMNS'
        file "test5.json"
        time 40000
        check { result, exception, startTime, endTime ->
            if (exception != null) {
                throw exception
            }
            
            def json = parseJson(result)
            txnId5 = json.TxnId
            assertEquals("success", json.Status.toLowerCase())
        }
    }
    // let t3 and t4 publish
    do_streamload_2pc_commit(txnId3)
    wait_for_publish(txnId3, 60)
    do_streamload_2pc_commit(txnId4)
    wait_for_publish(txnId4, 60)
    qt_sql1 "select k,v1,v2,v3,v4,v5 from ${tableName} order by k;"

    do_streamload_2pc_commit(txnId5)
    wait_for_publish(txnId5, 60)
    qt_sql2 "select k,v1,v2,v3,v4,v5 from ${tableName} order by k;"
}
