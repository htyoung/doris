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

package org.apache.doris.datasource;

public enum TableFormatType {
    HIVE("hive"),
    ICEBERG("iceberg"),
    HUDI("hudi"),
    PAIMON("paimon"),
    MAX_COMPUTE("max_compute"),
    TRANSACTIONAL_HIVE("transactional_hive"),
    LAKESOUL("lakesoul"),
    TRINO_CONNECTOR("trino_connector"),
    TVF("tvf");

    private final String tableFormatType;

    TableFormatType(String tableFormatType) {
        this.tableFormatType = tableFormatType;
    }

    public String value() {
        return tableFormatType;
    }
}
