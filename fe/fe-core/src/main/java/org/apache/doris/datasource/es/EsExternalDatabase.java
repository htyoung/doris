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

package org.apache.doris.datasource.es;

import org.apache.doris.datasource.ExternalCatalog;
import org.apache.doris.datasource.ExternalDatabase;
import org.apache.doris.datasource.InitDatabaseLog;

/**
 * Elasticsearch metastore external database.
 */
public class EsExternalDatabase extends ExternalDatabase<EsExternalTable> {

    /**
     * Create Elasticsearch external database.
     *
     * @param extCatalog External data source this database belongs to.
     * @param id database id.
     * @param name database name.
     * @param remoteName remote database name.
     */
    public EsExternalDatabase(ExternalCatalog extCatalog, long id, String name, String remoteName) {
        super(extCatalog, id, name, remoteName, InitDatabaseLog.Type.ES);
    }

    @Override
    public EsExternalTable buildTableInternal(String remoteTableName, String localTableName, long tblId,
            ExternalCatalog catalog,
            ExternalDatabase db) {
        return new EsExternalTable(tblId, localTableName, remoteTableName, (EsExternalCatalog) extCatalog,
                (EsExternalDatabase) db);
    }
}
