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

#pragma once

#include <vector>

#include "common/status.h"
#include "io/io_common.h"
#include "olap/iterators.h"
#include "olap/rowset/rowset_fwd.h"
#include "olap/simple_rowid_conversion.h"
#include "olap/tablet_fwd.h"

namespace doris {
class KeyBoundsPB;
class RowIdConversion;
class RowsetWriter;

namespace segment_v2 {
class SegmentWriter;
} // namespace segment_v2

namespace vectorized {
class RowSourcesBuffer;
class VerticalBlockReader;
}; // namespace vectorized

class Merger {
public:
    struct Statistics {
        int64_t cloud_local_read_time = 0;
        int64_t cloud_remote_read_time = 0;
        // number of rows written to the destination rowset after merge
        int64_t output_rows = 0;
        int64_t merged_rows = 0;
        int64_t filtered_rows = 0;
        RowIdConversion* rowid_conversion = nullptr;
        // these data for trans
        int64_t cached_bytes_total = 0;
        int64_t bytes_read_from_local = 0;
        int64_t bytes_read_from_remote = 0;
    };

    // merge rows from `src_rowset_readers` and write into `dst_rowset_writer`.
    // return OK and set statistics into `*stats_output`.
    // return others on error

    static Status vmerge_rowsets(BaseTabletSPtr tablet, ReaderType reader_type,
                                 const TabletSchema& cur_tablet_schema,
                                 const std::vector<RowsetReaderSharedPtr>& src_rowset_readers,
                                 RowsetWriter* dst_rowset_writer, Statistics* stats_output);
    static Status vertical_merge_rowsets(
            BaseTabletSPtr tablet, ReaderType reader_type, const TabletSchema& tablet_schema,
            const std::vector<RowsetReaderSharedPtr>& src_rowset_readers,
            RowsetWriter* dst_rowset_writer, uint32_t max_rows_per_segment, int64_t merge_way_num,
            Statistics* stats_output);

    // for vertical compaction
    static void vertical_split_columns(const TabletSchema& tablet_schema,
                                       std::vector<std::vector<uint32_t>>* column_groups,
                                       std::vector<uint32_t>* key_group_cluster_key_idxes);
    static Status vertical_compact_one_group(
            BaseTabletSPtr tablet, ReaderType reader_type, const TabletSchema& tablet_schema,
            bool is_key, const std::vector<uint32_t>& column_group,
            vectorized::RowSourcesBuffer* row_source_buf,
            const std::vector<RowsetReaderSharedPtr>& src_rowset_readers,
            RowsetWriter* dst_rowset_writer, uint32_t max_rows_per_segment,
            Statistics* stats_output, std::vector<uint32_t> key_group_cluster_key_idxes,
            int64_t batch_size, CompactionSampleInfo* sample_info);

    // for segcompaction
    static Status vertical_compact_one_group(int64_t tablet_id, ReaderType reader_type,
                                             const TabletSchema& tablet_schema, bool is_key,
                                             const std::vector<uint32_t>& column_group,
                                             vectorized::RowSourcesBuffer* row_source_buf,
                                             vectorized::VerticalBlockReader& src_block_reader,
                                             segment_v2::SegmentWriter& dst_segment_writer,
                                             Statistics* stats_output, uint64_t* index_size,
                                             KeyBoundsPB& key_bounds,
                                             SimpleRowIdConversion* rowid_conversion);
};

} // namespace doris
