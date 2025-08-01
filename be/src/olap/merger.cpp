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

#include "olap/merger.h"

#include <gen_cpp/olap_file.pb.h>
#include <gen_cpp/types.pb.h>
#include <stddef.h>
#include <unistd.h>

#include <algorithm>
#include <iterator>
#include <memory>
#include <mutex>
#include <numeric>
#include <ostream>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

#include "cloud/config.h"
#include "common/config.h"
#include "common/logging.h"
#include "common/status.h"
#include "olap/base_tablet.h"
#include "olap/iterators.h"
#include "olap/olap_common.h"
#include "olap/olap_define.h"
#include "olap/rowid_conversion.h"
#include "olap/rowset/rowset.h"
#include "olap/rowset/rowset_meta.h"
#include "olap/rowset/rowset_writer.h"
#include "olap/rowset/segment_v2/segment_writer.h"
#include "olap/storage_engine.h"
#include "olap/tablet.h"
#include "olap/tablet_fwd.h"
#include "olap/tablet_meta.h"
#include "olap/tablet_reader.h"
#include "olap/utils.h"
#include "util/slice.h"
#include "vec/core/block.h"
#include "vec/olap/block_reader.h"
#include "vec/olap/vertical_block_reader.h"
#include "vec/olap/vertical_merge_iterator.h"

namespace doris {
#include "common/compile_check_begin.h"
Status Merger::vmerge_rowsets(BaseTabletSPtr tablet, ReaderType reader_type,
                              const TabletSchema& cur_tablet_schema,
                              const std::vector<RowsetReaderSharedPtr>& src_rowset_readers,
                              RowsetWriter* dst_rowset_writer, Statistics* stats_output) {
    if (!cur_tablet_schema.cluster_key_uids().empty()) {
        return Status::InternalError(
                "mow table with cluster keys does not support non vertical compaction");
    }
    vectorized::BlockReader reader;
    TabletReader::ReaderParams reader_params;
    reader_params.tablet = tablet;
    reader_params.reader_type = reader_type;

    TabletReader::ReadSource read_source;
    read_source.rs_splits.reserve(src_rowset_readers.size());
    for (const RowsetReaderSharedPtr& rs_reader : src_rowset_readers) {
        read_source.rs_splits.emplace_back(rs_reader);
    }
    read_source.fill_delete_predicates();
    reader_params.set_read_source(std::move(read_source));

    reader_params.version = dst_rowset_writer->version();

    TabletSchemaSPtr merge_tablet_schema = std::make_shared<TabletSchema>();
    merge_tablet_schema->copy_from(cur_tablet_schema);

    // Merge the columns in delete predicate that not in latest schema in to current tablet schema
    for (auto& del_pred_rs : reader_params.delete_predicates) {
        merge_tablet_schema->merge_dropped_columns(*del_pred_rs->tablet_schema());
    }
    reader_params.tablet_schema = merge_tablet_schema;
    if (!tablet->tablet_schema()->cluster_key_uids().empty()) {
        reader_params.delete_bitmap = &tablet->tablet_meta()->delete_bitmap();
    }

    if (stats_output && stats_output->rowid_conversion) {
        reader_params.record_rowids = true;
        reader_params.rowid_conversion = stats_output->rowid_conversion;
        stats_output->rowid_conversion->set_dst_rowset_id(dst_rowset_writer->rowset_id());
    }

    reader_params.return_columns.resize(cur_tablet_schema.num_columns());
    std::iota(reader_params.return_columns.begin(), reader_params.return_columns.end(), 0);
    reader_params.origin_return_columns = &reader_params.return_columns;
    RETURN_IF_ERROR(reader.init(reader_params));

    vectorized::Block block = cur_tablet_schema.create_block(reader_params.return_columns);
    size_t output_rows = 0;
    bool eof = false;
    while (!eof && !ExecEnv::GetInstance()->storage_engine().stopped()) {
        auto tablet_state = tablet->tablet_state();
        if (tablet_state != TABLET_RUNNING && tablet_state != TABLET_NOTREADY) {
            tablet->clear_cache();
            return Status::Error<INTERNAL_ERROR>("tablet {} is not used any more",
                                                 tablet->tablet_id());
        }

        // Read one block from block reader
        RETURN_NOT_OK_STATUS_WITH_WARN(reader.next_block_with_aggregation(&block, &eof),
                                       "failed to read next block when merging rowsets of tablet " +
                                               std::to_string(tablet->tablet_id()));
        RETURN_NOT_OK_STATUS_WITH_WARN(dst_rowset_writer->add_block(&block),
                                       "failed to write block when merging rowsets of tablet " +
                                               std::to_string(tablet->tablet_id()));

        if (reader_params.record_rowids && block.rows() > 0) {
            std::vector<uint32_t> segment_num_rows;
            RETURN_IF_ERROR(dst_rowset_writer->get_segment_num_rows(&segment_num_rows));
            stats_output->rowid_conversion->add(reader.current_block_row_locations(),
                                                segment_num_rows);
        }

        output_rows += block.rows();
        block.clear_column_data();
    }
    if (ExecEnv::GetInstance()->storage_engine().stopped()) {
        return Status::Error<INTERNAL_ERROR>("tablet {} failed to do compaction, engine stopped",
                                             tablet->tablet_id());
    }

    if (stats_output != nullptr) {
        stats_output->output_rows = output_rows;
        stats_output->merged_rows = reader.merged_rows();
        stats_output->filtered_rows = reader.filtered_rows();
        stats_output->bytes_read_from_local = reader.stats().file_cache_stats.bytes_read_from_local;
        stats_output->bytes_read_from_remote =
                reader.stats().file_cache_stats.bytes_read_from_remote;
        stats_output->cached_bytes_total = reader.stats().file_cache_stats.bytes_write_into_cache;
        if (config::is_cloud_mode()) {
            stats_output->cloud_local_read_time =
                    reader.stats().file_cache_stats.local_io_timer / 1000;
            stats_output->cloud_remote_read_time =
                    reader.stats().file_cache_stats.remote_io_timer / 1000;
        }
    }

    RETURN_NOT_OK_STATUS_WITH_WARN(dst_rowset_writer->flush(),
                                   "failed to flush rowset when merging rowsets of tablet " +
                                           std::to_string(tablet->tablet_id()));

    return Status::OK();
}

// split columns into several groups, make sure all keys in one group
// unique_key should consider sequence&delete column
void Merger::vertical_split_columns(const TabletSchema& tablet_schema,
                                    std::vector<std::vector<uint32_t>>* column_groups,
                                    std::vector<uint32_t>* key_group_cluster_key_idxes) {
    size_t num_key_cols = tablet_schema.num_key_columns();
    size_t total_cols = tablet_schema.num_columns();
    std::vector<uint32_t> key_columns;
    for (auto i = 0; i < num_key_cols; ++i) {
        key_columns.emplace_back(i);
    }
    // in unique key, sequence & delete sign column should merge with key columns
    int32_t sequence_col_idx = -1;
    int32_t delete_sign_idx = -1;
    // in key column compaction, seq_col real index is _num_key_columns
    // and delete_sign column is _block->columns() - 1
    if (tablet_schema.keys_type() == KeysType::UNIQUE_KEYS) {
        if (tablet_schema.has_sequence_col()) {
            sequence_col_idx = tablet_schema.sequence_col_idx();
            key_columns.emplace_back(sequence_col_idx);
        }
        delete_sign_idx = tablet_schema.field_index(DELETE_SIGN);
        if (delete_sign_idx != -1) {
            key_columns.emplace_back(delete_sign_idx);
        }
        if (!tablet_schema.cluster_key_uids().empty()) {
            for (const auto& cid : tablet_schema.cluster_key_uids()) {
                auto idx = tablet_schema.field_index(cid);
                DCHECK(idx >= 0) << "could not find cluster key column with unique_id=" << cid
                                 << " in tablet schema, table_id=" << tablet_schema.table_id();
                if (idx >= num_key_cols) {
                    key_columns.emplace_back(idx);
                }
            }
            // tablet schema unique ids: [1, 2, 5, 3, 6, 4], [1 2] is key columns
            // cluster key unique ids: [3, 1, 4]
            // the key_columns should be [0, 1, 3, 5]
            // the key_group_cluster_key_idxes should be [2, 1, 3]
            for (const auto& cid : tablet_schema.cluster_key_uids()) {
                auto idx = tablet_schema.field_index(cid);
                for (auto i = 0; i < key_columns.size(); ++i) {
                    if (idx == key_columns[i]) {
                        key_group_cluster_key_idxes->emplace_back(i);
                        break;
                    }
                }
            }
        }
    }
    VLOG_NOTICE << "sequence_col_idx=" << sequence_col_idx
                << ", delete_sign_idx=" << delete_sign_idx;
    // for duplicate no keys
    if (!key_columns.empty()) {
        column_groups->emplace_back(key_columns);
    }

    std::vector<uint32_t> value_columns;

    for (size_t i = num_key_cols; i < total_cols; ++i) {
        if (i == sequence_col_idx || i == delete_sign_idx ||
            key_columns.end() != std::find(key_columns.begin(), key_columns.end(), i)) {
            continue;
        }

        if (!value_columns.empty() &&
            value_columns.size() % config::vertical_compaction_num_columns_per_group == 0) {
            column_groups->push_back(value_columns);
            value_columns.clear();
        }
        value_columns.push_back(cast_set<uint32_t>(i));
    }

    if (!value_columns.empty()) {
        column_groups->push_back(value_columns);
    }
}

Status Merger::vertical_compact_one_group(
        BaseTabletSPtr tablet, ReaderType reader_type, const TabletSchema& tablet_schema,
        bool is_key, const std::vector<uint32_t>& column_group,
        vectorized::RowSourcesBuffer* row_source_buf,
        const std::vector<RowsetReaderSharedPtr>& src_rowset_readers,
        RowsetWriter* dst_rowset_writer, uint32_t max_rows_per_segment, Statistics* stats_output,
        std::vector<uint32_t> key_group_cluster_key_idxes, int64_t batch_size,
        CompactionSampleInfo* sample_info) {
    // build tablet reader
    VLOG_NOTICE << "vertical compact one group, max_rows_per_segment=" << max_rows_per_segment;
    vectorized::VerticalBlockReader reader(row_source_buf);
    TabletReader::ReaderParams reader_params;
    reader_params.is_key_column_group = is_key;
    reader_params.key_group_cluster_key_idxes = key_group_cluster_key_idxes;
    reader_params.tablet = tablet;
    reader_params.reader_type = reader_type;

    TabletReader::ReadSource read_source;
    read_source.rs_splits.reserve(src_rowset_readers.size());
    for (const RowsetReaderSharedPtr& rs_reader : src_rowset_readers) {
        read_source.rs_splits.emplace_back(rs_reader);
    }
    read_source.fill_delete_predicates();
    reader_params.set_read_source(std::move(read_source));

    reader_params.version = dst_rowset_writer->version();

    TabletSchemaSPtr merge_tablet_schema = std::make_shared<TabletSchema>();
    merge_tablet_schema->copy_from(tablet_schema);

    for (auto& del_pred_rs : reader_params.delete_predicates) {
        merge_tablet_schema->merge_dropped_columns(*del_pred_rs->tablet_schema());
    }

    reader_params.tablet_schema = merge_tablet_schema;
    bool has_cluster_key = false;
    if (!tablet->tablet_schema()->cluster_key_uids().empty()) {
        reader_params.delete_bitmap = &tablet->tablet_meta()->delete_bitmap();
        has_cluster_key = true;
    }

    if (is_key && stats_output && stats_output->rowid_conversion) {
        reader_params.record_rowids = true;
        reader_params.rowid_conversion = stats_output->rowid_conversion;
        stats_output->rowid_conversion->set_dst_rowset_id(dst_rowset_writer->rowset_id());
    }

    reader_params.return_columns = column_group;
    reader_params.origin_return_columns = &reader_params.return_columns;
    reader_params.batch_size = batch_size;
    RETURN_IF_ERROR(reader.init(reader_params, sample_info));

    vectorized::Block block = tablet_schema.create_block(reader_params.return_columns);
    size_t output_rows = 0;
    bool eof = false;
    while (!eof && !ExecEnv::GetInstance()->storage_engine().stopped()) {
        auto tablet_state = tablet->tablet_state();
        if (tablet_state != TABLET_RUNNING && tablet_state != TABLET_NOTREADY) {
            tablet->clear_cache();
            return Status::Error<INTERNAL_ERROR>("tablet {} is not used any more",
                                                 tablet->tablet_id());
        }
        // Read one block from block reader
        RETURN_NOT_OK_STATUS_WITH_WARN(reader.next_block_with_aggregation(&block, &eof),
                                       "failed to read next block when merging rowsets of tablet " +
                                               std::to_string(tablet->tablet_id()));
        RETURN_NOT_OK_STATUS_WITH_WARN(
                dst_rowset_writer->add_columns(&block, column_group, is_key, max_rows_per_segment,
                                               has_cluster_key),
                "failed to write block when merging rowsets of tablet " +
                        std::to_string(tablet->tablet_id()));

        if (is_key && reader_params.record_rowids && block.rows() > 0) {
            std::vector<uint32_t> segment_num_rows;
            RETURN_IF_ERROR(dst_rowset_writer->get_segment_num_rows(&segment_num_rows));
            stats_output->rowid_conversion->add(reader.current_block_row_locations(),
                                                segment_num_rows);
        }
        output_rows += block.rows();
        block.clear_column_data();
    }
    if (ExecEnv::GetInstance()->storage_engine().stopped()) {
        return Status::Error<INTERNAL_ERROR>("tablet {} failed to do compaction, engine stopped",
                                             tablet->tablet_id());
    }

    if (is_key && stats_output != nullptr) {
        stats_output->output_rows = output_rows;
        stats_output->merged_rows = reader.merged_rows();
        stats_output->filtered_rows = reader.filtered_rows();
        stats_output->bytes_read_from_local = reader.stats().file_cache_stats.bytes_read_from_local;
        stats_output->bytes_read_from_remote =
                reader.stats().file_cache_stats.bytes_read_from_remote;
        stats_output->cached_bytes_total = reader.stats().file_cache_stats.bytes_write_into_cache;
        if (config::is_cloud_mode()) {
            stats_output->cloud_local_read_time =
                    reader.stats().file_cache_stats.local_io_timer / 1000;
            stats_output->cloud_remote_read_time =
                    reader.stats().file_cache_stats.remote_io_timer / 1000;
        }
    }
    RETURN_IF_ERROR(dst_rowset_writer->flush_columns(is_key));

    return Status::OK();
}

// for segcompaction
Status Merger::vertical_compact_one_group(
        int64_t tablet_id, ReaderType reader_type, const TabletSchema& tablet_schema, bool is_key,
        const std::vector<uint32_t>& column_group, vectorized::RowSourcesBuffer* row_source_buf,
        vectorized::VerticalBlockReader& src_block_reader,
        segment_v2::SegmentWriter& dst_segment_writer, Statistics* stats_output,
        uint64_t* index_size, KeyBoundsPB& key_bounds, SimpleRowIdConversion* rowid_conversion) {
    // TODO: record_rowids
    vectorized::Block block = tablet_schema.create_block(column_group);
    size_t output_rows = 0;
    bool eof = false;
    while (!eof && !ExecEnv::GetInstance()->storage_engine().stopped()) {
        // Read one block from block reader
        RETURN_NOT_OK_STATUS_WITH_WARN(src_block_reader.next_block_with_aggregation(&block, &eof),
                                       "failed to read next block when merging rowsets of tablet " +
                                               std::to_string(tablet_id));
        if (!block.rows()) {
            break;
        }
        RETURN_NOT_OK_STATUS_WITH_WARN(dst_segment_writer.append_block(&block, 0, block.rows()),
                                       "failed to write block when merging rowsets of tablet " +
                                               std::to_string(tablet_id));

        if (is_key && rowid_conversion != nullptr) {
            rowid_conversion->add(src_block_reader.current_block_row_locations());
        }
        output_rows += block.rows();
        block.clear_column_data();
    }
    if (ExecEnv::GetInstance()->storage_engine().stopped()) {
        return Status::Error<INTERNAL_ERROR>("tablet {} failed to do compaction, engine stopped",
                                             tablet_id);
    }

    if (is_key && stats_output != nullptr) {
        stats_output->output_rows = output_rows;
        stats_output->merged_rows = src_block_reader.merged_rows();
        stats_output->filtered_rows = src_block_reader.filtered_rows();
        stats_output->bytes_read_from_local =
                src_block_reader.stats().file_cache_stats.bytes_read_from_local;
        stats_output->bytes_read_from_remote =
                src_block_reader.stats().file_cache_stats.bytes_read_from_remote;
        stats_output->cached_bytes_total =
                src_block_reader.stats().file_cache_stats.bytes_write_into_cache;
    }

    // segcompaction produce only one segment at once
    RETURN_IF_ERROR(dst_segment_writer.finalize_columns_data());
    RETURN_IF_ERROR(dst_segment_writer.finalize_columns_index(index_size));

    if (is_key) {
        Slice min_key = dst_segment_writer.min_encoded_key();
        Slice max_key = dst_segment_writer.max_encoded_key();
        DCHECK_LE(min_key.compare(max_key), 0);
        key_bounds.set_min_key(min_key.to_string());
        key_bounds.set_max_key(max_key.to_string());
    }

    return Status::OK();
}

int64_t estimate_batch_size(int group_index, BaseTabletSPtr tablet, int64_t way_cnt) {
    std::unique_lock<std::mutex> lock(tablet->sample_info_lock);
    CompactionSampleInfo info = tablet->sample_infos[group_index];
    if (way_cnt <= 0) {
        LOG(INFO) << "estimate batch size for vertical compaction, tablet id: "
                  << tablet->tablet_id() << " way cnt: " << way_cnt;
        return 4096 - 32;
    }
    int64_t block_mem_limit = config::compaction_memory_bytes_limit / way_cnt;
    if (tablet->last_compaction_status.is<ErrorCode::MEM_LIMIT_EXCEEDED>()) {
        block_mem_limit /= 4;
    }

    int64_t group_data_size = 0;
    if (info.group_data_size > 0 && info.bytes > 0 && info.rows > 0) {
        double smoothing_factor = 0.5;
        group_data_size =
                int64_t((cast_set<double>(info.group_data_size) * (1 - smoothing_factor)) +
                        (cast_set<double>(info.bytes / info.rows) * smoothing_factor));
        tablet->sample_infos[group_index].group_data_size = group_data_size;
    } else if (info.group_data_size > 0 && (info.bytes <= 0 || info.rows <= 0)) {
        group_data_size = info.group_data_size;
    } else if (info.group_data_size <= 0 && info.bytes > 0 && info.rows > 0) {
        group_data_size = info.bytes / info.rows;
        tablet->sample_infos[group_index].group_data_size = group_data_size;
    } else {
        LOG(INFO) << "estimate batch size for vertical compaction, tablet id: "
                  << tablet->tablet_id() << " group data size: " << info.group_data_size
                  << " row num: " << info.rows << " consume bytes: " << info.bytes;
        return 1024 - 32;
    }

    if (group_data_size <= 0) {
        LOG(WARNING) << "estimate batch size for vertical compaction, tablet id: "
                     << tablet->tablet_id() << " unexpected group data size: " << group_data_size;
        return 4096 - 32;
    }

    tablet->sample_infos[group_index].bytes = 0;
    tablet->sample_infos[group_index].rows = 0;

    int64_t batch_size = block_mem_limit / group_data_size;
    int64_t res = std::max(std::min(batch_size, int64_t(4096 - 32)), int64_t(32L));
    LOG(INFO) << "estimate batch size for vertical compaction, tablet id: " << tablet->tablet_id()
              << " group data size: " << info.group_data_size << " row num: " << info.rows
              << " consume bytes: " << info.bytes << " way cnt: " << way_cnt
              << " batch size: " << res;
    return res;
}

// steps to do vertical merge:
// 1. split columns into column groups
// 2. compact groups one by one, generate a row_source_buf when compact key group
// and use this row_source_buf to compact value column groups
// 3. build output rowset
Status Merger::vertical_merge_rowsets(BaseTabletSPtr tablet, ReaderType reader_type,
                                      const TabletSchema& tablet_schema,
                                      const std::vector<RowsetReaderSharedPtr>& src_rowset_readers,
                                      RowsetWriter* dst_rowset_writer,
                                      uint32_t max_rows_per_segment, int64_t merge_way_num,
                                      Statistics* stats_output) {
    LOG(INFO) << "Start to do vertical compaction, tablet_id: " << tablet->tablet_id();
    std::vector<std::vector<uint32_t>> column_groups;
    std::vector<uint32_t> key_group_cluster_key_idxes;
    vertical_split_columns(tablet_schema, &column_groups, &key_group_cluster_key_idxes);

    vectorized::RowSourcesBuffer row_sources_buf(
            tablet->tablet_id(), dst_rowset_writer->context().tablet_path, reader_type);
    {
        std::unique_lock<std::mutex> lock(tablet->sample_info_lock);
        tablet->sample_infos.resize(column_groups.size(), {0, 0, 0});
    }
    // compact group one by one
    for (auto i = 0; i < column_groups.size(); ++i) {
        VLOG_NOTICE << "row source size: " << row_sources_buf.total_size();
        bool is_key = (i == 0);
        int64_t batch_size = config::compaction_batch_size != -1
                                     ? config::compaction_batch_size
                                     : estimate_batch_size(i, tablet, merge_way_num);
        CompactionSampleInfo sample_info;
        Status st = vertical_compact_one_group(
                tablet, reader_type, tablet_schema, is_key, column_groups[i], &row_sources_buf,
                src_rowset_readers, dst_rowset_writer, max_rows_per_segment, stats_output,
                key_group_cluster_key_idxes, batch_size, &sample_info);
        {
            std::unique_lock<std::mutex> lock(tablet->sample_info_lock);
            tablet->sample_infos[i] = sample_info;
        }
        RETURN_IF_ERROR(st);
        if (is_key) {
            RETURN_IF_ERROR(row_sources_buf.flush());
        }
        RETURN_IF_ERROR(row_sources_buf.seek_to_begin());
    }

    // finish compact, build output rowset
    VLOG_NOTICE << "finish compact groups";
    RETURN_IF_ERROR(dst_rowset_writer->final_flush());

    return Status::OK();
}
#include "common/compile_check_end.h"
} // namespace doris
