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

#include <glog/logging.h>
#include <stddef.h>
#include <stdint.h>

#include <memory>

#include "common/status.h"
#include "io/fs/file_reader_writer_fwd.h"
#include "olap/olap_common.h"
#include "olap/rowset/segment_v2/bloom_filter.h"
#include "olap/rowset/segment_v2/bloom_filter_index_writer.h"
#include "olap/rowset/segment_v2/indexed_column_reader.h"
#include "olap/rowset/segment_v2/indexed_column_writer.h"
#include "util/faststring.h"
#include "util/slice.h"

namespace doris {
#include "common/compile_check_begin.h"
class TypeInfo;

namespace io {
class FileWriter;
} // namespace io
namespace segment_v2 {

class PrimaryKeyIndexMetaPB;
} // namespace segment_v2

// Build index for primary key.
// The primary key index is designed in a similar way like RocksDB
// Partitioned Index, which is created in the segment file when MemTable flushes.
// Index is stored in multiple pages to leverage the IndexedColumnWriter.
//
// NOTE: for now, it's only used when unique key merge-on-write property enabled.
class PrimaryKeyIndexBuilder {
public:
    PrimaryKeyIndexBuilder(io::FileWriter* file_writer, size_t seq_col_length, size_t rowid_length)
            : _file_writer(file_writer),
              _num_rows(0),
              _size(0),
              _disk_size(0),
              _seq_col_length(seq_col_length),
              _rowid_length(rowid_length) {}

    Status init();

    Status add_item(const Slice& key);

    uint32_t num_rows() const { return _num_rows; }

    uint64_t size() const { return _size; }

    uint64_t disk_size() const { return _disk_size; }

    // used for be ut
    uint32_t data_page_num() const { return _primary_key_index_builder->data_page_num(); }

    Slice min_key() {
        return Slice(_min_key.data(), _min_key.size() - _seq_col_length - _rowid_length);
    }
    Slice max_key() {
        return Slice(_max_key.data(), _max_key.size() - _seq_col_length - _rowid_length);
    }

    Status finalize(segment_v2::PrimaryKeyIndexMetaPB* meta);

private:
    io::FileWriter* _file_writer = nullptr;
    uint32_t _num_rows;
    uint64_t _size;
    uint64_t _disk_size;
    size_t _seq_col_length;
    size_t _rowid_length;

    faststring _min_key;
    faststring _max_key;
    std::unique_ptr<segment_v2::IndexedColumnWriter> _primary_key_index_builder;
    std::unique_ptr<segment_v2::BloomFilterIndexWriter> _bloom_filter_index_builder;
};

class PrimaryKeyIndexReader {
public:
    PrimaryKeyIndexReader() : _index_parsed(false), _bf_parsed(false) {}

    ~PrimaryKeyIndexReader() {
        segment_v2::g_pk_total_bloom_filter_num << -static_cast<int64_t>(_bf_num);
        segment_v2::g_pk_total_bloom_filter_total_bytes << -static_cast<int64_t>(_bf_bytes);
        segment_v2::g_pk_read_bloom_filter_num << -static_cast<int64_t>(_bf_num);
        segment_v2::g_pk_read_bloom_filter_total_bytes << -static_cast<int64_t>(_bf_bytes);
    }

    Status parse_index(io::FileReaderSPtr file_reader,
                       const segment_v2::PrimaryKeyIndexMetaPB& meta,
                       OlapReaderStatistics* pk_index_load_stats);

    Status parse_bf(io::FileReaderSPtr file_reader, const segment_v2::PrimaryKeyIndexMetaPB& meta,
                    OlapReaderStatistics* pk_index_load_stats);

    Status new_iterator(std::unique_ptr<segment_v2::IndexedColumnIterator>* index_iterator,
                        OlapReaderStatistics* stats) const {
        DCHECK(_index_parsed);
        index_iterator->reset(new segment_v2::IndexedColumnIterator(_index_reader.get(), stats));
        return Status::OK();
    }

    const TypeInfo* type_info() const {
        DCHECK(_index_parsed);
        return _index_reader->type_info();
    }

    // verify whether exist in BloomFilter
    bool check_present(const Slice& key) {
        DCHECK(_bf_parsed);
        return _bf->test_bytes(key.data, key.size);
    }

    int64_t num_rows() const {
        DCHECK(_index_parsed);
        return _index_reader->num_values();
    }

    uint64_t get_bf_memory_size() {
        DCHECK(_bf_parsed);
        return _bf->size();
    }

    uint64_t get_memory_size() {
        DCHECK(_index_parsed);
        return _index_reader->get_memory_size();
    }

    static constexpr size_t ROW_ID_LENGTH = sizeof(uint32_t) + 1;

private:
    bool _index_parsed;
    bool _bf_parsed;
    std::unique_ptr<segment_v2::IndexedColumnReader> _index_reader;
    std::unique_ptr<segment_v2::BloomFilter> _bf;
    size_t _bf_num = 0;
    uint64_t _bf_bytes = 0;
};
#include "common/compile_check_end.h"
} // namespace doris
