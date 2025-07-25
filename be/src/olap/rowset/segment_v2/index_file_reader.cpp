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

#include "olap/rowset/segment_v2/index_file_reader.h"

#include <memory>
#include <utility>

#include "olap/rowset/segment_v2/inverted_index_compound_reader.h"
#include "olap/rowset/segment_v2/inverted_index_fs_directory.h"
#include "olap/tablet_schema.h"
#include "util/debug_points.h"

namespace doris::segment_v2 {

Status IndexFileReader::init(int32_t read_buffer_size, const io::IOContext* io_ctx) {
    std::unique_lock<std::shared_mutex> lock(_mutex); // Lock for writing
    if (!_inited) {
        _read_buffer_size = read_buffer_size;
        if (_storage_format >= InvertedIndexStorageFormatPB::V2) {
            RETURN_IF_ERROR(_init_from(read_buffer_size, io_ctx));
        }
        _inited = true;
    }
    return Status::OK();
}

Status IndexFileReader::_init_from(int32_t read_buffer_size, const io::IOContext* io_ctx) {
    auto index_file_full_path = InvertedIndexDescriptor::get_index_file_path_v2(_index_path_prefix);

    try {
        CLuceneError err;
        CL_NS(store)::IndexInput* index_input = nullptr;

        // 1. get file size from meta
        int64_t file_size = -1;
        if (_idx_file_info.has_index_size()) {
            file_size = _idx_file_info.index_size();
        }
        file_size = file_size == 0 ? -1 : file_size;

        DBUG_EXECUTE_IF("file_size_not_in_rowset_meta ", {
            if (file_size == -1) {
                return Status::Error<ErrorCode::INVERTED_INDEX_CLUCENE_ERROR>(
                        "CLuceneError occur file size = -1, file is {}", index_file_full_path);
            }
        })

        // 2. open file
        auto ok = DorisFSDirectory::FSIndexInput::open(
                _fs, index_file_full_path.c_str(), index_input, err, read_buffer_size, file_size);
        if (!ok) {
            if (err.number() == CL_ERR_FileNotFound) {
                return Status::Error<ErrorCode::INVERTED_INDEX_FILE_NOT_FOUND>(
                        "inverted index file {} is not found.", index_file_full_path);
            } else if (err.number() == CL_ERR_EmptyIndexSegment) {
                return Status::Error<ErrorCode::INVERTED_INDEX_BYPASS>(
                        "inverted index file {} is empty.", index_file_full_path);
            }
            return Status::Error<ErrorCode::INVERTED_INDEX_CLUCENE_ERROR>(
                    "CLuceneError occur when open idx file {}, error msg: {}", index_file_full_path,
                    err.what());
        }
        _stream = std::unique_ptr<CL_NS(store)::IndexInput>(index_input);
        _stream->setIoContext(io_ctx);
        _stream->setIndexFile(true);

        // 3. read file
        int32_t version = _stream->readInt(); // Read version number
        if (version >= InvertedIndexStorageFormatPB::V2) {
            DCHECK(version == _storage_format);
            int32_t numIndices = _stream->readInt(); // Read number of indices

            for (int32_t i = 0; i < numIndices; ++i) {
                int64_t indexId = _stream->readLong();      // Read index ID
                int32_t suffix_length = _stream->readInt(); // Read suffix length
                std::vector<uint8_t> suffix_data(suffix_length);
                _stream->readBytes(suffix_data.data(), suffix_length);
                std::string suffix_str(suffix_data.begin(), suffix_data.end());

                int32_t numFiles = _stream->readInt(); // Read number of files in the index

                auto fileEntries = std::make_unique<EntriesType>();
                fileEntries->reserve(numFiles);

                for (int32_t j = 0; j < numFiles; ++j) {
                    int32_t file_name_length = _stream->readInt();
                    std::string file_name(file_name_length, '\0');
                    _stream->readBytes(reinterpret_cast<uint8_t*>(file_name.data()),
                                       file_name_length);
                    auto entry = std::make_unique<ReaderFileEntry>();
                    entry->file_name = std::move(file_name);
                    entry->offset = _stream->readLong();
                    entry->length = _stream->readLong();
                    fileEntries->emplace(entry->file_name, std::move(entry));
                }

                _indices_entries.emplace(std::make_pair(indexId, std::move(suffix_str)),
                                         std::move(fileEntries));
            }
        } else {
            return Status::Error<ErrorCode::INVERTED_INDEX_CLUCENE_ERROR>(
                    "unknown inverted index format {}", version);
        }
    } catch (CLuceneError& err) {
        if (_stream != nullptr) {
            try {
                _stream->close();
            } catch (CLuceneError& err) {
                return Status::Error<ErrorCode::INVERTED_INDEX_CLUCENE_ERROR>(
                        "CLuceneError occur when close idx file {}, error msg: {}",
                        index_file_full_path, err.what());
            }
        }
        return Status::Error<ErrorCode::INVERTED_INDEX_CLUCENE_ERROR>(
                "CLuceneError occur when init idx file {}, error msg: {}", index_file_full_path,
                err.what());
    }
    return Status::OK();
}

Result<InvertedIndexDirectoryMap> IndexFileReader::get_all_directories() {
    InvertedIndexDirectoryMap res;
    std::shared_lock<std::shared_mutex> lock(_mutex); // Lock for reading
    for (auto& [index, _] : _indices_entries) {
        auto&& [index_id, index_suffix] = index;
        LOG(INFO) << "index_id:" << index_id << " index_suffix:" << index_suffix;
        auto ret = _open(index_id, index_suffix);
        if (!ret.has_value()) {
            return ResultError(ret.error());
        }
        res.emplace(std::make_pair(index_id, index_suffix), std::move(ret.value()));
    }
    return res;
}

Result<std::unique_ptr<DorisCompoundReader>> IndexFileReader::_open(
        int64_t index_id, const std::string& index_suffix, const io::IOContext* io_ctx) const {
    std::unique_ptr<DorisCompoundReader> compound_reader;

    if (_storage_format == InvertedIndexStorageFormatPB::V1) {
        auto index_file_path = InvertedIndexDescriptor::get_index_file_path_v1(
                _index_path_prefix, index_id, index_suffix);
        try {
            CLuceneError err;
            CL_NS(store)::IndexInput* index_input = nullptr;

            // 1. get file size from meta
            int64_t file_size = -1;
            if (_idx_file_info.index_info_size() > 0) {
                for (const auto& idx_info : _idx_file_info.index_info()) {
                    if (index_id == idx_info.index_id() &&
                        index_suffix == idx_info.index_suffix()) {
                        file_size = idx_info.index_file_size();
                        break;
                    }
                }
            }
            file_size = file_size == 0 ? -1 : file_size;
            DBUG_EXECUTE_IF("file_size_not_in_rowset_meta ", {
                if (file_size == -1) {
                    return ResultError(Status::Error<ErrorCode::INVERTED_INDEX_CLUCENE_ERROR>(
                            "CLuceneError occur file size = -1, file is {}", index_file_path));
                }
            })

            // 2. open file
            auto ok = DorisFSDirectory::FSIndexInput::open(
                    _fs, index_file_path.c_str(), index_input, err, _read_buffer_size, file_size);
            if (!ok) {
                // now index_input = nullptr
                if (err.number() == CL_ERR_FileNotFound) {
                    return ResultError(Status::Error<ErrorCode::INVERTED_INDEX_FILE_NOT_FOUND>(
                            "inverted index file {} is not found.", index_file_path));
                }
                return ResultError(Status::Error<ErrorCode::INVERTED_INDEX_CLUCENE_ERROR>(
                        "CLuceneError occur when open idx file {}, error msg: {}", index_file_path,
                        err.what()));
            }

            // 3. read file in DorisCompoundReader
            compound_reader = std::make_unique<DorisCompoundReader>(index_input, _read_buffer_size);
        } catch (CLuceneError& err) {
            return ResultError(Status::Error<ErrorCode::INVERTED_INDEX_CLUCENE_ERROR>(
                    "CLuceneError occur when open idx file {}, error msg: {}", index_file_path,
                    err.what()));
        }
    } else {
        std::shared_lock<std::shared_mutex> lock(_mutex); // Lock for reading
        if (_stream == nullptr) {
            return ResultError(Status::Error<ErrorCode::INVERTED_INDEX_FILE_NOT_FOUND>(
                    "CLuceneError occur when open idx file {}, stream is nullptr",
                    InvertedIndexDescriptor::get_index_file_path_v2(_index_path_prefix)));
        }

        // Check if the specified index exists
        auto index_it = _indices_entries.find(std::make_pair(index_id, index_suffix));
        if (index_it == _indices_entries.end()) {
            std::ostringstream errMsg;
            errMsg << "No index with id " << index_id << " found";
            return ResultError(Status::Error<ErrorCode::INVERTED_INDEX_FILE_NOT_FOUND>(
                    "CLuceneError occur when open idx file {}, error msg: {}",
                    InvertedIndexDescriptor::get_index_file_path_v2(_index_path_prefix),
                    errMsg.str()));
        }
        // Need to clone resource here, because index searcher cache need it.
        compound_reader = std::make_unique<DorisCompoundReader>(_stream->clone(), *index_it->second,
                                                                _read_buffer_size, io_ctx);
    }
    return compound_reader;
}

Result<std::unique_ptr<DorisCompoundReader>> IndexFileReader::open(
        const TabletIndex* index_meta, const io::IOContext* io_ctx) const {
    auto index_id = index_meta->index_id();
    auto index_suffix = index_meta->get_index_suffix();
    return _open(index_id, index_suffix, io_ctx);
}

std::string IndexFileReader::get_index_file_cache_key(const TabletIndex* index_meta) const {
    return InvertedIndexDescriptor::get_index_file_cache_key(
            _index_path_prefix, index_meta->index_id(), index_meta->get_index_suffix());
}

std::string IndexFileReader::get_index_file_path(const TabletIndex* index_meta) const {
    if (_storage_format == InvertedIndexStorageFormatPB::V1) {
        return InvertedIndexDescriptor::get_index_file_path_v1(
                _index_path_prefix, index_meta->index_id(), index_meta->get_index_suffix());
    }
    return InvertedIndexDescriptor::get_index_file_path_v2(_index_path_prefix);
}

Status IndexFileReader::index_file_exist(const TabletIndex* index_meta, bool* res) const {
    if (_storage_format == InvertedIndexStorageFormatPB::V1) {
        auto index_file_path = InvertedIndexDescriptor::get_index_file_path_v1(
                _index_path_prefix, index_meta->index_id(), index_meta->get_index_suffix());
        return _fs->exists(index_file_path, res);
    } else {
        std::shared_lock<std::shared_mutex> lock(_mutex); // Lock for reading
        if (_stream == nullptr) {
            *res = false;
            return Status::Error<ErrorCode::INVERTED_INDEX_FILE_NOT_FOUND>(
                    "idx file {} is not opened",
                    InvertedIndexDescriptor::get_index_file_path_v2(_index_path_prefix));
        }
        // Check if the specified index exists
        auto index_it = _indices_entries.find(
                std::make_pair(index_meta->index_id(), index_meta->get_index_suffix()));
        if (index_it == _indices_entries.end()) {
            *res = false;
        } else {
            *res = true;
        }
    }
    return Status::OK();
}

Status IndexFileReader::has_null(const TabletIndex* index_meta, bool* res) const {
    if (_storage_format == InvertedIndexStorageFormatPB::V1) {
        *res = true;
        return Status::OK();
    }
    std::shared_lock<std::shared_mutex> lock(_mutex); // Lock for reading
    if (_stream == nullptr) {
        return Status::Error<ErrorCode::INVERTED_INDEX_FILE_NOT_FOUND>(
                "idx file {} is not opened",
                InvertedIndexDescriptor::get_index_file_path_v2(_index_path_prefix));
    }
    // Check if the specified index exists
    auto index_it = _indices_entries.find(
            std::make_pair(index_meta->index_id(), index_meta->get_index_suffix()));
    if (index_it == _indices_entries.end()) {
        *res = false;
    } else {
        const auto& entries = index_it->second;
        auto entry_it =
                entries->find(InvertedIndexDescriptor::get_temporary_null_bitmap_file_name());
        if (entry_it == entries->end()) {
            *res = false;
            return Status::OK();
        }
        const auto& e = entry_it->second;
        // roaring bitmap cookie header size is 5
        if (e->length <= 5) {
            *res = false;
        } else {
            *res = true;
        }
    }
    return Status::OK();
}

void IndexFileReader::debug_file_entries() {
    std::shared_lock<std::shared_mutex> lock(_mutex); // Lock for reading
    for (const auto& index : _indices_entries) {
        LOG(INFO) << "index_id:" << index.first.first;
        const auto& index_entries = index.second;
        for (const auto& entry : *index_entries) {
            const auto& file_entry = entry.second;
            LOG(INFO) << "file entry name:" << file_entry->file_name
                      << " length:" << file_entry->length << " offset:" << file_entry->offset;
        }
    }
}

} // namespace doris::segment_v2
