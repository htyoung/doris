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
// This file is copied from
// https://github.com/ClickHouse/ClickHouse/blob/master/src/Functions/FunctionsCodingIP.cpp
// and modified by Doris

#pragma once
#include <glog/logging.h>

#include <cstddef>
#include <memory>

#include "common/cast_set.h"
#include "vec/columns/column.h"
#include "vec/columns/column_const.h"
#include "vec/columns/column_nullable.h"
#include "vec/columns/column_string.h"
#include "vec/columns/column_struct.h"
#include "vec/columns/column_vector.h"
#include "vec/common/assert_cast.h"
#include "vec/common/endian.h"
#include "vec/common/format_ip.h"
#include "vec/common/ipv6_to_binary.h"
#include "vec/core/column_with_type_and_name.h"
#include "vec/core/types.h"
#include "vec/data_types/data_type.h"
#include "vec/data_types/data_type_ipv4.h"
#include "vec/data_types/data_type_ipv6.h"
#include "vec/data_types/data_type_nullable.h"
#include "vec/data_types/data_type_number.h"
#include "vec/data_types/data_type_string.h"
#include "vec/data_types/data_type_struct.h"
#include "vec/functions/function.h"
#include "vec/functions/function_helpers.h"
#include "vec/runtime/ip_address_cidr.h"

namespace doris::vectorized {
#include "common/compile_check_begin.h"

class FunctionIPv4NumToString : public IFunction {
private:
    template <PrimitiveType ArgPType>
    Status execute_type(Block& block, const ColumnWithTypeAndName& argument, size_t result) const {
        using ColumnType = ColumnVector<ArgPType>;
        const ColumnPtr& column = argument.column;

        const auto* col = assert_cast<const ColumnType*>(column.get());
        const typename ColumnType::Container& vec_in = col->get_data();
        auto col_res = ColumnString::create();

        ColumnString::Chars& vec_res = col_res->get_chars();
        ColumnString::Offsets& offsets_res = col_res->get_offsets();

        vec_res.resize(vec_in.size() *
                       (IPV4_MAX_TEXT_LENGTH + 1)); /// the longest value is: 255.255.255.255\0
        offsets_res.resize(vec_in.size());
        char* begin = reinterpret_cast<char*>(vec_res.data());
        char* pos = begin;

        auto null_map = ColumnUInt8::create(vec_in.size(), 0);
        size_t src_size =
                std::min(sizeof(typename PrimitiveTypeTraits<ArgPType>::CppType), (unsigned long)4);
        for (size_t i = 0; i < vec_in.size(); ++i) {
            auto value = vec_in[i];
            if (value < IPV4_MIN_NUM_VALUE || value > IPV4_MAX_NUM_VALUE) {
                null_map->get_data()[i] = 1;
            } else {
                format_ipv4(reinterpret_cast<const unsigned char*>(&vec_in[i]), src_size, pos);
            }
            offsets_res[i] = cast_set<uint32_t>(pos - begin);
        }

        vec_res.resize(pos - begin);
        block.replace_by_position(result,
                                  ColumnNullable::create(std::move(col_res), std::move(null_map)));
        return Status::OK();
    }

public:
    static constexpr auto name = "ipv4_num_to_string";
    static FunctionPtr create() { return std::make_shared<FunctionIPv4NumToString>(); }

    String get_name() const override { return name; }

    size_t get_number_of_arguments() const override { return 1; }

    DataTypePtr get_return_type_impl(const DataTypes& arguments) const override {
        return make_nullable(std::make_shared<DataTypeString>());
    }

    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count) const override {
        ColumnWithTypeAndName& argument = block.get_by_position(arguments[0]);

        switch (argument.type->get_primitive_type()) {
        case PrimitiveType::TYPE_TINYINT:
            return execute_type<TYPE_TINYINT>(block, argument, result);
            break;
        case PrimitiveType::TYPE_SMALLINT:
            return execute_type<TYPE_SMALLINT>(block, argument, result);
            break;
        case PrimitiveType::TYPE_INT:
            return execute_type<TYPE_INT>(block, argument, result);
            break;
        case PrimitiveType::TYPE_BIGINT:
            return execute_type<TYPE_BIGINT>(block, argument, result);
            break;
        default:
            break;
        }

        return Status::InternalError(
                "Illegal column {} of argument of function {}, expected Int8 or Int16 or Int32 or "
                "Int64",
                argument.name, get_name());
    }
};

/// Since IPExceptionMode means wider scope, we use more specific name here.
enum class IPConvertExceptionMode : uint8_t { Throw, Default, Null };

static inline bool try_parse_ipv4(const char* pos, Int64& result_value) {
    return parse_ipv4_whole(pos, reinterpret_cast<unsigned char*>(&result_value));
}

template <IPConvertExceptionMode exception_mode, typename ToColumn>
ColumnPtr convert_to_ipv4(ColumnPtr column, const PaddedPODArray<UInt8>* null_map = nullptr) {
    const auto* column_string = assert_cast<const ColumnString*>(column.get());

    size_t column_size = column_string->size();

    ColumnUInt8::MutablePtr col_null_map_to;
    ColumnUInt8::Container* vec_null_map_to = nullptr;

    if constexpr (exception_mode == IPConvertExceptionMode::Null) {
        col_null_map_to = ColumnUInt8::create(column_size, false);
        vec_null_map_to = &col_null_map_to->get_data();
    }

    auto col_res = ToColumn::create(column_size, 0);
    auto& vec_res = col_res->get_data();

    const ColumnString::Chars& vec_src = column_string->get_chars();
    const ColumnString::Offsets& offsets_src = column_string->get_offsets();
    size_t prev_offset = 0;

    for (size_t i = 0; i < vec_res.size(); ++i) {
        if (null_map && (*null_map)[i]) {
            if constexpr (exception_mode == IPConvertExceptionMode::Throw) {
                throw Exception(
                        ErrorCode::INVALID_ARGUMENT,
                        "Null Input, you may consider convert it to a valid default IPv4 value "
                        "like '0.0.0.0' first");
            }
            vec_res[i] = 0;
            prev_offset = offsets_src[i];
            if constexpr (exception_mode == IPConvertExceptionMode::Null) {
                (*vec_null_map_to)[i] = true;
            }
            continue;
        }
        const char* src_start = reinterpret_cast<const char*>(&vec_src[prev_offset]);
        size_t src_length = (i < vec_res.size() - 1) ? (offsets_src[i] - prev_offset)
                                                     : (vec_src.size() - prev_offset);
        std::string src(src_start, src_length);
        bool parse_result = try_parse_ipv4(src.c_str(), vec_res[i]);

        if (!parse_result) {
            if constexpr (exception_mode == IPConvertExceptionMode::Throw) {
                throw Exception(ErrorCode::INVALID_ARGUMENT, "Invalid IPv4 value");
            } else if constexpr (exception_mode == IPConvertExceptionMode::Default) {
                vec_res[i] = 0;
            } else if constexpr (exception_mode == IPConvertExceptionMode::Null) {
                (*vec_null_map_to)[i] = true;
                vec_res[i] = 0;
            }
        }

        prev_offset = offsets_src[i];
    }

    if constexpr (exception_mode == IPConvertExceptionMode::Null) {
        return ColumnNullable::create(std::move(col_res), std::move(col_null_map_to));
    }
    return col_res;
}

template <IPConvertExceptionMode exception_mode>
class FunctionIPv4StringToNum : public IFunction {
public:
    static constexpr auto name = exception_mode == IPConvertExceptionMode::Throw
                                         ? "ipv4_string_to_num"
                                         : (exception_mode == IPConvertExceptionMode::Default
                                                    ? "ipv4_string_to_num_or_default"
                                                    : "ipv4_string_to_num_or_null");

    static FunctionPtr create() {
        return std::make_shared<FunctionIPv4StringToNum<exception_mode>>();
    }

    String get_name() const override { return name; }

    size_t get_number_of_arguments() const override { return 1; }

    DataTypePtr get_return_type_impl(const DataTypes& arguments) const override {
        auto result_type = std::make_shared<DataTypeInt64>();

        if constexpr (exception_mode == IPConvertExceptionMode::Null) {
            return make_nullable(result_type);
        }

        return result_type;
    }

    bool use_default_implementation_for_nulls() const override { return false; }

    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count) const override {
        ColumnPtr column = block.get_by_position(arguments[0]).column;
        ColumnPtr null_map_column;
        const NullMap* null_map = nullptr;
        if (column->is_nullable()) {
            const auto* column_nullable = assert_cast<const ColumnNullable*>(column.get());
            column = column_nullable->get_nested_column_ptr();
            null_map_column = column_nullable->get_null_map_column_ptr();
            null_map = &column_nullable->get_null_map_data();
        }

        auto col_res = convert_to_ipv4<exception_mode, ColumnInt64>(column, null_map);

        if (null_map && exception_mode == IPConvertExceptionMode::Null) {
            block.replace_by_position(
                    result, ColumnNullable::create(std::move(col_res), std::move(null_map_column)));
        } else {
            block.replace_by_position(result, std::move(col_res));
        }
        return Status::OK();
    }
};

template <typename T>
void process_ipv6_column(const ColumnPtr& column, size_t input_rows_count,
                         ColumnString::Chars& vec_res, ColumnString::Offsets& offsets_res,
                         ColumnUInt8::MutablePtr& null_map, unsigned char* ipv6_address_data) {
    auto* begin = reinterpret_cast<char*>(vec_res.data());
    auto* pos = begin;

    const auto* col = assert_cast<const T*>(column.get());

    for (size_t i = 0; i < input_rows_count; ++i) {
        bool is_empty = false;

        if constexpr (std::is_same_v<T, ColumnIPv6>) {
            const auto& vec_in = col->get_data();
            memcpy(ipv6_address_data, reinterpret_cast<const unsigned char*>(&vec_in[i]),
                   IPV6_BINARY_LENGTH);
        } else { // ColumnString
            const auto str_ref = col->get_data_at(i);
            const char* value = str_ref.data;
            size_t value_size = str_ref.size;

            if (value_size > IPV6_BINARY_LENGTH || value == nullptr || value_size == 0) {
                is_empty = true;
            } else {
                memcpy(ipv6_address_data, value, value_size);
                memset(ipv6_address_data + value_size, 0, IPV6_BINARY_LENGTH - value_size);
            }
        }

        if (is_empty) {
            null_map->get_data()[i] = 1;
        } else {
            if constexpr (std::is_same_v<T, ColumnIPv6>) {
                // ipv6 is little-endian byte order storage in doris
                // so parsing ipv6 in little-endian byte order
                format_ipv6(ipv6_address_data, pos);
            } else {
                // 16 bytes ipv6 string is big-endian byte order storage in doris
                // so transfer to little-endian firstly
                std::reverse(ipv6_address_data, ipv6_address_data + IPV6_BINARY_LENGTH);
                format_ipv6(ipv6_address_data, pos);
            }
        }
        offsets_res[i] = cast_set<uint32_t>(pos - begin);
    }
}

class FunctionIPv6NumToString : public IFunction {
public:
    static constexpr auto name = "ipv6_num_to_string";
    static FunctionPtr create() { return std::make_shared<FunctionIPv6NumToString>(); }

    String get_name() const override { return name; }

    size_t get_number_of_arguments() const override { return 1; }

    DataTypePtr get_return_type_impl(const DataTypes& arguments) const override {
        return make_nullable(std::make_shared<DataTypeString>());
    }

    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count) const override {
        const ColumnPtr& column = block.get_by_position(arguments[0]).column;

        auto col_res = ColumnString::create();
        ColumnString::Chars& vec_res = col_res->get_chars();
        ColumnString::Offsets& offsets_res = col_res->get_offsets();
        vec_res.resize(input_rows_count * (IPV6_MAX_TEXT_LENGTH + 1));
        offsets_res.resize(input_rows_count);

        auto null_map = ColumnUInt8::create(input_rows_count, 0);

        unsigned char ipv6_address_data[IPV6_BINARY_LENGTH];

        if (check_and_get_column<ColumnIPv6>(column.get())) {
            process_ipv6_column<ColumnIPv6>(column, input_rows_count, vec_res, offsets_res,
                                            null_map, ipv6_address_data);
        } else { //ColumnString
            process_ipv6_column<ColumnString>(column, input_rows_count, vec_res, offsets_res,
                                              null_map, ipv6_address_data);
        }
        vec_res.resize(offsets_res[offsets_res.size() - 1]);

        block.replace_by_position(result,
                                  ColumnNullable::create(std::move(col_res), std::move(null_map)));
        return Status::OK();
    }
};

namespace detail {
template <IPConvertExceptionMode exception_mode, typename ToColumn = ColumnIPv6,
          typename StringColumnType>
ColumnPtr convert_to_ipv6(const StringColumnType& string_column,
                          const PaddedPODArray<UInt8>* null_map = nullptr) {
    const size_t column_size = string_column.size();

    ColumnUInt8::MutablePtr col_null_map_to;
    ColumnUInt8::Container* vec_null_map_to = nullptr;

    if constexpr (exception_mode == IPConvertExceptionMode::Null) {
        col_null_map_to = ColumnUInt8::create(column_size, false);
        vec_null_map_to = &col_null_map_to->get_data();
    }

    auto column_create = [](size_t column_size) -> typename ToColumn::MutablePtr {
        if constexpr (std::is_same_v<ToColumn, ColumnString>) {
            auto column_string = ColumnString::create();
            column_string->get_chars().reserve(column_size * IPV6_BINARY_LENGTH);
            column_string->get_offsets().reserve(column_size);
            return column_string;
        } else {
            return ColumnIPv6::create();
        }
    };

    auto get_vector = [](auto& col_res, size_t col_size) -> decltype(auto) {
        if constexpr (std::is_same_v<ToColumn, ColumnString>) {
            auto& vec_res = col_res->get_chars();
            vec_res.resize(col_size * IPV6_BINARY_LENGTH);
            return (vec_res);
        } else {
            auto& vec_res = col_res->get_data();
            vec_res.resize(col_size);
            return (vec_res);
        }
    };

    auto col_res = column_create(column_size);
    auto& vec_res = get_vector(col_res, column_size);

    using Chars = typename StringColumnType::Chars;
    const Chars& vec_src = string_column.get_chars();

    size_t src_offset = 0;

    /// ColumnString contains not null terminated strings. But functions parseIPv6, parseIPv4 expect null terminated string.
    /// TODO fix this - now parseIPv6/parseIPv4 accept end iterator, so can be parsed in-place
    std::string string_buffer;

    int offset_inc = 1;
    ColumnString* column_string = nullptr;
    if constexpr (std::is_same_v<ToColumn, ColumnString>) {
        offset_inc = IPV6_BINARY_LENGTH;
        column_string = assert_cast<ColumnString*>(col_res.get());
    }

    for (size_t out_offset = 0, i = 0; i < column_size; out_offset += offset_inc, ++i) {
        char src_ipv4_buf[sizeof("::ffff:") + IPV4_MAX_TEXT_LENGTH + 1] = "::ffff:";
        size_t src_next_offset = src_offset;

        const char* src_value = nullptr;
        auto* res_value = reinterpret_cast<unsigned char*>(&vec_res[out_offset]);

        if constexpr (std::is_same_v<StringColumnType, ColumnString>) {
            src_value = reinterpret_cast<const char*>(&vec_src[src_offset]);
            src_next_offset = string_column.get_offsets()[i];

            string_buffer.assign(src_value, src_next_offset - src_offset);
            src_value = string_buffer.c_str();
        }

        if (null_map && (*null_map)[i]) {
            if (exception_mode == IPConvertExceptionMode::Throw) {
                throw Exception(
                        ErrorCode::INVALID_ARGUMENT,
                        "Null Input, you may consider convert it to a valid default IPv6 value "
                        "like '::' first");
            } else if (exception_mode == IPConvertExceptionMode::Default) {
                std::fill_n(&vec_res[out_offset], offset_inc, 0);
            } else {
                std::fill_n(&vec_res[out_offset], offset_inc, 0);
                (*vec_null_map_to)[i] = true;
            }
            if constexpr (std::is_same_v<ToColumn, ColumnString>) {
                DCHECK(column_string != nullptr);
                column_string->get_offsets().push_back((i + 1) * IPV6_BINARY_LENGTH);
            }
            src_offset = src_next_offset;
            continue;
        }

        bool parse_result = false;
        Int64 dummy_result = 0;

        /// For both cases below: In case of failure, the function parseIPv6 fills vec_res with zero bytes.

        /// If the source IP address is parsable as an IPv4 address, then transform it into a valid IPv6 address.
        /// Keeping it simple by just prefixing `::ffff:` to the IPv4 address to represent it as a valid IPv6 address.
        size_t string_length = src_next_offset - src_offset;
        if (string_length != 0) {
            if (try_parse_ipv4(src_value, dummy_result)) {
                strncat(src_ipv4_buf, src_value, sizeof(src_ipv4_buf) - strlen(src_ipv4_buf) - 1);
                parse_result = parse_ipv6_whole(src_ipv4_buf, res_value);
            } else {
                parse_result = parse_ipv6_whole(src_value, res_value);
            }
        }

        if (parse_result && string_length != 0) {
            if constexpr (std::is_same_v<ToColumn, ColumnString>) {
                // handling 16 bytes ipv6 string in the big-endian byte order
                // is aimed at conforming to human reading habits
                std::reverse(res_value, res_value + IPV6_BINARY_LENGTH);
            }
            if constexpr (std::is_same_v<ToColumn, ColumnString>) {
                auto* column_string_res = assert_cast<ColumnString*>(col_res.get());
                std::copy(res_value, res_value + IPV6_BINARY_LENGTH,
                          column_string_res->get_chars().begin() + i * IPV6_BINARY_LENGTH);
                column_string_res->get_offsets().push_back((i + 1) * IPV6_BINARY_LENGTH);
            } else {
                col_res->insert_data(reinterpret_cast<const char*>(res_value), IPV6_BINARY_LENGTH);
            }
        } else {
            if (exception_mode == IPConvertExceptionMode::Throw) {
                throw Exception(ErrorCode::INVALID_ARGUMENT, "Invalid IPv6 value");
            }
            std::fill_n(&vec_res[out_offset], offset_inc, 0);
            if constexpr (std::is_same_v<ToColumn, ColumnString>) {
                auto* column_string_res = assert_cast<ColumnString*>(col_res.get());
                column_string_res->get_offsets().push_back((i + 1) * IPV6_BINARY_LENGTH);
            }
            if constexpr (exception_mode == IPConvertExceptionMode::Null) {
                (*vec_null_map_to)[i] = true;
            }
        }
        src_offset = src_next_offset;
    }

    if constexpr (exception_mode == IPConvertExceptionMode::Null) {
        return ColumnNullable::create(std::move(col_res), std::move(col_null_map_to));
    }
    return col_res;
}
} // namespace detail

template <IPConvertExceptionMode exception_mode, typename ToColumn = ColumnIPv6>
ColumnPtr convert_to_ipv6(ColumnPtr column, const PaddedPODArray<UInt8>* null_map = nullptr) {
    const auto* column_input_string = assert_cast<const ColumnString*>(column.get());
    auto result = detail::convert_to_ipv6<exception_mode, ToColumn>(*column_input_string, null_map);
    return result;
}

template <IPConvertExceptionMode exception_mode>
class FunctionIPv6StringToNum : public IFunction {
public:
    static constexpr auto name = exception_mode == IPConvertExceptionMode::Throw
                                         ? "ipv6_string_to_num"
                                         : (exception_mode == IPConvertExceptionMode::Default
                                                    ? "ipv6_string_to_num_or_default"
                                                    : "ipv6_string_to_num_or_null");

    static FunctionPtr create() {
        return std::make_shared<FunctionIPv6StringToNum<exception_mode>>();
    }

    String get_name() const override { return name; }

    size_t get_number_of_arguments() const override { return 1; }

    bool use_default_implementation_for_nulls() const override { return false; }

    DataTypePtr get_return_type_impl(const DataTypes& arguments) const override {
        auto result_type = std::make_shared<DataTypeString>();

        if constexpr (exception_mode == IPConvertExceptionMode::Null) {
            return make_nullable(result_type);
        }

        return result_type;
    }

    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count) const override {
        ColumnPtr column = block.get_by_position(arguments[0]).column;
        ColumnPtr null_map_column;
        const NullMap* null_map = nullptr;

        if (column->is_nullable()) {
            const auto* column_nullable = assert_cast<const ColumnNullable*>(column.get());
            column = column_nullable->get_nested_column_ptr();
            null_map_column = column_nullable->get_null_map_column_ptr();
            null_map = &column_nullable->get_null_map_data();
        }

        auto col_res = convert_to_ipv6<exception_mode, ColumnString>(column, null_map);

        if (null_map && exception_mode == IPConvertExceptionMode::Null) {
            block.replace_by_position(
                    result, ColumnNullable::create(std::move(col_res), std::move(null_map_column)));
        } else {
            block.replace_by_position(result, std::move(col_res));
        }
        return Status::OK();
    }
};

template <typename Type>
class FunctionIsIPString : public IFunction {
    static_assert(std::is_same_v<Type, IPv4> || std::is_same_v<Type, IPv6>);

public:
    static constexpr auto name = std::is_same_v<Type, IPv4> ? "is_ipv4_string" : "is_ipv6_string";
    static FunctionPtr create() { return std::make_shared<FunctionIsIPString<Type>>(); }

    String get_name() const override { return name; }

    size_t get_number_of_arguments() const override { return 1; }

    DataTypePtr get_return_type_impl(const DataTypes& arguments) const override {
        return std::make_shared<DataTypeUInt8>();
    }

    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count) const override {
        const auto& addr_column_with_type_and_name = block.get_by_position(arguments[0]);
        const ColumnPtr& addr_column = addr_column_with_type_and_name.column;
        const auto* str_addr_column = assert_cast<const ColumnString*>(addr_column.get());
        auto col_res = ColumnUInt8::create(input_rows_count, 0);
        auto& col_res_data = col_res->get_data();

        for (size_t i = 0; i < input_rows_count; ++i) {
            if constexpr (std::is_same_v<Type, IPv4>) {
                StringRef ipv4_str = str_addr_column->get_data_at(i);
                if (IPv4Value::is_valid_string(ipv4_str.data, ipv4_str.size)) {
                    col_res_data[i] = 1;
                }
            } else {
                StringRef ipv6_str = str_addr_column->get_data_at(i);
                if (IPv6Value::is_valid_string(ipv6_str.data, ipv6_str.size)) {
                    col_res_data[i] = 1;
                }
            }
        }

        block.replace_by_position(result, std::move(col_res));
        return Status::OK();
    }
};

class FunctionIsIPAddressInRange : public IFunction {
public:
    static constexpr auto name = "is_ip_address_in_range";
    static FunctionPtr create() { return std::make_shared<FunctionIsIPAddressInRange>(); }

    String get_name() const override { return name; }

    size_t get_number_of_arguments() const override { return 2; }

    DataTypePtr get_return_type_impl(const DataTypes& arguments) const override {
        return std::make_shared<DataTypeUInt8>();
    }

    template <PrimitiveType PT, typename ColumnType>
    void execute_impl_with_ip(size_t input_rows_count, bool addr_const, bool cidr_const,
                              const ColumnString* str_cidr_column, const ColumnPtr addr_column,
                              ColumnUInt8* col_res) const {
        auto& col_res_data = col_res->get_data();
        const auto& ip_data = assert_cast<const ColumnType*>(addr_column.get())->get_data();
        for (size_t i = 0; i < input_rows_count; ++i) {
            auto addr_idx = index_check_const(i, addr_const);
            auto cidr_idx = index_check_const(i, cidr_const);
            auto cidr_data = str_cidr_column->get_data_at(cidr_idx);
            // cidr_data maybe NULL, But the input column is nested column, so check here avoid throw exception
            if (cidr_data.data == nullptr || cidr_data.size == 0) {
                col_res_data[i] = 0;
                continue;
            }
            const auto cidr = parse_ip_with_cidr(cidr_data.to_string_view());
            if constexpr (PT == PrimitiveType::TYPE_IPV4) {
                if (cidr._address.as_v4()) {
                    col_res_data[i] = match_ipv4_subnet(ip_data[addr_idx], cidr._address.as_v4(),
                                                        cidr._prefix)
                                              ? 1
                                              : 0;
                } else {
                    col_res_data[i] = 0;
                }
            } else if constexpr (PT == PrimitiveType::TYPE_IPV6) {
                if (cidr._address.as_v6()) {
                    col_res_data[i] = match_ipv6_subnet((uint8_t*)(&ip_data[addr_idx]),
                                                        cidr._address.as_v6(), cidr._prefix)
                                              ? 1
                                              : 0;
                } else {
                    col_res_data[i] = 0;
                }
            }
        }
    }

    Status evaluate_inverted_index(
            const ColumnsWithTypeAndName& arguments,
            const std::vector<vectorized::IndexFieldNameAndTypePair>& data_type_with_names,
            std::vector<segment_v2::IndexIterator*> iterators, uint32_t num_rows,
            segment_v2::InvertedIndexResultBitmap& bitmap_result) const override {
        DCHECK(arguments.size() == 1);
        DCHECK(data_type_with_names.size() == 1);
        DCHECK(iterators.size() == 1);
        auto* iter = iterators[0];
        auto data_type_with_name = data_type_with_names[0];
        if (iter == nullptr) {
            return Status::OK();
        }

        if (!iter->get_reader()->is_bkd_index()) {
            // Not support only bkd index
            return Status::Error<ErrorCode::INVERTED_INDEX_EVALUATE_SKIPPED>(
                    "Inverted index evaluate skipped, ip range reader can only support by bkd "
                    "reader");
        }
        // Get the is_ip_address_in_range from the arguments: cidr
        const auto& cidr_column_with_type_and_name = arguments[0];
        // in is_ip_address_in_range param is const Field
        ColumnPtr arg_column = cidr_column_with_type_and_name.column;
        DataTypePtr arg_type = cidr_column_with_type_and_name.type;
        if ((is_column_nullable(*arg_column) && !is_column_const(*remove_nullable(arg_column))) ||
            (!is_column_nullable(*arg_column) && !is_column_const(*arg_column))) {
            // if not we should skip inverted index and evaluate in expression
            return Status::Error<ErrorCode::INVERTED_INDEX_EVALUATE_SKIPPED>(
                    "Inverted index evaluate skipped, is_ip_address_in_range only support const "
                    "value");
        }
        // check param type is string
        if (!is_string_type(arg_type->get_primitive_type())) {
            return Status::Error<ErrorCode::INVERTED_INDEX_EVALUATE_SKIPPED>(
                    "Inverted index evaluate skipped, is_ip_address_in_range only support string "
                    "type");
        }
        // min && max ip address
        Field min_ip, max_ip;
        IPAddressCIDR cidr = parse_ip_with_cidr(arg_column->get_data_at(0));
        if (data_type_with_name.second->get_primitive_type() == TYPE_IPV4 &&
            cidr._address.as_v4()) {
            auto range = apply_cidr_mask(cidr._address.as_v4(), cidr._prefix);
            min_ip = Field::create_field<TYPE_IPV4>(range.first);
            max_ip = Field::create_field<TYPE_IPV4>(range.second);
        } else if (data_type_with_name.second->get_primitive_type() == TYPE_IPV6 &&
                   cidr._address.as_v6()) {
            auto cidr_range_ipv6_col = ColumnIPv6::create(2, 0);
            auto& cidr_range_ipv6_data = cidr_range_ipv6_col->get_data();
            apply_cidr_mask(reinterpret_cast<const char*>(cidr._address.as_v6()),
                            reinterpret_cast<char*>(&cidr_range_ipv6_data[0]),
                            reinterpret_cast<char*>(&cidr_range_ipv6_data[1]), cidr._prefix);
            min_ip = Field::create_field<TYPE_IPV6>(cidr_range_ipv6_data[0]);
            max_ip = Field::create_field<TYPE_IPV6>(cidr_range_ipv6_data[1]);
        } else {
            // if here param is invalid for current column to calcute min_ip|max_ip we just return
            return Status::Error<ErrorCode::INVERTED_INDEX_EVALUATE_SKIPPED>(
                    "Inverted index evaluate skipped, data type " + arg_type->get_name() +
                    " can not support this cidr " + arg_column->get_data_at(0).to_string());
        }
        // apply for inverted index
        std::shared_ptr<roaring::Roaring> null_bitmap = std::make_shared<roaring::Roaring>();

        auto param_type = data_type_with_name.second->get_primitive_type();
        std::unique_ptr<segment_v2::InvertedIndexQueryParamFactory> query_param = nullptr;

        // >= min ip
        RETURN_IF_ERROR(segment_v2::InvertedIndexQueryParamFactory::create_query_value(
                param_type, &min_ip, query_param));
        segment_v2::InvertedIndexParam res_param;
        res_param.column_name = data_type_with_name.first;
        res_param.query_type = segment_v2::InvertedIndexQueryType::GREATER_EQUAL_QUERY;
        res_param.query_value = query_param->get_value();
        res_param.num_rows = num_rows;
        res_param.roaring = std::make_shared<roaring::Roaring>();
        RETURN_IF_ERROR(iter->read_from_index(&res_param));

        // <= max ip
        RETURN_IF_ERROR(segment_v2::InvertedIndexQueryParamFactory::create_query_value(
                param_type, &max_ip, query_param));
        segment_v2::InvertedIndexParam max_param;
        max_param.column_name = data_type_with_name.first;
        max_param.query_type = segment_v2::InvertedIndexQueryType::LESS_EQUAL_QUERY;
        max_param.query_value = query_param->get_value();
        max_param.num_rows = num_rows;
        max_param.roaring = std::make_shared<roaring::Roaring>();
        RETURN_IF_ERROR(iter->read_from_index(&max_param));

        DBUG_EXECUTE_IF("ip.inverted_index_filtered", {
            auto req_id = DebugPoints::instance()->get_debug_param_or_default<int32_t>(
                    "ip.inverted_index_filtered", "req_id", 0);
            LOG(INFO) << "execute inverted index req_id: " << req_id
                      << " min: " << res_param.roaring->cardinality();
        });
        *res_param.roaring &= *max_param.roaring;
        DBUG_EXECUTE_IF("ip.inverted_index_filtered", {
            auto req_id = DebugPoints::instance()->get_debug_param_or_default<int32_t>(
                    "ip.inverted_index_filtered", "req_id", 0);
            LOG(INFO) << "execute inverted index req_id: " << req_id
                      << " max: " << max_param.roaring->cardinality()
                      << " result: " << res_param.roaring->cardinality();
        });
        segment_v2::InvertedIndexResultBitmap result(res_param.roaring, null_bitmap);
        bitmap_result = result;
        bitmap_result.mask_out_null();
        return Status::OK();
    }

    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count) const override {
        DBUG_EXECUTE_IF("ip.inverted_index_filtered", {
            auto req_id = DebugPoints::instance()->get_debug_param_or_default<int32_t>(
                    "ip.inverted_index_filtered", "req_id", 0);
            return Status::Error<ErrorCode::INTERNAL_ERROR>(
                    "{} has already execute inverted index req_id {} , should not execute expr "
                    "with rows: {}",
                    get_name(), req_id, input_rows_count);
        });
        const auto& addr_column_with_type_and_name = block.get_by_position(arguments[0]);
        const auto& cidr_column_with_type_and_name = block.get_by_position(arguments[1]);
        const auto& [addr_column, addr_const] =
                unpack_if_const(addr_column_with_type_and_name.column);
        const auto& [cidr_column, cidr_const] =
                unpack_if_const(cidr_column_with_type_and_name.column);

        auto col_res = ColumnUInt8::create(input_rows_count, 0);
        auto& col_res_data = col_res->get_data();

        if (addr_column_with_type_and_name.type->get_primitive_type() == TYPE_IPV4) {
            execute_impl_with_ip<PrimitiveType::TYPE_IPV4, ColumnIPv4>(
                    input_rows_count, addr_const, cidr_const,
                    assert_cast<const ColumnString*>(cidr_column.get()), addr_column,
                    col_res.get());
        } else if (addr_column_with_type_and_name.type->get_primitive_type() == TYPE_IPV6) {
            execute_impl_with_ip<PrimitiveType::TYPE_IPV6, ColumnIPv6>(
                    input_rows_count, addr_const, cidr_const,
                    assert_cast<const ColumnString*>(cidr_column.get()), addr_column,
                    col_res.get());
        } else {
            const auto* str_addr_column = assert_cast<const ColumnString*>(addr_column.get());
            const auto* str_cidr_column = assert_cast<const ColumnString*>(cidr_column.get());

            for (size_t i = 0; i < input_rows_count; ++i) {
                auto addr_idx = index_check_const(i, addr_const);
                auto cidr_idx = index_check_const(i, cidr_const);
                auto addr_data = str_addr_column->get_data_at(addr_idx);
                auto cidr_data = str_cidr_column->get_data_at(cidr_idx);
                // cidr_data maybe NULL, But the input column is nested column, so check here avoid throw exception
                if (cidr_data.data == nullptr || cidr_data.size == 0) {
                    col_res_data[i] = 0;
                    continue;
                }
                const auto addr = IPAddressVariant(addr_data.to_string_view());
                const auto cidr = parse_ip_with_cidr(cidr_data.to_string_view());
                col_res_data[i] = is_address_in_range(addr, cidr) ? 1 : 0;
            }
        }

        block.replace_by_position(result, std::move(col_res));
        return Status::OK();
    }
};

class FunctionIPv4CIDRToRange : public IFunction {
public:
    static constexpr auto name = "ipv4_cidr_to_range";
    static FunctionPtr create() { return std::make_shared<FunctionIPv4CIDRToRange>(); }

    String get_name() const override { return name; }

    size_t get_number_of_arguments() const override { return 2; }

    DataTypePtr get_return_type_impl(const DataTypes& arguments) const override {
        DataTypePtr element = std::make_shared<DataTypeIPv4>();
        return std::make_shared<DataTypeStruct>(DataTypes {element, element},
                                                Strings {"min", "max"});
    }

    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count) const override {
        ColumnWithTypeAndName& ip_column = block.get_by_position(arguments[0]);
        ColumnWithTypeAndName& cidr_column = block.get_by_position(arguments[1]);

        const auto& [ip_column_ptr, ip_col_const] = unpack_if_const(ip_column.column);
        const auto& [cidr_column_ptr, cidr_col_const] = unpack_if_const(cidr_column.column);

        const auto* col_ip_column = assert_cast<const ColumnIPv4*>(ip_column_ptr.get());
        const auto* col_cidr_column = assert_cast<const ColumnInt16*>(cidr_column_ptr.get());

        const typename ColumnIPv4::Container& vec_ip_input = col_ip_column->get_data();
        const ColumnInt16::Container& vec_cidr_input = col_cidr_column->get_data();
        auto col_lower_range_output = ColumnIPv4::create(input_rows_count, 0);
        auto col_upper_range_output = ColumnIPv4::create(input_rows_count, 0);

        ColumnIPv4::Container& vec_lower_range_output = col_lower_range_output->get_data();
        ColumnIPv4::Container& vec_upper_range_output = col_upper_range_output->get_data();

        static constexpr UInt8 max_cidr_mask = IPV4_BINARY_LENGTH * 8;

        if (ip_col_const) {
            auto ip = vec_ip_input[0];
            for (size_t i = 0; i < input_rows_count; ++i) {
                auto cidr = vec_cidr_input[i];
                if (cidr < 0 || cidr > max_cidr_mask) {
                    throw Exception(ErrorCode::INVALID_ARGUMENT, "Illegal cidr value '{}'",
                                    std::to_string(cidr));
                }
                auto range = apply_cidr_mask(ip, cast_set<UInt8>(cidr));
                vec_lower_range_output[i] = range.first;
                vec_upper_range_output[i] = range.second;
            }
        } else if (cidr_col_const) {
            auto cidr = vec_cidr_input[0];
            if (cidr < 0 || cidr > max_cidr_mask) {
                throw Exception(ErrorCode::INVALID_ARGUMENT, "Illegal cidr value '{}'",
                                std::to_string(cidr));
            }
            for (size_t i = 0; i < input_rows_count; ++i) {
                auto ip = vec_ip_input[i];
                auto range = apply_cidr_mask(ip, cast_set<UInt8>(cidr));
                vec_lower_range_output[i] = range.first;
                vec_upper_range_output[i] = range.second;
            }
        } else {
            for (size_t i = 0; i < input_rows_count; ++i) {
                auto ip = vec_ip_input[i];
                auto cidr = vec_cidr_input[i];
                if (cidr < 0 || cidr > max_cidr_mask) {
                    throw Exception(ErrorCode::INVALID_ARGUMENT, "Illegal cidr value '{}'",
                                    std::to_string(cidr));
                }
                auto range = apply_cidr_mask(ip, cast_set<UInt8>(cidr));
                vec_lower_range_output[i] = range.first;
                vec_upper_range_output[i] = range.second;
            }
        }

        block.replace_by_position(
                result, ColumnStruct::create(Columns {std::move(col_lower_range_output),
                                                      std::move(col_upper_range_output)}));
        return Status::OK();
    }
};

/**
 * this function accepts two arguments: an IPv6 address and a CIDR mask
 *  IPv6 address can be either ipv6 type or string type as ipv6 string address
 *  FE: PropagateNullable is used to handle nullable columns
 */
class FunctionIPv6CIDRToRange : public IFunction {
public:
    static constexpr auto name = "ipv6_cidr_to_range";
    static FunctionPtr create() { return std::make_shared<FunctionIPv6CIDRToRange>(); }

    String get_name() const override { return name; }

    size_t get_number_of_arguments() const override { return 2; }

    DataTypePtr get_return_type_impl(const DataTypes& arguments) const override {
        DataTypePtr element = std::make_shared<DataTypeIPv6>();
        return std::make_shared<DataTypeStruct>(DataTypes {element, element},
                                                Strings {"min", "max"});
    }

    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count) const override {
        const auto& addr_column_with_type_and_name = block.get_by_position(arguments[0]);
        const auto& cidr_column_with_type_and_name = block.get_by_position(arguments[1]);
        const auto& [addr_column, add_col_const] =
                unpack_if_const(addr_column_with_type_and_name.column);
        const auto& [cidr_column, col_const] =
                unpack_if_const(cidr_column_with_type_and_name.column);

        const auto* cidr_col = assert_cast<const ColumnInt16*>(cidr_column.get());
        ColumnPtr col_res = nullptr;

        if (addr_column_with_type_and_name.type->get_primitive_type() == TYPE_IPV6) {
            const auto* ipv6_addr_column = assert_cast<const ColumnIPv6*>(addr_column.get());
            col_res = execute_impl(*ipv6_addr_column, *cidr_col, input_rows_count, add_col_const,
                                   col_const);
        } else if (is_string_type(addr_column_with_type_and_name.type->get_primitive_type())) {
            ColumnPtr col_ipv6 =
                    convert_to_ipv6<IPConvertExceptionMode::Throw>(addr_column, nullptr);
            const auto* ipv6_addr_column = assert_cast<const ColumnIPv6*>(col_ipv6.get());
            col_res = execute_impl(*ipv6_addr_column, *cidr_col, input_rows_count, add_col_const,
                                   col_const);
        } else {
            return Status::RuntimeError(
                    "Illegal column {} of argument of function {}, Expected IPv6 or String",
                    addr_column->get_name(), get_name());
        }

        block.replace_by_position(result, std::move(col_res));
        return Status::OK();
    }

    static ColumnPtr execute_impl(const ColumnIPv6& from_column, const ColumnInt16& cidr_column,
                                  size_t input_rows_count, bool is_addr_const = false,
                                  bool is_cidr_const = false) {
        auto col_res_lower_range = ColumnIPv6::create(input_rows_count, 0);
        auto col_res_upper_range = ColumnIPv6::create(input_rows_count, 0);
        auto& vec_res_lower_range = col_res_lower_range->get_data();
        auto& vec_res_upper_range = col_res_upper_range->get_data();

        static constexpr UInt8 max_cidr_mask = IPV6_BINARY_LENGTH * 8;

        if (is_addr_const) {
            for (size_t i = 0; i < input_rows_count; ++i) {
                auto cidr = cidr_column.get_int(i);
                if (cidr < 0 || cidr > max_cidr_mask) {
                    throw Exception(ErrorCode::INVALID_ARGUMENT, "Illegal cidr value '{}'",
                                    std::to_string(cidr));
                }
                apply_cidr_mask(from_column.get_data_at(0).data,
                                reinterpret_cast<char*>(&vec_res_lower_range[i]),
                                reinterpret_cast<char*>(&vec_res_upper_range[i]),
                                cast_set<UInt8>(cidr));
            }
        } else if (is_cidr_const) {
            auto cidr = cidr_column.get_int(0);
            if (cidr < 0 || cidr > max_cidr_mask) {
                throw Exception(ErrorCode::INVALID_ARGUMENT, "Illegal cidr value '{}'",
                                std::to_string(cidr));
            }
            for (size_t i = 0; i < input_rows_count; ++i) {
                apply_cidr_mask(from_column.get_data_at(i).data,
                                reinterpret_cast<char*>(&vec_res_lower_range[i]),
                                reinterpret_cast<char*>(&vec_res_upper_range[i]),
                                cast_set<UInt8>(cidr));
            }
        } else {
            for (size_t i = 0; i < input_rows_count; ++i) {
                auto cidr = cidr_column.get_int(i);
                if (cidr < 0 || cidr > max_cidr_mask) {
                    throw Exception(ErrorCode::INVALID_ARGUMENT, "Illegal cidr value '{}'",
                                    std::to_string(cidr));
                }
                apply_cidr_mask(from_column.get_data_at(i).data,
                                reinterpret_cast<char*>(&vec_res_lower_range[i]),
                                reinterpret_cast<char*>(&vec_res_upper_range[i]),
                                cast_set<UInt8>(cidr));
            }
        }
        return ColumnStruct::create(
                Columns {std::move(col_res_lower_range), std::move(col_res_upper_range)});
    }
};

class FunctionIsIPv4Compat : public IFunction {
public:
    static constexpr auto name = "is_ipv4_compat";
    static FunctionPtr create() { return std::make_shared<FunctionIsIPv4Compat>(); }

    String get_name() const override { return name; }

    size_t get_number_of_arguments() const override { return 1; }

    DataTypePtr get_return_type_impl(const DataTypes& arguments) const override {
        return std::make_shared<DataTypeUInt8>();
    }

    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count) const override {
        const ColumnPtr& column = block.get_by_position(arguments[0]).column;
        const auto* col_in = assert_cast<const ColumnString*>(column.get());

        size_t col_size = col_in->size();
        auto col_res = ColumnUInt8::create(col_size, 0);
        auto& col_res_data = col_res->get_data();

        for (size_t i = 0; i < col_size; ++i) {
            auto ipv4_in = col_in->get_data_at(i);
            if (is_ipv4_compat(reinterpret_cast<const UInt8*>(ipv4_in.data))) {
                col_res_data[i] = 1;
            }
        }

        block.replace_by_position(result, std::move(col_res));
        return Status::OK();
    }

private:
    static bool is_ipv4_compat(const UInt8* address) {
        return (LittleEndian::Load64(address) == 0) && (LittleEndian::Load32(address + 8) == 0) &&
               (LittleEndian::Load32(address + 12) != 0);
    }
};

class FunctionIsIPv4Mapped : public IFunction {
public:
    static constexpr auto name = "is_ipv4_mapped";
    static FunctionPtr create() { return std::make_shared<FunctionIsIPv4Mapped>(); }

    String get_name() const override { return name; }

    size_t get_number_of_arguments() const override { return 1; }

    DataTypePtr get_return_type_impl(const DataTypes& arguments) const override {
        return std::make_shared<DataTypeUInt8>();
    }

    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count) const override {
        const ColumnPtr& column = block.get_by_position(arguments[0]).column;
        const auto* col_in = assert_cast<const ColumnString*>(column.get());

        size_t col_size = col_in->size();
        auto col_res = ColumnUInt8::create(col_size, 0);
        auto& col_res_data = col_res->get_data();

        for (size_t i = 0; i < col_size; ++i) {
            auto ipv4_in = col_in->get_data_at(i);
            if (is_ipv4_mapped(reinterpret_cast<const UInt8*>(ipv4_in.data))) {
                col_res_data[i] = 1;
            }
        }

        block.replace_by_position(result, std::move(col_res));
        return Status::OK();
    }

private:
    static bool is_ipv4_mapped(const UInt8* address) {
        return (LittleEndian::Load64(address) == 0) &&
               ((LittleEndian::Load64(address + 8) & 0x00000000FFFFFFFFULL) ==
                0x00000000FFFF0000ULL);
    }
};

template <IPConvertExceptionMode exception_mode, PrimitiveType PType>
inline constexpr auto to_ip_func_name() {
    if constexpr (PType == TYPE_IPV4) {
        return exception_mode == IPConvertExceptionMode::Throw
                       ? "to_ipv4"
                       : (exception_mode == IPConvertExceptionMode::Default ? "to_ipv4_or_default"
                                                                            : "to_ipv4_or_null");
    } else {
        return exception_mode == IPConvertExceptionMode::Throw
                       ? "to_ipv6"
                       : (exception_mode == IPConvertExceptionMode::Default ? "to_ipv6_or_default"
                                                                            : "to_ipv6_or_null");
    }
}

template <IPConvertExceptionMode exception_mode, PrimitiveType PType>
class FunctionToIP : public IFunction {
    static_assert(is_ip(PType));

public:
    static constexpr auto name = to_ip_func_name<exception_mode, PType>();

    static FunctionPtr create() { return std::make_shared<FunctionToIP<exception_mode, PType>>(); }

    String get_name() const override { return name; }

    size_t get_number_of_arguments() const override { return 1; }

    DataTypePtr get_return_type_impl(const DataTypes& arguments) const override {
        DataTypePtr result_type;

        if constexpr (PType == TYPE_IPV4) {
            result_type = std::make_shared<DataTypeIPv4>();
        } else {
            result_type = std::make_shared<DataTypeIPv6>();
        }

        if constexpr (exception_mode == IPConvertExceptionMode::Null) {
            return make_nullable(result_type);
        } else {
            return result_type;
        }
    }

    bool use_default_implementation_for_nulls() const override { return false; }

    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count) const override {
        const auto& addr_column_with_type_and_name = block.get_by_position(arguments[0]);
        const ColumnPtr& addr_column = addr_column_with_type_and_name.column;
        const ColumnString* str_addr_column = nullptr;
        const NullMap* addr_null_map = nullptr;

        if (addr_column_with_type_and_name.type->is_nullable()) {
            const auto* addr_column_nullable =
                    assert_cast<const ColumnNullable*>(addr_column.get());
            str_addr_column = assert_cast<const ColumnString*>(
                    addr_column_nullable->get_nested_column_ptr().get());
            addr_null_map = &addr_column_nullable->get_null_map_data();
        } else {
            str_addr_column = assert_cast<const ColumnString*>(addr_column.get());
        }

        auto col_res = ColumnVector<PType>::create(input_rows_count, 0);
        auto res_null_map = ColumnUInt8::create(input_rows_count, 0);
        auto& col_res_data = col_res->get_data();
        auto& res_null_map_data = res_null_map->get_data();

        for (size_t i = 0; i < input_rows_count; ++i) {
            if (addr_null_map && (*addr_null_map)[i]) {
                if constexpr (exception_mode == IPConvertExceptionMode::Throw) {
                    throw Exception(ErrorCode::INVALID_ARGUMENT,
                                    "The arguments of function {} must be String, not NULL",
                                    get_name());
                } else if constexpr (exception_mode == IPConvertExceptionMode::Default) {
                    col_res_data[i] = 0; // '0.0.0.0' or '::'
                    continue;
                } else {
                    res_null_map_data[i] = 1;
                    continue;
                }
            }

            if constexpr (PType == TYPE_IPV4) {
                StringRef ipv4_str = str_addr_column->get_data_at(i);
                IPv4 ipv4_val = 0;
                if (IPv4Value::from_string(ipv4_val, ipv4_str.data, ipv4_str.size)) {
                    col_res_data[i] = ipv4_val;
                } else {
                    if constexpr (exception_mode == IPConvertExceptionMode::Throw) {
                        throw Exception(ErrorCode::INVALID_ARGUMENT, "Invalid IPv4 value '{}'",
                                        ipv4_str.to_string_view());
                    } else if constexpr (exception_mode == IPConvertExceptionMode::Default) {
                        col_res_data[i] = 0; // '0.0.0.0'
                    } else {
                        res_null_map_data[i] = 1;
                    }
                }
            } else {
                StringRef ipv6_str = str_addr_column->get_data_at(i);
                IPv6 ipv6_val = 0;
                if (IPv6Value::from_string(ipv6_val, ipv6_str.data, ipv6_str.size)) {
                    col_res_data[i] = ipv6_val;
                } else {
                    if constexpr (exception_mode == IPConvertExceptionMode::Throw) {
                        throw Exception(ErrorCode::INVALID_ARGUMENT, "Invalid IPv6 value '{}'",
                                        ipv6_str.to_string_view());
                    } else if constexpr (exception_mode == IPConvertExceptionMode::Default) {
                        col_res_data[i] = 0; // '::'
                    } else if constexpr (exception_mode == IPConvertExceptionMode::Null) {
                        res_null_map_data[i] = 1;
                    }
                }
            }
        }

        if constexpr (exception_mode == IPConvertExceptionMode::Null) {
            block.replace_by_position(
                    result, ColumnNullable::create(std::move(col_res), std::move(res_null_map)));
        } else {
            block.replace_by_position(result, std::move(col_res));
        }

        return Status::OK();
    }
};

class FunctionIPv4ToIPv6 : public IFunction {
public:
    static constexpr auto name = "ipv4_to_ipv6";
    static FunctionPtr create() { return std::make_shared<FunctionIPv4ToIPv6>(); }

    String get_name() const override { return name; }

    size_t get_number_of_arguments() const override { return 1; }

    DataTypePtr get_return_type_impl(const DataTypes& arguments) const override {
        return std::make_shared<DataTypeIPv6>();
    }

    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count) const override {
        const auto& ipv4_column_with_type_and_name = block.get_by_position(arguments[0]);
        const auto& [ipv4_column, ipv4_const] =
                unpack_if_const(ipv4_column_with_type_and_name.column);
        const auto* ipv4_addr_column = assert_cast<const ColumnIPv4*>(ipv4_column.get());
        const auto& ipv4_column_data = ipv4_addr_column->get_data();
        auto col_res = ColumnIPv6::create(input_rows_count, 0);
        auto& col_res_data = col_res->get_data();

        for (size_t i = 0; i < input_rows_count; ++i) {
            auto ipv4_idx = index_check_const(i, ipv4_const);
            map_ipv4_to_ipv6(ipv4_column_data[ipv4_idx],
                             reinterpret_cast<UInt8*>(&col_res_data[i]));
        }

        block.replace_by_position(result, std::move(col_res));
        return Status::OK();
    }
};

class FunctionCutIPv6 : public IFunction {
public:
    static constexpr auto name = "cut_ipv6";
    static FunctionPtr create() { return std::make_shared<FunctionCutIPv6>(); }

    String get_name() const override { return name; }

    size_t get_number_of_arguments() const override { return 3; }

    DataTypePtr get_return_type_impl(const DataTypes& arguments) const override {
        return std::make_shared<DataTypeString>();
    }

    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count) const override {
        const auto& ipv6_column_with_type_and_name = block.get_by_position(arguments[0]);
        const auto& bytes_to_cut_for_ipv6_column_with_type_and_name =
                block.get_by_position(arguments[1]);
        const auto& bytes_to_cut_for_ipv4_column_with_type_and_name =
                block.get_by_position(arguments[2]);

        const auto& [ipv6_column, ipv6_const] =
                unpack_if_const(ipv6_column_with_type_and_name.column);
        const auto& [bytes_to_cut_for_ipv6_column, bytes_to_cut_for_ipv6_const] =
                unpack_if_const(bytes_to_cut_for_ipv6_column_with_type_and_name.column);
        const auto& [bytes_to_cut_for_ipv4_column, bytes_to_cut_for_ipv4_const] =
                unpack_if_const(bytes_to_cut_for_ipv4_column_with_type_and_name.column);

        const auto* ipv6_addr_column = assert_cast<const ColumnIPv6*>(ipv6_column.get());
        const auto* to_cut_for_ipv6_bytes_column =
                assert_cast<const ColumnInt8*>(bytes_to_cut_for_ipv6_column.get());
        const auto* to_cut_for_ipv4_bytes_column =
                assert_cast<const ColumnInt8*>(bytes_to_cut_for_ipv4_column.get());

        const auto& ipv6_addr_column_data = ipv6_addr_column->get_data();
        const auto& to_cut_for_ipv6_bytes_column_data = to_cut_for_ipv6_bytes_column->get_data();
        const auto& to_cut_for_ipv4_bytes_column_data = to_cut_for_ipv4_bytes_column->get_data();

        auto col_res = ColumnString::create();
        ColumnString::Chars& chars_res = col_res->get_chars();
        ColumnString::Offsets& offsets_res = col_res->get_offsets();
        chars_res.resize(input_rows_count * (IPV6_MAX_TEXT_LENGTH + 1)); // + 1 for ending '\0'
        offsets_res.resize(input_rows_count);
        auto* begin = reinterpret_cast<char*>(chars_res.data());
        auto* pos = begin;

        for (size_t i = 0; i < input_rows_count; ++i) {
            auto ipv6_idx = index_check_const(i, ipv6_const);
            auto bytes_to_cut_for_ipv6_idx = index_check_const(i, bytes_to_cut_for_ipv6_const);
            auto bytes_to_cut_for_ipv4_idx = index_check_const(i, bytes_to_cut_for_ipv4_const);
            // the current function logic is processed in big endian manner
            // But ipv6 in doris is stored in little-endian byte order
            // need transfer to big-endian byte order first, so we can't deal this process in column
            auto val_128 = ipv6_addr_column_data[ipv6_idx];
            auto* address = reinterpret_cast<unsigned char*>(&val_128);

            Int8 bytes_to_cut_for_ipv6_count =
                    to_cut_for_ipv6_bytes_column_data[bytes_to_cut_for_ipv6_idx];
            Int8 bytes_to_cut_for_ipv4_count =
                    to_cut_for_ipv4_bytes_column_data[bytes_to_cut_for_ipv4_idx];

            if (bytes_to_cut_for_ipv6_count > IPV6_BINARY_LENGTH) [[unlikely]] {
                throw Exception(ErrorCode::INVALID_ARGUMENT,
                                "Illegal value for argument 2 {} of function {}",
                                bytes_to_cut_for_ipv6_column_with_type_and_name.type->get_name(),
                                get_name());
            }

            if (bytes_to_cut_for_ipv4_count > IPV6_BINARY_LENGTH) [[unlikely]] {
                throw Exception(ErrorCode::INVALID_ARGUMENT,
                                "Illegal value for argument 3 {} of function {}",
                                bytes_to_cut_for_ipv4_column_with_type_and_name.type->get_name(),
                                get_name());
            }

            UInt8 bytes_to_cut_count = is_ipv4_mapped(address) ? bytes_to_cut_for_ipv4_count
                                                               : bytes_to_cut_for_ipv6_count;
            cut_address(address, pos, bytes_to_cut_count);
            offsets_res[i] = cast_set<uint32_t>(pos - begin);
        }

        chars_res.resize(offsets_res[offsets_res.size() - 1]);

        block.replace_by_position(result, std::move(col_res));
        return Status::OK();
    }

private:
    static bool is_ipv4_mapped(const UInt8* address) {
        return (LittleEndian::Load64(address + 8) == 0) &&
               ((LittleEndian::Load64(address) & 0xFFFFFFFF00000000ULL) == 0x0000FFFF00000000ULL);
    }

    static void cut_address(unsigned char* address, char*& dst, UInt8 zeroed_tail_bytes_count) {
        format_ipv6(address, dst, zeroed_tail_bytes_count);
    }
};

class FunctionIPv6FromUInt128StringOrNull : public IFunction {
public:
    static constexpr auto name = "ipv6_from_uint128_string_or_null";
    static FunctionPtr create() { return std::make_shared<FunctionIPv6FromUInt128StringOrNull>(); }

    String get_name() const override { return name; }

    size_t get_number_of_arguments() const override { return 1; }

    DataTypePtr get_return_type_impl(const DataTypes& arguments) const override {
        return std::make_shared<DataTypeNullable>(std::make_shared<DataTypeIPv6>());
    }

    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count) const override {
        const auto& ipv6_column_with_type_and_name = block.get_by_position(arguments[0]);
        const auto& [ipv6_column, ipv6_const] =
                unpack_if_const(ipv6_column_with_type_and_name.column);
        const auto* ipv6_addr_column = assert_cast<const ColumnString*>(ipv6_column.get());
        // result is nullable column
        auto col_res = ColumnNullable::create(ColumnIPv6::create(input_rows_count, 0),
                                              ColumnUInt8::create(input_rows_count, 1));
        auto& col_res_data = assert_cast<ColumnIPv6*>(&col_res->get_nested_column())->get_data();
        auto& res_null_map_data = col_res->get_null_map_data();

        for (size_t i = 0; i < input_rows_count; ++i) {
            IPv6 ipv6 = 0;
            auto ipv6_idx = index_check_const(i, ipv6_const);
            StringRef uint128_string = ipv6_addr_column->get_data_at(ipv6_idx);
            if (!IPv6Value::from_uint128_string(ipv6, uint128_string.data, uint128_string.size)) {
                VLOG_DEBUG << "Invalid uin128 IPv6 value '" << uint128_string.to_string_view()
                           << "'";
                // we should set null to the result not throw exception for load senior
            } else {
                col_res_data[i] = ipv6;
                res_null_map_data[i] = 0;
            }
        }

        block.replace_by_position(result, std::move(col_res));
        return Status::OK();
    }
};

} // namespace doris::vectorized

#include "common/compile_check_end.h"
