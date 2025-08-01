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
// https://github.com/ClickHouse/ClickHouse/blob/master/src/Columns/IColumn.h
// and modified by Doris

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "common/status.h"
#include "olap/olap_common.h"
#include "runtime/define_primitive_type.h"
#include "vec/common/cow.h"
#include "vec/common/pod_array_fwd.h"
#include "vec/common/string_ref.h"
#include "vec/common/typeid_cast.h"
#include "vec/core/field.h"
#include "vec/core/types.h"

namespace doris {
class SipHash;
}

namespace doris::vectorized {

class Arena;
class ColumnSorter;

using EqualFlags = std::vector<uint8_t>;
using EqualRange = std::pair<int, int>;

/// Declares interface to store columns in memory.
class IColumn : public COW<IColumn> {
private:
    friend class COW<IColumn>;

    /// Creates the same column with the same data.
    /// This is internal method to use from COW.
    /// It performs shallow copy with copy-ctor and not useful from outside.
    /// If you want to copy column for modification, look at 'mutate' method.
    virtual MutablePtr clone() const = 0;

public:
    // 64bit offsets now only Array type used, so we make it protected
    // to avoid use IColumn::Offset64 directly.
    // please use ColumnArray::Offset64 instead if we need.
    using Offset64 = UInt64;
    using Offsets64 = PaddedPODArray<Offset64>;

    // 32bit offsets for string
    using Offset = UInt32;
    using Offsets = PaddedPODArray<Offset>;

    /// Name of a Column. It is used in info messages.
    virtual std::string get_name() const = 0;

    // used to check the column data is valid or not.
    virtual void sanity_check() const {
        // do nothing by default, but some column may need to check
    }

    /** If column isn't constant, returns nullptr (or itself).
      * If column is constant, transforms constant to full column (if column type allows such transform) and return it.
      */
    virtual Ptr convert_to_full_column_if_const() const { return get_ptr(); }

    /** If in join. the StringColumn size may overflow uint32_t, we need convert to uint64_t to ColumnString64
  * The Column: ColumnString, ColumnNullable, ColumnArray, ColumnStruct need impl the code
  */
    virtual Ptr convert_column_if_overflow() { return get_ptr(); }

    /// If column isn't ColumnDictionary, return itself.
    /// If column is ColumnDictionary, transforms is to predicate column.
    virtual MutablePtr convert_to_predicate_column_if_dictionary() { return get_ptr(); }

    /// If column is ColumnDictionary, and is a range comparison predicate, convert dict encoding
    virtual void convert_dict_codes_if_necessary() {}

    /// If column is ColumnDictionary, and is a bloom filter predicate, generate_hash_values
    virtual void initialize_hash_values_for_runtime_filter() {}

    /// Creates empty column with the same type.
    virtual MutablePtr clone_empty() const { return clone_resized(0); }

    /// Creates column with the same type and specified size.
    /// If size is less current size, then data is cut.
    /// If size is greater, than default values are appended.
    virtual MutablePtr clone_resized(size_t s) const {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method clone_resized is not supported for " + get_name());
        return nullptr;
    }

    // shrink the end zeros for ColumnStr(also for who has it nested). so nest column will call it for all nested.
    // for non-str col, will reach here(do nothing). only ColumnStr will really shrink itself.
    virtual void shrink_padding_chars() {}

    // Only used in ColumnVariant to handle lifecycle of variant. Other columns would do nothing.
    virtual void finalize() {}

    // Only used on ColumnDictionary
    virtual void set_rowset_segment_id(std::pair<RowsetId, uint32_t> rowset_segment_id) {}

    virtual std::pair<RowsetId, uint32_t> get_rowset_segment_id() const { return {}; }

    /// Returns number of values in column.
    virtual size_t size() const = 0;

    /// There are no values in columns.
    bool empty() const { return size() == 0; }

    /// Returns value of n-th element in universal Field representation.
    /// Is used in rare cases, since creation of Field instance is expensive usually.
    virtual Field operator[](size_t n) const = 0;

    /// Like the previous one, but avoids extra copying if Field is in a container, for example.
    virtual void get(size_t n, Field& res) const = 0;

    /// If possible, returns pointer to memory chunk which contains n-th element (if it isn't possible, throws an exception)
    /// Is used to optimize some computations (in aggregation, for example).
    /// this function is used in ColumnString, ColumnFixedString, ColumnVector, not support in ColumnArray|ColumnMap...
    /// and should be pair with insert_data
    virtual StringRef get_data_at(size_t n) const {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method get_data_at is not supported for " + get_name());
    }

    virtual Int64 get_int(size_t /*n*/) const {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method get_int is not supported for " + get_name());
        return 0;
    }

    virtual bool is_null_at(size_t /*n*/) const { return false; }

    /** If column is numeric, return value of n-th element, casted to bool.
      * For NULL values of Nullable column returns false.
      * Otherwise throw an exception.
      */
    virtual bool get_bool(size_t /*n*/) const {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method get_bool is not supported for " + get_name());
        return false;
    }

    /// Removes all elements outside of specified range.
    /// Is used in LIMIT operation, for example.
    virtual Ptr cut(size_t start, size_t length) const final {
        MutablePtr res = clone_empty();
        res->insert_range_from(*this, start, length);
        return res;
    }

    /**
    * erase data from 'start' and length elements from the column.
    * @param length The number of elements to remove from the start position of the column
    * @throws doris::Exception with NOT_IMPLEMENTED_ERROR if the operation is not supported
    *         for this column type
    * eg: erase(3, 2) means remove the idx 3 and 4 elements (0-based)
    */
    virtual void erase(size_t start, size_t length) {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method erase is not supported for " + get_name());
    }

    /// cut or expand inplace. `this` would be moved, only the return value is avaliable.
    virtual Ptr shrink(size_t length) const final {
        // NOLINTBEGIN(performance-move-const-arg)
        MutablePtr res = std::move(*this).mutate();
        res->resize(length);
        // NOLINTEND(performance-move-const-arg)
        return res->get_ptr();
    }

    /// Appends new value at the end of column (column's size is increased by 1).
    /// Is used to transform raw strings to Blocks (for example, inside input format parsers)
    virtual void insert(const Field& x) = 0;

    /// Appends n-th element from other column with the same type.
    /// Is used in merge-sort and merges. It could be implemented in inherited classes more optimally than default implementation.
    virtual void insert_from(const IColumn& src, size_t n);

    /// Appends range of elements from other column with the same type.
    /// Could be used to concatenate columns.
    virtual void insert_range_from(const IColumn& src, size_t start, size_t length) = 0;

    /// Appends range of elements from other column with the same type.
    /// Do not need throw execption in ColumnString overflow uint32, only
    /// use in join
    virtual void insert_range_from_ignore_overflow(const IColumn& src, size_t start,
                                                   size_t length) {
        insert_range_from(src, start, length);
    }

    /// Appends one element from other column with the same type multiple times.
    virtual void insert_many_from(const IColumn& src, size_t position, size_t length) {
        for (size_t i = 0; i < length; ++i) {
            insert_from(src, position);
        }
    }

    // insert the data of target columns into self column according to positions
    // positions[i] means index of srcs whitch need to insert_from
    // the virtual function overhead of multiple calls to insert_from can be reduced to once
    virtual void insert_from_multi_column(const std::vector<const IColumn*>& srcs,
                                          const std::vector<size_t>& positions) = 0;

    /// Appends a batch elements from other column with the same type
    /// Also here should make sure indices_end is bigger than indices_begin
    /// indices_begin + indices_end represent the row indices of column src
    virtual void insert_indices_from(const IColumn& src, const uint32_t* indices_begin,
                                     const uint32_t* indices_end) = 0;

    /// Appends data located in specified memory chunk if it is possible (throws an exception if it cannot be implemented).
    /// used in ColumnString, ColumnFixedString, ColumnVector, not support in ColumnArray|ColumnMap...
    /// Is used to optimize some computations (in aggregation, for example).
    /// Parameter length could be ignored if column values have fixed size.
    /// All data will be inserted as single element
    virtual void insert_data(const char* pos, size_t length) {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method insert_data is not supported for " + get_name());
    }

    virtual void insert_many_fix_len_data(const char* pos, size_t num) {
        throw doris::Exception(
                ErrorCode::NOT_IMPLEMENTED_ERROR,
                "Method insert_many_fix_len_data is not supported for " + get_name());
    }

    // todo(zeno) Use dict_args temp object to cover all arguments
    virtual void insert_many_dict_data(const int32_t* data_array, size_t start_index,
                                       const StringRef* dict, size_t data_num,
                                       uint32_t dict_num = 0) {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method insert_many_dict_data is not supported for " + get_name());
    }

    /// Insert binary data into column from a continuous buffer, the implementation maybe copy all binary data
    /// in one single time.
    virtual void insert_many_continuous_binary_data(const char* data, const uint32_t* offsets,
                                                    const size_t num) {
        throw doris::Exception(
                ErrorCode::NOT_IMPLEMENTED_ERROR,
                "Method insert_many_continuous_binary_data is not supported for " + get_name());
    }

    virtual void insert_many_strings(const StringRef* strings, size_t num) {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method insert_many_strings is not supported for " + get_name());
    }

    virtual void insert_many_strings_overflow(const StringRef* strings, size_t num,
                                              size_t max_length) {
        throw doris::Exception(
                ErrorCode::NOT_IMPLEMENTED_ERROR,
                "Method insert_many_strings_overflow is not supported for " + get_name());
    }

    // Here `pos` points to the memory data type is the same as the data type of the column.
    // This function is used by `insert_keys_into_columns` in AggregationNode.
    virtual void insert_many_raw_data(const char* pos, size_t num) {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method insert_many_raw_data is not supported for " + get_name());
    }

    void insert_data_repeatedly(const char* pos, size_t length, size_t data_num) {
        for (size_t i = 0; i < data_num; ++i) {
            insert_data(pos, length);
        }
    }

    /// Appends "default value".
    /// Is used when there are need to increase column size, but inserting value doesn't make sense.
    /// For example, ColumnNullable(Nested) absolutely ignores values of nested column if it is marked as NULL.
    virtual void insert_default() = 0;

    /// Appends "default value" multiple times.
    virtual void insert_many_defaults(size_t length) {
        for (size_t i = 0; i < length; ++i) {
            insert_default();
        }
    }

    /** Removes last n elements.
      * Is used to support exception-safety of several operations.
      *  For example, sometimes insertion should be reverted if we catch an exception during operation processing.
      * If column has less than n elements or n == 0 - undefined behavior.
      */
    virtual void pop_back(size_t n) = 0;

    /** Serializes n-th element. Serialized element should be placed continuously inside Arena's memory.
      * Serialized value can be deserialized to reconstruct original object. Is used in aggregation.
      * The method is similar to get_data_at(), but can work when element's value cannot be mapped to existing continuous memory chunk,
      *  For example, to obtain unambiguous representation of Array of strings, strings data should be interleaved with their sizes.
      * Parameter begin should be used with Arena::alloc_continue.
      */
    virtual StringRef serialize_value_into_arena(size_t n, Arena& arena,
                                                 char const*& begin) const = 0;

    /// Deserializes a value that was serialized using IColumn::serialize_value_into_arena method.
    /// Returns pointer to the position after the read data.
    virtual const char* deserialize_and_insert_from_arena(const char* pos) = 0;

    virtual void serialize_vec(StringRef* keys, size_t num_rows) const {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method serialize_vec is not supported for " + get_name());
    }

    // This function deserializes group-by keys into column in the vectorized way.
    virtual void deserialize_vec(StringRef* keys, const size_t num_rows) {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method deserialize_vec is not supported for " + get_name());
    }
    /// The exact size to serialize the `row`-th row data in this column.
    virtual size_t serialize_size_at(size_t row) const {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Column {} should not be serialized.", get_name());
    }
    /// `serialize_impl` is the implementation to serialize a column into a continuous memory.
    virtual size_t serialize_impl(char* pos, const size_t row) const {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method serialize_impl is not supported for " + get_name());
    }
    /// `deserialize_impl` will deserialize data which is serialized by `serialize_impl`.
    virtual size_t deserialize_impl(const char* pos) {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method deserialize_impl is not supported for " + get_name());
    }

    /// Return the size of largest row.
    /// This is for calculating the memory size for vectorized serialization of aggregation keys.
    virtual size_t get_max_row_byte_size() const {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method get_max_row_byte_size is not supported for " + get_name());
        return 0;
    }

    /// TODO: SipHash is slower than city or xx hash, rethink we should have a new interface
    /// Update state of hash function with value of n-th element.
    /// On subsequent calls of this method for sequence of column values of arbitrary types,
    ///  passed bytes to hash must identify sequence of values unambiguously.
    virtual void update_hash_with_value(size_t n, SipHash& hash) const {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method update_hash_with_value is not supported for " + get_name());
    }

    /// Update state of hash function with value of n elements to avoid the virtual function call
    /// null_data to mark whether need to do hash compute, null_data == nullptr
    /// means all element need to do hash function, else only *null_data != 0 need to do hash func
    /// do xxHash here, faster than other sip hash
    virtual void update_hashes_with_value(uint64_t* __restrict hashes,
                                          const uint8_t* __restrict null_data = nullptr) const {
        throw doris::Exception(
                ErrorCode::NOT_IMPLEMENTED_ERROR,
                "Method update_hashes_with_value is not supported for " + get_name());
    }

    // use range for one hash value to avoid virtual function call in loop
    virtual void update_xxHash_with_value(size_t start, size_t end, uint64_t& hash,
                                          const uint8_t* __restrict null_data) const {
        throw doris::Exception(
                ErrorCode::NOT_IMPLEMENTED_ERROR,
                "Method update_xxHash_with_value is not supported for " + get_name());
    }

    /// Update state of crc32 hash function with value of n elements to avoid the virtual function call
    /// null_data to mark whether need to do hash compute, null_data == nullptr
    /// means all element need to do hash function, else only *null_data != 0 need to do hash func
    virtual void update_crcs_with_value(uint32_t* __restrict hash, PrimitiveType type,
                                        uint32_t rows, uint32_t offset = 0,
                                        const uint8_t* __restrict null_data = nullptr) const {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method update_crcs_with_value is not supported for " + get_name());
    }

    // use range for one hash value to avoid virtual function call in loop
    virtual void update_crc_with_value(size_t start, size_t end, uint32_t& hash,
                                       const uint8_t* __restrict null_data) const {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method update_crc_with_value is not supported for " + get_name());
    }

    /** Removes elements that don't match the filter.
      * Is used in WHERE and HAVING operations.
      * If result_size_hint > 0, then makes advance reserve(result_size_hint) for the result column;
      *  if 0, then don't makes reserve(),
      *  otherwise (i.e. < 0), makes reserve() using size of source column.
      */
    using Filter = PaddedPODArray<UInt8>;
    virtual Ptr filter(const Filter& filt, ssize_t result_size_hint) const = 0;

    /// This function will modify the original table.
    /// Return rows number after filtered.
    virtual size_t filter(const Filter& filter) = 0;

    /**
     *  used by lazy materialization to filter column by selected rowids
     *  Q: Why use IColumn* as args type instead of MutablePtr or ImmutablePtr ?
     *  A: If use MutablePtr/ImmutablePtr as col_ptr's type, which means there could be many 
     *  convert(convert MutablePtr to ImmutablePtr or convert ImmutablePtr to MutablePtr)
     *  happends in filter_by_selector because of mem-reuse logic or ColumnNullable, I think this is meaningless;
     *  So using raw ptr directly here.
     *  NOTICE: only column_nullable and predict_column, column_dictionary now support filter_by_selector
     *  // nullable -> predict_column
     *  // string (dictionary) -> column_dictionary
     */
    virtual Status filter_by_selector(const uint16_t* sel, size_t sel_size, IColumn* col_ptr) {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method filter_by_selector is not supported for {}, only "
                               "column_nullable, column_dictionary and predict_column support",
                               get_name());
    }

    /// Permutes elements using specified permutation. Is used in sortings.
    /// limit - if it isn't 0, puts only first limit elements in the result.
    using Permutation = PaddedPODArray<size_t>;
    virtual MutablePtr permute(const Permutation& perm, size_t limit) const = 0;

    /** Compares (*this)[n] and rhs[m]. Column rhs should have the same type.
      * Returns negative number, 0, or positive number (*this)[n] is less, equal, greater than rhs[m] respectively.
      * Is used in sortings.
      *
      * If one of element's value is NaN or NULLs, then:
      * - if nan_direction_hint == -1, NaN and NULLs are considered as least than everything other;
      * - if nan_direction_hint ==  1, NaN and NULLs are considered as greatest than everything other.
      * For example, if nan_direction_hint == -1 is used by descending sorting, NaNs will be at the end.
      *
      * For non Nullable and non floating point types, nan_direction_hint is ignored.
      * For array/map/struct types, we compare with nested column element and offsets size
      */
    virtual int compare_at(size_t n, size_t m, const IColumn& rhs, int nan_direction_hint) const {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR, "compare_at for " + get_name());
    }

    /**
     * To compare all rows in this column with another row (with row_id = rhs_row_id in column rhs)
     * @param nan_direction_hint and direction indicates the ordering.
     * @param cmp_res if we already has a comparison result for row i, e.g. cmp_res[i] = 1, we can skip row i
     * @param filter this stores comparison results for all rows. filter[i] = 1 means row i is less than row rhs_row_id in rhs
     */
    virtual void compare_internal(size_t rhs_row_id, const IColumn& rhs, int nan_direction_hint,
                                  int direction, std::vector<uint8_t>& cmp_res,
                                  uint8_t* __restrict filter) const;

    /** Returns a permutation that sorts elements of this column,
      *  i.e. perm[i]-th element of source column should be i-th element of sorted column.
      * reverse - true: descending order, false: ascending order.
      * limit - if isn't 0, then only first limit elements of the result column could be sorted.
      * nan_direction_hint - see above.
      */
    virtual void get_permutation(bool reverse, size_t limit, int nan_direction_hint,
                                 Permutation& res) const {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "get_permutation for " + get_name());
    }

    /** Copies each element according offsets parameter.
      * (i-th element should be copied offsets[i] - offsets[i - 1] times.)
      * It is necessary in ARRAY JOIN operation.
      */
    virtual Ptr replicate(const Offsets& offsets) const = 0;

    /** Split column to smaller columns. Each value goes to column index, selected by corresponding element of 'selector'.
      * Selector must contain values from 0 to num_columns - 1.
      * For default implementation, see column_impl.h
      */
    using ColumnIndex = UInt64;
    using Selector = PaddedPODArray<ColumnIndex>;

    // The append_data_by_selector function requires the column to implement the insert_from function.
    // In fact, this function is just calling insert_from but without the overhead of a virtual function.

    virtual void append_data_by_selector(MutablePtr& res, const Selector& selector) const = 0;

    // Here, begin and end represent the range of the Selector.
    virtual void append_data_by_selector(MutablePtr& res, const Selector& selector, size_t begin,
                                         size_t end) const = 0;

    /// Insert data from several other columns according to source mask (used in vertical merge).
    /// For now it is a helper to de-virtualize calls to insert*() functions inside gather loop
    /// (descendants should call gatherer_stream.gather(*this) to implement this function.)
    /// TODO: interface decoupled from ColumnGathererStream that allows non-generic specializations.
    //    virtual void gather(ColumnGathererStream & gatherer_stream) = 0;

    /// Reserves memory for specified amount of elements. If reservation isn't possible, does nothing.
    /// It affects performance only (not correctness).
    virtual void reserve(size_t /*n*/) {}

    /// Resize memory for specified amount of elements. If reservation isn't possible, does nothing.
    /// It affects performance only (not correctness).
    /// Note. resize means not only change column self but also sub-columns if have.
    virtual void resize(size_t /*n*/) {}

    /// Size of column data in memory (may be approximate) - for profiling. Zero, if could not be determined.
    virtual size_t byte_size() const = 0;

    /**
    * @brief Checks whether the current column has enough capacity to accommodate the given source column.
    * 
    * This pure virtual function should be implemented by derived classes to determine whether the 
    * current column has enough reserved memory to hold the data of the specified `src` column.
    * 
    * @param src The source column whose data needs to be checked for fitting into the current column.
    * @return true if the current column has enough capacity to hold the `src` data, false otherwise.
    */
    virtual bool has_enough_capacity(const IColumn& src) const = 0;

    /// Size of memory, allocated for column.
    /// This is greater or equals to byte_size due to memory reservation in containers.
    /// Zero, if could not be determined.
    virtual size_t allocated_bytes() const = 0;

    /// If the column contains subcolumns (such as Array, Nullable, etc), do callback on them.
    /// Shallow: doesn't do recursive calls; don't do call for itself.
    using ColumnCallback = std::function<void(WrappedPtr&)>;
    using ImutableColumnCallback = std::function<void(const IColumn&)>;
    virtual void for_each_subcolumn(ColumnCallback) {}

    /// Columns have equal structure.
    /// If true - you can use "compare_at", "insert_from", etc. methods.
    virtual bool structure_equals(const IColumn&) const {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Method structure_equals is not supported for " + get_name());
        return false;
    }

    MutablePtr mutate() const&& {
        MutablePtr res = shallow_mutate();
        res->for_each_subcolumn(
                [](WrappedPtr& subcolumn) { subcolumn = std::move(*subcolumn).mutate(); });
        return res;
    }

    static MutablePtr mutate(Ptr ptr) {
        MutablePtr res = ptr->shallow_mutate(); /// Now use_count is 2.
        ptr.reset();                            /// Reset use_count to 1.
        res->for_each_subcolumn(
                [](WrappedPtr& subcolumn) { subcolumn = std::move(*subcolumn).mutate(); });
        return res;
    }

    /** Some columns can contain another columns inside.
      * So, we have a tree of columns. But not all combinations are possible.
      * There are the following rules:
      *
      * ColumnConst may be only at top. It cannot be inside any column.
      * ColumnNullable can contain only simple columns.
      */

    /// Various properties on behaviour of column type.

    /// It's true for ColumnNullable only.
    virtual bool is_nullable() const { return false; }
    /// It's true for ColumnNullable, can be true or false for ColumnConst, etc.
    virtual bool is_concrete_nullable() const { return false; }

    // true if column has null element
    virtual bool has_null() const { return false; }

    // true if column has null element [0,size)
    virtual bool has_null(size_t size) const { return false; }

    virtual bool is_exclusive() const { return use_count() == 1; }

    /// Clear data of column, just like vector clear
    virtual void clear() = 0;

    /** Memory layout properties.
      *
      * Each value of a column can be placed in memory contiguously or not.
      *
      * Example: simple columns like UInt64 or FixedString store their values contiguously in single memory buffer.
      *
      * Example: Tuple store values of each component in separate subcolumn, so the values of Tuples with at least two components are not contiguous.
      * Another example is Nullable. Each value have null flag, that is stored separately, so the value is not contiguous in memory.
      *
      * There are some important cases, when values are not stored contiguously, but for each value, you can get contiguous memory segment,
      *  that will unambiguously identify the value. In this case, methods get_data_at and insert_data are implemented.
      * Example: String column: bytes of strings are stored concatenated in one memory buffer
      *  and offsets to that buffer are stored in another buffer. The same is for Array of fixed-size contiguous elements.
      *
      * To avoid confusion between these cases, we don't have isContiguous method.
      */

    virtual StringRef get_raw_data() const {
        throw doris::Exception(ErrorCode::NOT_IMPLEMENTED_ERROR,
                               "Column {} is not a contiguous block of memory", get_name());
        return StringRef {};
    }

    /// Returns ratio of values in column, that are equal to default value of column.
    /// Checks only @sample_ratio ratio of rows.
    virtual double get_ratio_of_default_rows(double sample_ratio = 1.0) const { return 0.0; }

    // Column is ColumnString/ColumnArray/ColumnMap or other variable length column at every row
    virtual bool is_variable_length() const { return false; }

    virtual bool is_column_string() const { return false; }

    virtual bool is_column_string64() const { return false; }

    virtual bool is_column_dictionary() const { return false; }

    /// If the only value column can contain is NULL.
    virtual bool only_null() const { return false; }

    /**
     * ColumnSorter is used to sort each columns in a Block. In this sorting pattern, sorting a
     * column will produce a list of EqualRange which has the same elements respectively. And for
     * next column in this block, we only need to sort rows in those `range`.
     *
     * Besides, we do not materialize sorted data eagerly. Instead, the intermediate sorting results
     * are represendted by permutation and data will be materialized after all of columns are sorted.
     *
     * @sorter: ColumnSorter is used to do sorting.
     * @flags : indicates if current item equals to the previous one.
     * @perms : permutation after sorting
     * @range : EqualRange which has the same elements respectively.
     * @last_column : indicates if this column is the last in this block.
     */
    virtual void sort_column(const ColumnSorter* sorter, EqualFlags& flags,
                             IColumn::Permutation& perms, EqualRange& range,
                             bool last_column) const;

    virtual ~IColumn() = default;
    IColumn() = default;
    IColumn(const IColumn&) = default;

    /** Print column name, size, and recursively print all subcolumns.
      */
    String dump_structure() const;

    // only used in agg value replace for column which is not variable length, eg.BlockReader::_copy_value_data
    // usage: self_column.replace_column_data(other_column, other_column's row index, self_column's row index)
    virtual void replace_column_data(const IColumn&, size_t row, size_t self_row = 0) = 0;
    // replace data to default value if null, used to avoid null data output decimal check failure
    // usage: nested_column.replace_column_null_data(nested_null_map.data())
    // only wrok on column_vector and column column decimal, there will be no behavior when other columns type call this method
    virtual void replace_column_null_data(const uint8_t* __restrict null_map) {}

protected:
    template <typename Derived>
    void append_data_by_selector_impl(MutablePtr& res, const Selector& selector) const {
        append_data_by_selector_impl<Derived>(res, selector, 0, selector.size());
    }
    template <typename Derived>
    void append_data_by_selector_impl(MutablePtr& res, const Selector& selector, size_t begin,
                                      size_t end) const {
        size_t num_rows = size();

        if (num_rows < selector.size()) {
            throw doris::Exception(ErrorCode::INTERNAL_ERROR,
                                   "Size of selector: {} is larger than size of column: {}",
                                   selector.size(), num_rows);
        }
        DCHECK_GE(end, begin);
        DCHECK_LE(end, selector.size());
        // here wants insert some value from this column, and the nums is (end - begin)
        // and many be this column num_rows is 4096, but only need insert num is (1 - 0) = 1
        // so can't call res->reserve(num_rows), it's will be too mush waste memory
        res->reserve(res->size() + (end - begin));

        for (size_t i = begin; i < end; ++i) {
            static_cast<Derived&>(*res).insert_from(*this, selector[i]);
        }
    }
    template <typename Derived>
    void insert_from_multi_column_impl(const std::vector<const IColumn*>& srcs,
                                       const std::vector<size_t>& positions) {
        reserve(size() + srcs.size());
        for (size_t i = 0; i < srcs.size(); ++i) {
            static_cast<Derived&>(*this).insert_from(*srcs[i], positions[i]);
        }
    }
};

using ColumnPtr = IColumn::Ptr;
using MutableColumnPtr = IColumn::MutablePtr;
using Columns = std::vector<ColumnPtr>;
using MutableColumns = std::vector<MutableColumnPtr>;
using ColumnPtrs = std::vector<ColumnPtr>;
using ColumnRawPtrs = std::vector<const IColumn*>;

template <typename... Args>
struct IsMutableColumns;

template <typename Arg, typename... Args>
struct IsMutableColumns<Arg, Args...> {
    static const bool value =
            std::is_assignable<MutableColumnPtr&&, Arg>::value && IsMutableColumns<Args...>::value;
};

template <>
struct IsMutableColumns<> {
    static const bool value = true;
};

// prefer assert_cast than check_and_get
template <typename Type>
const Type* check_and_get_column(const IColumn& column) {
    return typeid_cast<const Type*>(&column);
}

template <typename Type>
const Type* check_and_get_column(const IColumn* column) {
    return typeid_cast<const Type*>(column);
}

template <typename Type>
bool is_column(const IColumn& column) {
    return check_and_get_column<Type>(&column);
}

template <typename Type>
bool is_column(const IColumn* column) {
    return check_and_get_column<Type>(column);
}

// check_and_get_column_ptr is used to return a ColumnPtr of a specific column type,
// which will hold ownership. This prevents the occurrence of dangling pointers due to certain situations.
template <typename ColumnType>
ColumnType::Ptr check_and_get_column_ptr(const ColumnPtr& column) {
    const ColumnType* raw_type_ptr = check_and_get_column<ColumnType>(column.get());
    if (raw_type_ptr == nullptr) {
        return nullptr;
    }
    return typename ColumnType::Ptr(const_cast<ColumnType*>(raw_type_ptr));
}

/// True if column's an ColumnConst instance. It's just a syntax sugar for type check.
bool is_column_const(const IColumn& column);

/// True if column's an ColumnNullable instance. It's just a syntax sugar for type check.
bool is_column_nullable(const IColumn& column);
} // namespace doris::vectorized

// Wrap `ColumnPtr` because `ColumnPtr` can't be used in forward declaration.
namespace doris {
struct ColumnPtrWrapper {
    vectorized::ColumnPtr column_ptr;

    ColumnPtrWrapper(vectorized::ColumnPtr col) : column_ptr(std::move(col)) {}
};
} // namespace doris
