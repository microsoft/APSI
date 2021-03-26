// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

// APSI
#include "apsi/item.h"
#include "apsi/util/stopwatch.h"

// SEAL
#include "seal/util/defines.h"

// Kuku
#include "kuku/common.h"

// GSL
#include "gsl/span"

namespace apsi {
    namespace util {
        /**
        Convert the given input to digits.
        */
        std::vector<std::uint64_t> conversion_to_digits(
            const std::uint64_t input, const std::uint64_t base);

        /**
        Split the given string.
        */
        void split(const std::string &s, const char delim, std::vector<std::string> &elems);

        /**
        Split the given string.
        */
        std::vector<std::string> split(const std::string &s, const char delim);

        /**
        Round up the given value using the given step.
        */
        template <typename T>
        typename std::enable_if<std::is_pod<T>::value, T>::type round_up_to(
            const T val, const T step)
        {
            return ((val + step - 1) / step) * step;
        }

        /**
        Partitions count many points into partition_count many disjoint parts as equally as
        possible. If count or partition_count is zero, the result is empty. If partition_count
        if larger than count, only count many partitions will be returned, each of size 1.
        The return value is a vector of pairs of points, where each pair contains the start
        and one-past-end points for the partition.
        */
        template <typename T>
        std::vector<std::pair<T, T>> partition_evenly(T count, T partition_count)
        {
            if (count == 0 || partition_count == 0) {
                return {};
            }

            partition_count = std::min(count, partition_count);

            std::vector<std::pair<T, T>> partitions;
            partitions.reserve(std::min(count, partition_count) + T(1));

            // May be zero
            T per_partition = count / partition_count;
            T extras_needed = count - per_partition * partition_count;

            T partition_start = 0;
            for (T i = 0; i < partition_count; i++) {
                T partition_end = partition_start + per_partition;
                if (extras_needed) {
                    partition_end++;
                    extras_needed--;
                }
                partitions.push_back({ partition_start, partition_end });
                partition_start = partition_end;
            }

            return partitions;
        }

        /**
        This function reads a given number of bytes from a stream in small parts, writing the result
        to the end of a given vector. This can avoid issues where a large number of bytes is
        requested incorrectly to be read from a stream, causing a larger than necessary memory
        allocation.
        */
        void read_from_stream(
            std::istream &in, std::uint32_t byte_count, std::vector<seal::seal_byte> &destination);

        /**
        This function reads a size-prefixed number of bytes from a stream and returns the result in
        a vector.
        */
        std::vector<seal::seal_byte> read_from_stream(std::istream &in);

        /**
        Casts std::unique_ptr<T> to std::unique_ptr<S>, when S* can be cast to T*. Returns nullptr
        if the cast fails.
        */
        template <typename To, typename From>
        std::unique_ptr<To> unique_ptr_cast(std::unique_ptr<From> &from)
        {
            auto ptr = dynamic_cast<To *>(from.get());
            if (!ptr) {
                return nullptr;
            }
            return std::unique_ptr<To>{ static_cast<To *>(from.release()) };
        }

        /**
        Casts std::unique_ptr<T> to std::unique_ptr<S>, when S* can be cast to T*. Returns nullptr
        if the cast fails.
        */
        template <typename To, typename From>
        std::unique_ptr<To> unique_ptr_cast(std::unique_ptr<From> &&from)
        {
            auto ptr = dynamic_cast<To *>(from.get());
            if (!ptr) {
                return nullptr;
            }
            return std::unique_ptr<To>{ static_cast<To *>(from.release()) };
        }

        /**
        Writes a vector into an std::ostream as [a, b, c, ..., z].
        */
        template <typename T, std::size_t Extent, typename ToString>
        std::string to_string(gsl::span<T, Extent> values, ToString to_string_fun)
        {
            if (values.empty()) {
                return "[ ]";
            }

            std::stringstream ss;
            ss << "[";
            for (std::size_t i = 0; i < values.size() - 1; i++) {
                ss << to_string_fun(values[i]) << ", ";
            }
            ss << to_string_fun(values.back()) << "]";

            return ss.str();
        }

        /**
        Writes a vector into an std::ostream as [a, b, c, ..., z].
        */
        template <typename T, std::size_t Extent>
        std::string to_string(gsl::span<T, Extent> values)
        {
            return to_string(values, [](T &t) -> T & { return t; });
        }

        /**
        Writes a vector into an std::ostream as [a, b, c, ..., z].
        */
        template <typename T, typename ToString>
        std::string to_string(const std::vector<T> &values, ToString to_string_fun)
        {
            return to_string(gsl::span<const T>(values), to_string_fun);
        }

        /**
        Writes a vector into an std::ostream as [a, b, c, ..., z].
        */
        template <typename T>
        std::string to_string(const std::vector<T> &values)
        {
            return to_string(gsl::span<const T>(values));
        }

        /**
        Writes a set into an std::ostream as {a, b, c, ..., z}.
        */
        template <typename T, typename ToString>
        std::string to_string(const std::set<T> &values, ToString to_string_fun)
        {
            if (values.empty()) {
                return "{ }";
            }

            std::stringstream ss;
            ss << "{";
            auto values_last = std::next(values.cbegin(), values.size() - 1);
            for (auto it = values.cbegin(); it != values_last; it++) {
                ss << to_string_fun(*it) << ", ";
            }
            ss << to_string_fun(*values_last) << "}";

            return ss.str();
        }

        /**
        Writes a set into an std::ostream as {a, b, c, ..., z}.
        */
        template <typename T>
        std::string to_string(const std::set<T> &values)
        {
            return to_string(values, [](const T &t) -> const T & { return t; });
        }

        /**
        Returns the next power of 2 for the given number
        */
        std::uint64_t next_power_of_2(std::uint64_t v);

        /**
        Computes the XOR of two byte buffers.
        */
        void xor_buffers(unsigned char *buf1, const unsigned char *buf2, std::size_t count);
    } // namespace util
} // namespace apsi
