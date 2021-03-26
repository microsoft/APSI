// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

// APSI
#include "apsi/item.h"

// GSL
#include "gsl/span"

namespace apsi {
    namespace receiver {
        /**
        A LabelData object contains the data for an arbitrary size label returned from a query.
        Member functions allow the label to be read as a string or as an array of (standard layout)
        objects of a desired type. There is usually no reason for a normal user to create LabelData
        objects. These are used as a part of a MatchRecord object and created by the query response
        processing API.
        */
        class LabelData {
        public:
            /**
            Creates an empty LabelData object.
            */
            LabelData() = default;

            /**
            Creates a LabelData object holding a given bit string.
            */
            LabelData(Label label) : label_(std::move(label))
            {}

            /**
            Sets the current label data to a given bit string.
            */
            void set(Label label)
            {
                label_ = std::move(label);
            }

            /**
            Returns a span of a desired (standard layout) type to the label data.
            */
            template <typename T, typename = std::enable_if_t<std::is_standard_layout<T>::value>>
            gsl::span<std::add_const_t<T>> get_as() const
            {
                if (!has_data()) {
                    return {};
                }
                std::size_t count = label_.size() / sizeof(T);
                return { reinterpret_cast<std::add_const_t<T> *>(label_.data()), count };
            }

            /**
            Returns a string containing the label data.
            */
            template <typename CharT = char>
            std::basic_string<CharT> to_string() const
            {
                if (!has_data()) {
                    return {};
                }
                auto string_data = get_as<CharT>();
                return { string_data.data(), string_data.size() };
            }

            /**
            Returns whether the LabelData object holds any any data.
            */
            bool has_data() const noexcept
            {
                return !label_.empty();
            }

            /**
            Returns whether the LabelData object holds any any data.
            */
            explicit operator bool() const noexcept
            {
                return has_data();
            }

        private:
            Label label_;
        };

        /**
        A MatchRecord object is a simple structure holding two values: a bool indicating a match
        found in a query and a LabelData object holding the corresponding label data, if such was
        retrieved. There is usually no reason for a normal user to create MatchRecord objects. These
        are created by the query response processing API.
        */
        class MatchRecord {
        public:
            /**
            Indicates whether this MatchRecord signals a match found in a query.
            */
            bool found = false;

            /**
            Holds the label data for the match indicated by this MatchRecord, if the sender returned
            any.
            */
            LabelData label;

            /**
            Returns whether this MatchRecord signals a match found in a query.
            */
            explicit operator bool() const noexcept
            {
                return found;
            }
        };
    } // namespace receiver
} // namespace apsi
