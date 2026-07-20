// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <cstring>
#include <string>
#include <utility>

// APSI
#include "apsi/item.h"

namespace apsi::receiver {
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
        Returns a const reference to the underlying byte buffer.
        */
        [[nodiscard]] const Label &value() const noexcept
        {
            return label_;
        }

        /**
        Returns a string containing the label data.
        */
        [[nodiscard]] std::string to_string() const
        {
            if (!has_data()) {
                return {};
            }
            std::string result(label_.size(), '\0');
            std::memcpy(result.data(), label_.data(), label_.size());
            return result;
        }

        /**
        Returns whether the LabelData object holds any any data.
        */
        [[nodiscard]] bool has_data() const noexcept
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
} // namespace apsi::receiver
