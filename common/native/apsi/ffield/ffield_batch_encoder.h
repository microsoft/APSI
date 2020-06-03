// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <seal/batchencoder.h>
#include <seal/context.h>
#include <seal/plaintext.h>
#include "apsi/ffield/ffield_array.h"

namespace apsi
{// TODO: Use size_t for most of the private data members.
    class FFieldBatchEncoder
    {
    public:
        FFieldBatchEncoder(std::shared_ptr<seal::SEALContext> context, FField field);

        inline seal::Modulus characteristic() const
        {
            return field_.characteristic_;
        }

        inline std::uint64_t degree() const
        {
            return field_.degree_;
        }

        inline std::size_t n() const
        {
            return n_;
        }

        inline std::uint64_t m() const
        {
            return m_;
        }

        inline int log_n() const
        {
            return log_n_;
        }

        inline std::uint64_t slot_count() const
        {
            return slot_count_;
        }

        inline const FField field() const
        {
            return field_;
        }

        inline FFieldArray create_array() const
        {
            return { static_cast<size_t>(slot_count_), field_ };
        }

        void compose(const FFieldArray &values, seal::Plaintext &destination) const;
        void decompose(const seal::Plaintext &plain, FFieldArray &destination) const;

    private:
        std::unique_ptr<seal::BatchEncoder> encoder_;
        FField field_;
        const std::size_t n_;
        const int log_n_;
        const std::uint64_t m_;
        const std::uint64_t slot_count_;
    }; // class FFieldBatchEncoder
} // namespace apsi
