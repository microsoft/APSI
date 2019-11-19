// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <seal/context.h>
#include <seal/plaintext.h>
#include <seal/batchencoder.h>
#include "apsi/ffield/ffield_array.h"

namespace apsi
{
    class FFieldFastBatchEncoder
    {
    public:
        FFieldFastBatchEncoder(
            std::shared_ptr<seal::SEALContext> context, FField field);

        inline seal::SmallModulus ch() const
        {
            return field_.ch_;
        }

        inline u64 d() const
        {
            return field_.d_;
        }

        inline u64 n() const
        {
            return n_;
        }

        inline u64 m() const
        {
            return m_;
        }

        inline int log_n() const
        {
            return log_n_;
        }

        inline u64 slot_count() const
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
        const u64 n_;
        const int log_n_;
        const u64 m_;
        const u64 slot_count_;
    }; // class FFieldFastBatchEncoder
} // namespace apsi
