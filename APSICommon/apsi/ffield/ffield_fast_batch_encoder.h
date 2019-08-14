// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#pragma once

// STD
#include <memory>
#include <vector>

// APSI 
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_elt.h"
#include "apsi/ffield/ffield_array.h"

// SEAL
#include <seal/context.h>
#include <seal/plaintext.h>
#include <seal/batchencoder.h>

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

        inline std::uint64_t d() const
        {
            return field_.d_;
        }

        inline std::uint64_t n() const
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
            return { slot_count_, field_ };
        }

        void compose(const FFieldArray &values, seal::Plaintext &destination) const;
        void decompose(const seal::Plaintext &plain, FFieldArray &destination) const;

    private:
        std::unique_ptr<seal::BatchEncoder> encoder_;
        FField field_;
        const std::uint64_t n_;
        const int log_n_;
        const std::uint64_t m_;
        const std::uint64_t slot_count_;
    };
}
