// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <algorithm>
#include <cstddef>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <utility>
#include <unordered_set>
#include <unordered_map>

// SEAL
#include "seal/util/defines.h"
#include "seal/dynarray.h"
#include "seal/randomgen.h"
#include "seal/memorymanager.h"

// APSI
#include "apsi/oprf/oprf_common.h"
#include "apsi/util/db_encoding.h"

namespace apsi
{
    namespace oprf
    {
        class OPRFKey
        {
        public:
            OPRFKey(std::shared_ptr<seal::UniformRandomGeneratorFactory> random_gen = nullptr)
                : random_(std::move(random_gen))
            {
                create();
            }

            OPRFKey(const OPRFKey &copy) : OPRFKey(copy.random_)
            {
                oprf_key_ = copy.oprf_key_;
            }

            OPRFKey(OPRFKey &&copy) = default;

            inline void create()
            {
                // Create a random key
                ECPoint::scalar_span_type out( oprf_key_.begin(), oprf_key_size );
                ECPoint::make_random_nonzero_scalar(
                    out, random_ ? random_->create() : nullptr);
            }

            void save(std::ostream &stream) const;

            void load(std::istream &stream);

            inline void save(oprf_key_span_type oprf_key) const
            {
                std::copy_n(oprf_key_.cbegin(), oprf_key_size, oprf_key.data());
            }

            inline void load(oprf_key_span_const_type oprf_key)
            {
                std::copy_n(oprf_key.data(), oprf_key_size, oprf_key_.begin());
            }

            inline void clear()
            {
                oprf_key_ = seal::DynArray<unsigned char>(
                    oprf_key_size, seal::MemoryManager::GetPool(seal::mm_prof_opt::mm_force_new, true));
            }

            inline oprf_key_span_const_type key_span() const noexcept
            {
                oprf_key_span_const_type result( oprf_key_.cbegin(), oprf_key_size );
                return result;
            }

        private:
            std::shared_ptr<seal::UniformRandomGeneratorFactory> random_{ nullptr };

            seal::DynArray<unsigned char> oprf_key_{ oprf_key_size,
                                                     seal::MemoryManager::GetPool(seal::mm_prof_opt::mm_force_new, true) };
        }; // class OPRFKey

        class OPRFSender
        {
        public:
            OPRFSender() = delete;

            static void ProcessQueries(
                gsl::span<const seal::seal_byte> oprf_queries, const OPRFKey &oprf_key,
                gsl::span<seal::seal_byte> oprf_responses);

            static std::unordered_set<oprf_hash_type> ComputeHashes(
                const std::unordered_set<oprf_item_type> &oprf_items,
                const OPRFKey &oprf_key);

            static std::unordered_map<oprf_hash_type, util::FullWidthLabel> ComputeHashes(
                const std::unordered_map<oprf_item_type, util::FullWidthLabel> &oprf_item_labels,
                const OPRFKey &oprf_key);
        }; // class OPRFSender
    }      // namespace oprf
} // namespace apsi
