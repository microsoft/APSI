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

// SEAL
#include "seal/util/defines.h"
#include "seal/intarray.h"
#include "seal/randomgen.h"
#include "seal/memorymanager.h"

// APSI
#include "apsi/oprf/oprf_common.h"

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
                ECPoint::make_random_nonzero_scalar(
                    { oprf_key_.begin(), oprf_key_size }, random_ ? random_->create() : nullptr);
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
                oprf_key_ = seal::IntArray<unsigned char>(
                    oprf_key_size, seal::MemoryManager::GetPool(seal::mm_prof_opt::FORCE_NEW, true));
            }

            inline oprf_key_span_const_type key_span() const noexcept
            {
                return { oprf_key_.cbegin(), oprf_key_size };
            }

        private:
            std::shared_ptr<seal::UniformRandomGeneratorFactory> random_{ nullptr };

            seal::IntArray<unsigned char> oprf_key_{ oprf_key_size,
                                                     seal::MemoryManager::GetPool(seal::mm_prof_opt::FORCE_NEW, true) };
        }; // class OPRFKey

        class OPRFSender
        {
        public:
            OPRFSender() = delete;

            static void ProcessQueries(
                gsl::span<const seal::seal_byte> oprf_queries, const OPRFKey &oprf_key,
                gsl::span<seal::seal_byte> oprf_responses);

            static void ComputeHashes(
                gsl::span<const oprf_item_type> oprf_items, const OPRFKey &oprf_key,
                gsl::span<oprf_hash_type> oprf_hashes, std::size_t thread_count = 0);

        private:
            static void compute_hashes_worker(
                std::pair<std::size_t, std::size_t> partition,
                gsl::span<const oprf_item_type> oprf_items, const OPRFKey &oprf_key,
                gsl::span<oprf_hash_type> oprf_hashes);
        }; // class OPRFSender
    }      // namespace oprf
} // namespace apsi
