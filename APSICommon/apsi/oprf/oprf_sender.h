// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <algorithm>
#include <iostream>
#include <memory>

// SEAL
#include <seal/memorymanager.h>
#include <seal/intarray.h>

// Microsoft GSL
#include <gsl/span>

// APSI
#include "apsi/oprf/oprf_common.h"

namespace apsi
{
    namespace oprf 
    {
        class OPRFKey
        {
        public:
            OPRFKey()
            {
            }

            OPRFKey(std::shared_ptr<seal::UniformRandomGeneratorFactory> random_gen)
            {
                // Create a random key
                ECPoint::make_random_nonzero_scalar(
                    { oprf_key_.begin(), oprf_key_size },
                    random_gen ? random_gen->create() : nullptr);
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

            inline void reset()
            {
                oprf_key_ = seal::IntArray<unsigned char>(
                    oprf_key_size,
                    seal::MemoryManager::GetPool(seal::mm_prof_opt::FORCE_NEW));
            }

            inline oprf_key_span_const_type key_span() const noexcept
            {
                return { oprf_key_.cbegin(), oprf_key_size };
            }

        private:
            seal::IntArray<unsigned char> oprf_key_{
                oprf_key_size,
                seal::MemoryManager::GetPool(seal::mm_prof_opt::FORCE_NEW, true) };
        };

        class OPRFSender
        {
        public:
            OPRFSender() = delete;

            static void ProcessQueries(
                gsl::span<const unsigned char, gsl::dynamic_extent> oprf_queries,
                const OPRFKey &oprf_key,
                gsl::span<unsigned char, gsl::dynamic_extent> oprf_responses);

            static void ComputeHashes(
                gsl::span<const oprf_item_type, gsl::dynamic_extent> oprf_items,
                const OPRFKey &oprf_key,
                gsl::span<oprf_hash_type, gsl::dynamic_extent> oprf_hashes);

        private:
        };
    }
}
