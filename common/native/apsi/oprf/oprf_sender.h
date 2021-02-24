// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <utility>
#include <unordered_set>
#include <unordered_map>
#include <vector>

// SEAL
#include "seal/util/defines.h"
#include "seal/dynarray.h"
#include "seal/memorymanager.h"
#include "seal/randomgen.h"

// APSI
#include "apsi/oprf/oprf_common.h"
#include "apsi/util/db_encoding.h"

// GSL
#include "gsl/span"

namespace apsi
{
    namespace oprf
    {
        class OPRFKey
        {
        public:
            OPRFKey(std::shared_ptr<seal::UniformRandomGeneratorFactory> random_gen = nullptr)
            {
                random_ = random_gen ? std::move(random_gen) : seal::UniformRandomGeneratorFactory::DefaultFactory();
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
                    oprf_key_span_type{ oprf_key_.begin(), oprf_key_size }, random_->create());
            }

            void save(std::ostream &stream) const;

            void load(std::istream &stream);

            inline void save(oprf_key_span_type oprf_key) const;

            inline void load(oprf_key_span_const_type oprf_key);

            inline void clear()
            {
                oprf_key_ = seal::DynArray<unsigned char>(
                    oprf_key_size, seal::MemoryManager::GetPool(seal::mm_prof_opt::mm_force_new, true));
            }

            inline oprf_key_span_const_type key_span() const noexcept
            {
                return oprf_key_span_const_type{ oprf_key_.cbegin(), oprf_key_size };
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

            static std::vector<seal::seal_byte> ProcessQueries(
                gsl::span<const seal::seal_byte> oprf_queries, const OPRFKey &oprf_key);

            static std::vector<oprf_hash_type> ComputeHashes(
                const gsl::span<const oprf_item_type> &oprf_items,
                const OPRFKey &oprf_key, std::size_t threads = 0);

            static std::vector<std::pair<oprf_hash_type, util::FullWidthLabel>> ComputeHashes(
                const gsl::span<const std::pair<oprf_item_type, util::FullWidthLabel>> &oprf_item_labels,
                const OPRFKey &oprf_key, std::size_t threads = 0);
        }; // class OPRFSender
    }      // namespace oprf
} // namespace apsi
