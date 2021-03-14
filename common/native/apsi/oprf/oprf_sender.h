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

// APSI
#include "apsi/oprf/oprf_common.h"
#include "apsi/item.h"

// GSL
#include "gsl/span"

namespace apsi
{
    namespace oprf
    {
        class OPRFKey
        {
        public:
            OPRFKey()
            {
                create();
            }

            OPRFKey &operator =(const OPRFKey &copy)
            {
                oprf_key_ = copy.oprf_key_;
                return *this;
            }

            OPRFKey &operator =(OPRFKey &&source) = default;

            OPRFKey(const OPRFKey &copy)
            {
                operator =(copy);
            }

            OPRFKey(OPRFKey &&source) = default;

            void create()
            {
                // Create a random key
                ECPoint::make_random_nonzero_scalar(oprf_key_span_type{ oprf_key_.begin(), oprf_key_size });
            }

            void save(std::ostream &stream) const;

            void load(std::istream &stream);

            void save(oprf_key_span_type oprf_key) const;

            void load(oprf_key_span_const_type oprf_key);

            void clear()
            {
                oprf_key_ = seal::DynArray<unsigned char>(
                    oprf_key_size, seal::MemoryManager::GetPool(seal::mm_prof_opt::mm_force_new, true));
            }

            oprf_key_span_const_type key_span() const noexcept
            {
                return oprf_key_span_const_type{ oprf_key_.cbegin(), oprf_key_size };
            }

        private:
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
                const OPRFKey &oprf_key);

            static std::vector<std::pair<oprf_hash_type, EncryptedLabel>> ComputeHashes(
                const gsl::span<const std::pair<oprf_item_type, Label>> &oprf_item_labels,
                const OPRFKey &oprf_key);
        }; // class OPRFSender
    }      // namespace oprf
} // namespace apsi
