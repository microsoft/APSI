// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

// SEAL
#include "seal/dynarray.h"
#include "seal/memorymanager.h"

// APSI
#include "apsi/item.h"
#include "apsi/oprf/oprf_common.h"
#include "apsi/util/db_encoding.h"
#include "apsi/util/utils.h"

// GSL
#include "gsl/span"

namespace apsi::oprf {
    class OPRFKey {
    public:
        OPRFKey()
        {
            create();
        }

        OPRFKey &operator=(const OPRFKey &copy) = default;

        OPRFKey &operator=(OPRFKey &&source) = default;

        OPRFKey(const OPRFKey &copy)
        {
            operator=(copy);
        }

        OPRFKey(OPRFKey &&source) = default;

        bool operator==(const OPRFKey &compare) const;

        bool operator!=(const OPRFKey &compare) const
        {
            return !operator==(compare);
        }

        void create()
        {
            // Reducing the key modulo the group order leaves images of it in frames below.
            util::StackScrubGuard scrub_guard;

            // Create a random key
            ECPoint::MakeRandomNonzeroScalar(
                oprf_key_span_type{ oprf_key_.begin(), oprf_key_size });
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

        [[nodiscard]] oprf_key_span_const_type key_span() const noexcept
        {
            return oprf_key_span_const_type{ oprf_key_.cbegin(), oprf_key_size };
        }

    private:
        seal::DynArray<unsigned char> oprf_key_{
            oprf_key_size, seal::MemoryManager::GetPool(seal::mm_prof_opt::mm_force_new, true)
        };
    }; // class OPRFKey

    class OPRFSender {
    public:
        OPRFSender() = delete;

        static std::vector<unsigned char> ProcessQueries(
            gsl::span<const unsigned char> oprf_queries, const OPRFKey &oprf_key);

        static std::pair<HashedItem, LabelKey> GetItemHash(
            const Item &item, const OPRFKey &oprf_key);

        static std::vector<HashedItem> ComputeHashes(
            const gsl::span<const Item> &oprf_items, const OPRFKey &oprf_key);

        /**
        Computes the OPRF hashes of the given items and encrypts their labels with the items'
        label keys, each label padded to label_byte_count bytes and preceded by a random nonce of
        nonce_byte_count bytes, as a labeled SenderDB stores them.

        Throws std::invalid_argument if nonce_byte_count is too large, or if a label is longer
        than label_byte_count, rather than truncating it: the receiver could not tell a truncated
        label from a correct one.
        */
        static std::vector<std::pair<HashedItem, EncryptedLabel>> ComputeHashes(
            const gsl::span<const std::pair<Item, Label>> &oprf_item_labels,
            const OPRFKey &oprf_key,
            std::size_t label_byte_count,
            std::size_t nonce_byte_count);

        /**
        Computes the OPRF hashes of the given items, as ComputeHashes does, together with the
        match tag of each item: tag_felt_count field elements of bits_per_felt bits each, derived
        from the item's label key as util::compute_match_tag describes. The label keys
        themselves are wiped rather than returned. A SenderDB whose parameters use match tags
        stores these tags with its items; see PSIParams::uses_tags.

        Throws std::invalid_argument if util::compute_match_tag rejects tag_felt_count or
        bits_per_felt, unless oprf_items is empty.
        */
        static std::vector<std::pair<HashedItem, std::vector<util::felt_t>>>
        ComputeHashesAndMatchTags(
            const gsl::span<const Item> &oprf_items,
            const OPRFKey &oprf_key,
            std::size_t tag_felt_count,
            std::uint32_t bits_per_felt);

        /**
        Computes the OPRF hashes of the given items and encrypts their labels, as ComputeHashes
        does for item-label pairs, together with the match tag of each item: tag_felt_count field
        elements of bits_per_felt bits each, derived from the item's label key as
        util::compute_match_tag describes. The label keys themselves are wiped rather than
        returned. A labeled SenderDB whose parameters use match tags stores these tags with its
        items; see PSIParams::uses_tags.

        Throws std::invalid_argument if nonce_byte_count is too large, if a label is longer than
        label_byte_count, as ComputeHashes does, or if util::compute_match_tag rejects
        tag_felt_count or bits_per_felt and oprf_item_labels is not empty.
        */
        static std::vector<std::tuple<HashedItem, EncryptedLabel, std::vector<util::felt_t>>>
        ComputeHashesAndMatchTags(
            const gsl::span<const std::pair<Item, Label>> &oprf_item_labels,
            const OPRFKey &oprf_key,
            std::size_t label_byte_count,
            std::size_t nonce_byte_count,
            std::size_t tag_felt_count,
            std::uint32_t bits_per_felt);
    }; // class OPRFSender
} // namespace apsi::oprf
