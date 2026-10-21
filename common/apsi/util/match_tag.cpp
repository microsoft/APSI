// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <limits>
#include <stdexcept>

// APSI
#include "apsi/util/match_tag.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/blake2.h"

using namespace std;

namespace apsi::util {
    vector<felt_t> compute_match_tag(const LabelKey &key, size_t felt_count, uint32_t bits_per_felt)
    {
        if (!felt_count) {
            throw invalid_argument("felt_count cannot be zero");
        }
        if (!bits_per_felt ||
            bits_per_felt > static_cast<uint32_t>(numeric_limits<felt_t>::digits)) {
            throw invalid_argument("bits_per_felt must be between 1 and 64");
        }

        // Blake2xb produces at most 2^32 - 1 bytes. Dividing first keeps the comparison itself
        // from overflowing.
        constexpr uint64_t max_byte_count = 0xFFFFFFFFULL;
        if (static_cast<uint64_t>(felt_count) > (max_byte_count * 8) / bits_per_felt) {
            throw invalid_argument("felt_count is too large");
        }

        uint64_t bit_count = static_cast<uint64_t>(felt_count) * bits_per_felt;
        auto byte_count = static_cast<size_t>((bit_count + 7) / 8);

        vector<unsigned char> bytes(byte_count);
        if (APSI_blake2xb(
                bytes.data(),
                byte_count,
                match_tag_domain.data(),
                match_tag_domain.size(),
                key.data(),
                key.size()) != 0) {
            throw runtime_error("failed to compute match tag");
        }

        // Spelled out bit by bit, least significant bit first, so that the layout is plain to see
        // and does not depend on how anything else in APSI packs bits
        vector<felt_t> felts(felt_count, 0);
        for (size_t j = 0; j < felt_count; j++) {
            felt_t felt = 0;
            for (uint32_t k = 0; k < bits_per_felt; k++) {
                uint64_t i = (static_cast<uint64_t>(j) * bits_per_felt) + k;
                felt_t bit =
                    static_cast<felt_t>((bytes[static_cast<size_t>(i / 8)] >> (i % 8)) & 1U);
                felt |= bit << k;
            }
            felts[j] = felt;
        }

        return felts;
    }
} // namespace apsi::util
