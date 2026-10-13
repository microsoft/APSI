// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

// APSI
#include "apsi/item.h"
#include "apsi/util/db_encoding.h"

namespace apsi::util {
    /**
    The input from which match tags are derived: the 17 ASCII bytes "apsi.match_tag.v1", with no
    terminating null. Label encryption keys the same Blake2xb with the same label key but feeds it
    a nonce of at most max_nonce_byte_count (16) bytes as its input, so a tag and a label
    keystream are never computed on the same input.
    */
    constexpr std::array<unsigned char, 17> match_tag_domain{ 'a', 'p', 's', 'i', '.', 'm',
                                                              'a', 't', 'c', 'h', '_', 't',
                                                              'a', 'g', '.', 'v', '1' };

    // See match_tag_domain. Raising max_nonce_byte_count to the length of the domain or beyond
    // would need a new domain.
    static_assert(
        match_tag_domain.size() > max_nonce_byte_count,
        "the match tag domain must be longer than any label nonce");

    /**
    Computes the match tag of an item from its label key, as field elements of bits_per_felt bits
    each, in the layout the sender stores it in and the receiver checks it in.

    The sender and the receiver both derive the tag from the label key of the item, which is the
    second half of the item's OPRF output: the sender for every item it stores, the receiver for
    every item it queries. A receiver's item matches exactly when the sender returns this tag in
    the item's slots, so the two sides must agree on it bit for bit:

        1. Let n = felt_count * bits_per_felt. Compute ceil(n / 8) bytes of Blake2xb output, keyed
           with key, on the input match_tag_domain.

        2. Read the bytes as a string of bits, least significant bit of the first byte first: bit
           i is (bytes[i / 8] >> (i % 8)) & 1. Field element j consists of bits j * bits_per_felt
           up to (j + 1) * bits_per_felt, the first of them least significant, and so lies in
           [0, 2^bits_per_felt). Any bits beyond n in the last byte are not used.

    Note that Blake2xb commits to its output length, so a tag of one length is unrelated to a tag
    of another, rather than a prefix of it: the parameters fix felt_count and bits_per_felt for
    both sides.

    With felts_per_item field elements per item and bits_per_felt the item bit count per field
    element, a tag of tag_part_count parts has felt_count = tag_part_count * felts_per_item
    field elements in part-major order: part p of the tag in the item's slot s is the field
    element at index p * felts_per_item + s. Since 2^bits_per_felt is at most the plain modulus,
    each field element is a valid plaintext value.

    Throws std::invalid_argument if felt_count is zero, if bits_per_felt is not in [1, 64], or if
    the tag would be longer than Blake2xb can produce, and std::runtime_error if Blake2xb fails.
    */
    std::vector<felt_t> compute_match_tag(
        const LabelKey &key, std::size_t felt_count, std::uint32_t bits_per_felt);
} // namespace apsi::util
