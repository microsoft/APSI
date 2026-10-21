// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <random>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// APSI
#include "apsi/item.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/psi_params.h"
#include "apsi/receiver.h"

// Google Test
#include "gtest/gtest.h"

namespace APSITests {
    apsi::Label create_label(unsigned char start, std::size_t byte_count);

    std::unordered_set<apsi::Item> rand_subset(
        const std::unordered_set<apsi::Item> &items, std::size_t size);

    std::unordered_set<apsi::Item> rand_subset(
        const std::unordered_map<apsi::Item, apsi::Label> &item_labels, std::size_t size);

    std::vector<apsi::Item> rand_subset(const std::vector<apsi::Item> &items, std::size_t size);

    std::vector<apsi::Item> rand_subset(
        const std::vector<std::pair<apsi::Item, apsi::Label>> &items, std::size_t size);

    void verify_unlabeled_results(
        const std::vector<apsi::receiver::MatchRecord> &query_result,
        const std::vector<apsi::Item> &query_vec,
        const std::vector<apsi::Item> &int_items);

    void verify_labeled_results(
        const std::vector<apsi::receiver::MatchRecord> &query_result,
        const std::vector<apsi::Item> &query_vec,
        const std::vector<apsi::Item> &int_items,
        const std::vector<std::pair<apsi::Item, apsi::Label>> &all_item_labels);

    /**
    A known OPRF key, so that a test whose shape depends on where items hash behaves the same on
    every run. The key is a scalar read as native-endian machine words: it must be nonzero and
    below the group order, and OPRFKey::load checks neither. The low bytes make it nonzero; the
    top eight must stay zero, because the order is just under 2^246 and filling the whole buffer
    would give a value near 2^253. This is the key the unit tests use.
    */
    apsi::oprf::OPRFKey fixed_oprf_key();

    apsi::PSIParams create_params1();

    apsi::PSIParams create_params2();

    apsi::PSIParams create_huge_params1();

    apsi::PSIParams create_huge_params2();

    /**
    Parameters with match tags: one field element of 16 bits per item and a tag of three parts.
    */
    apsi::PSIParams create_tag_params1();

    /**
    Parameters with match tags: two field elements per item, a tag of two parts, and
    Paterson-Stockmeyer evaluation.
    */
    apsi::PSIParams create_tag_params2();

    /**
    Parameters with match tags and short items: a 14-bit plain modulus, so only 13 bits per item,
    one hash function, and every query power sent. Two items in a bin then have the same field
    element one time in 8192, so among 20000 items about a dozen pairs do, and each such pair has
    to go to different bin bundles.
    */
    apsi::PSIParams create_tag_collision_params();
} // namespace APSITests
