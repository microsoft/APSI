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

    apsi::PSIParams create_params1();

    apsi::PSIParams create_params2();

    apsi::PSIParams create_huge_params1();

    apsi::PSIParams create_huge_params2();
} // namespace APSITests
