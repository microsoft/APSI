// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <cstddef>
#include <memory>
#include <random>
#include <vector>
#include <algorithm>
#include <array>
#include <set>
#include <unordered_set>
#include <unordered_map>

// APSI
#include "apsi/item.h"
#include "apsi/util/db_encoding.h"
#include "apsi/psi_params.h"
#include "apsi/receiver.h"

#include "gtest/gtest.h"

namespace APSITests
{
    std::unordered_set<apsi::Item> rand_subset(const std::unordered_set<apsi::Item> &items, std::size_t size);

    std::unordered_set<apsi::Item> rand_subset(
        const std::unordered_map<apsi::Item, apsi::util::FullWidthLabel> &items,
        std::size_t size);

    void verify_unlabeled_results(
        const std::vector<apsi::receiver::MatchRecord> &query_result,
        const std::vector<apsi::Item> &query_vec,
        const std::unordered_set<apsi::Item> &int_items);

    void verify_labeled_results(
        const std::vector<apsi::receiver::MatchRecord> &query_result,
        const std::vector<apsi::Item> &query_vec,
        const std::unordered_set<apsi::Item> &int_items,
        const std::unordered_map<apsi::Item, apsi::util::FullWidthLabel> &all_item_labels);

    apsi::PSIParams create_params();

    apsi::PSIParams create_huge_params();
} // namespace APSITests