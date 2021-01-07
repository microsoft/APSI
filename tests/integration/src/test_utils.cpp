// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSI
#include "test_utils.h"

#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::receiver;
using namespace apsi::util;
using namespace seal;

namespace APSITests
{
    unordered_set<Item> rand_subset(const unordered_set<Item> &items, size_t size)
    {
        random_device rd;

        set<size_t> ss;
        while (ss.size() != size)
        {
            ss.emplace(static_cast<size_t>(rd() % items.size()));
        }

        vector<Item> items_vec(items.begin(), items.end());
        unordered_set<Item> items_subset;
        for (auto idx : ss)
        {
            items_subset.insert(items_vec[idx]);
        }

        return items_subset;
    }

    unordered_set<Item> rand_subset(const unordered_map<Item, FullWidthLabel> &items, size_t size)
    {
        random_device rd;

        set<size_t> ss;
        while (ss.size() != size)
        {
            ss.emplace(static_cast<size_t>(rd() % items.size()));
        }

        vector<Item> items_vec;
        transform(items.begin(), items.end(), back_inserter(items_vec), [](auto &item) { return item.first; });
        unordered_set<Item> items_subset;
        for (auto idx : ss)
        {
            items_subset.insert(items_vec[idx]);
        }

        return items_subset;
    }

    void verify_unlabeled_results(
        const vector<MatchRecord> &query_result,
        const vector<Item> &query_vec,
        const unordered_set<Item> &int_items
    ) {
        // Count matches
        size_t match_count = accumulate(query_result.cbegin(), query_result.cend(), size_t(0),
            [](auto sum, auto &curr) { return sum + curr.found; });

        // Check that intersection size is correct
        ASSERT_EQ(int_items.size(), match_count);

        // Check that every intersection item was actually found
        for (auto &item : int_items)
        {
            auto where = find(query_vec.begin(), query_vec.end(), item);
            ASSERT_NE(query_vec.end(), where);

            auto idx = distance(query_vec.begin(), where);
            ASSERT_TRUE(query_result[idx].found);
        }
    }

    void verify_labeled_results(
        const vector<MatchRecord> &query_result,
        const vector<Item> &query_vec,
        const unordered_set<Item> &int_items,
        const unordered_map<Item, FullWidthLabel> &all_item_labels
    ) {
        verify_unlabeled_results(query_result, query_vec, int_items);

        // Verify that all labels were received for items that were found
        for (auto &result : query_result)
        {
            if (result.found)
            {
                ASSERT_TRUE(result.label);

            }
        }

        // Check that the labels are correct for items in the intersection
        for (auto &item : int_items)
        {
            auto where = find(query_vec.begin(), query_vec.end(), item);
            auto idx = distance(query_vec.begin(), where);

            auto reference_label = find_if(
                all_item_labels.begin(),
                all_item_labels.end(),
                [&item](auto &item_label) { return item == item_label.first; });
            ASSERT_NE(all_item_labels.end(), reference_label);

            array<uint64_t, 2> label;
            copy_n(query_result[idx].label.get_as<uint64_t>().begin(), 2, label.begin());
            ASSERT_EQ(reference_label->second.value(), label);
        }
    }

    PSIParams create_params()
    {
        PSIParams::ItemParams item_params;
        item_params.felts_per_item = 8;

        PSIParams::TableParams table_params;
        table_params.hash_func_count = 3;
        table_params.max_items_per_bin = 16;
        table_params.table_size = 4096;

        PSIParams::QueryParams query_params;
        query_params.query_powers = { 1, 3, 5 };

        PSIParams::SEALParams seal_params;
        seal_params.set_poly_modulus_degree(8192);
        seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(8192));
        seal_params.set_plain_modulus(65537);

        return { item_params, table_params, query_params, seal_params };
    }

    PSIParams create_huge_params()
    {
        PSIParams::ItemParams item_params;
        item_params.felts_per_item = 8;

        PSIParams::TableParams table_params;
        table_params.hash_func_count = 4;
        table_params.max_items_per_bin = 128;
        table_params.table_size = 65536;

        PSIParams::QueryParams query_params;
        query_params.query_powers = { 1, 7, 12, 43, 52 };

        PSIParams::SEALParams seal_params;
        seal_params.set_poly_modulus_degree(16384);
        seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(16384));
        seal_params.set_plain_modulus(65537);

        return { item_params, table_params, query_params, seal_params };
    }
}