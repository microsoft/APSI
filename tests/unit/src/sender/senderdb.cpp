// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <memory>
#include <cstddef>

// APSI
#include "apsi/senderdb.h"
#include "apsi/psiparams.h"

#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::sender;
using namespace seal;

namespace APSITests
{
    namespace
    {
        shared_ptr<PSIParams> get_params()
        {
            static shared_ptr<PSIParams> params = nullptr;
            if (!params)
            {
                PSIParams::ItemParams item_params;
                item_params.felts_per_item = 8;

                PSIParams::TableParams table_params;
                table_params.hash_func_count = 3;
                table_params.max_items_per_bin = 16;
                table_params.table_size = 1024;

                PSIParams::QueryParams query_params;
                query_params.query_powers_count = 3;

                size_t pmd = 4096;
                PSIParams::SEALParams seal_params(scheme_type::bfv);
                seal_params.set_poly_modulus_degree(pmd);
                seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
                seal_params.set_plain_modulus(65537);

                params = make_shared<PSIParams>(item_params, table_params, query_params, seal_params);
            }

            return params;
        }
    }

    TEST(SenderDBTests, UnlabeledBasics)
    {
        auto params = get_params();
        UnlabeledSenderDB sender_db(*params);

        ASSERT_EQ(0, sender_db.get_bin_bundle_count());
        sender_db.clear_db();
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());

        ASSERT_FALSE(sender_db.get_context().encryptor());
        ASSERT_FALSE(sender_db.get_context().decryptor());
        ASSERT_TRUE(sender_db.get_context().evaluator());
        ASSERT_FALSE(sender_db.get_context().relin_keys());
        ASSERT_TRUE(sender_db.get_context().seal_context());
        ASSERT_FALSE(sender_db.get_context().secret_key());

        auto items = sender_db.get_items();
        ASSERT_TRUE(items.empty());

        auto set_params = sender_db.get_params();
        ASSERT_EQ(params->to_string(), set_params.to_string());
    }

    TEST(SenderDBTests, LabeledBasics)
    {
        auto params = get_params();
        LabeledSenderDB sender_db(*params);

        ASSERT_EQ(0, sender_db.get_bin_bundle_count());
        sender_db.clear_db();
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());

        ASSERT_FALSE(sender_db.get_context().encryptor());
        ASSERT_FALSE(sender_db.get_context().decryptor());
        ASSERT_TRUE(sender_db.get_context().evaluator());
        ASSERT_FALSE(sender_db.get_context().relin_keys());
        ASSERT_TRUE(sender_db.get_context().seal_context());
        ASSERT_FALSE(sender_db.get_context().secret_key());

        auto items = sender_db.get_items();
        ASSERT_TRUE(items.empty());

        auto set_params = sender_db.get_params();
        ASSERT_EQ(params->to_string(), set_params.to_string());
    }

    TEST(SenderDBTests, UnlabeledInsertOrAssignSingle)
    {
        auto params = get_params();
        UnlabeledSenderDB sender_db(*params);

        // Insert a single item
        sender_db.insert_or_assign(HashedItem(0, 0));
        ASSERT_EQ(1, sender_db.get_items().size());
        ASSERT_EQ(1, sender_db.get_bin_bundle_count());

        // Now re-insert; this should have no effect
        sender_db.insert_or_assign(HashedItem(0, 0));
        ASSERT_EQ(1, sender_db.get_items().size());
        ASSERT_EQ(1, sender_db.get_bin_bundle_count());

        // Clear and check that items were removed
        sender_db.clear_db();
        ASSERT_TRUE(sender_db.get_items().empty());
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());

        // Insert an item and then a second item separately; note that we have only one bundle index
        sender_db.insert_or_assign(HashedItem(0, 0));
        sender_db.insert_or_assign(HashedItem(1, 0));
        ASSERT_EQ(2, sender_db.get_items().size());
        ASSERT_EQ(1, sender_db.get_bin_bundle_count());

        // Check that both items are found and whatever was not inserted is not found.
        ASSERT_FALSE(sender_db.get_items().find({ 0, 0 }) == sender_db.get_items().end());
        ASSERT_FALSE(sender_db.get_items().find({ 1, 0 }) == sender_db.get_items().end());
        ASSERT_TRUE(sender_db.get_items().find({ 2, 0 }) == sender_db.get_items().end());

        auto bundle_idx_count = params->bundle_idx_count();
        for (uint32_t i = 0; i < bundle_idx_count; i++)
        {
            // Access caches
            auto cache = sender_db.get_cache_at(i);

            // Check the cache; we have only one bundle at this index
            ASSERT_TRUE(all_of(cache.begin(), cache.end(), [](auto &a) { return a.get().batched_matching_polyn; }));
            ASSERT_TRUE(none_of(cache.begin(), cache.end(), [](auto &a) { return a.get().batched_interp_polyn; }));
        }

        // Accessing cache beyond range
        ASSERT_THROW(auto cache = sender_db.get_cache_at(bundle_idx_count), out_of_range);

        // Clear and check that items were removed
        sender_db.clear_db();
        ASSERT_TRUE(sender_db.get_items().empty());
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());
    }

    TEST(SenderDBTests, UnlabeledInsertOrAssignMany)
    {
        auto params = get_params();
        UnlabeledSenderDB sender_db(*params);

        // Create a vector of items with duplicates
        unordered_set<HashedItem> items;
        for (uint64_t i = 0; i < 200; i++)
        {
            items.emplace(i, i + 1);
        }

        // Insert all items
        sender_db.insert_or_assign(items);
        ASSERT_EQ(200, sender_db.get_items().size());
        auto bin_bundle_count = sender_db.get_bin_bundle_count();

        // Now re-insert; this should have no effect
        sender_db.insert_or_assign(items);
        ASSERT_EQ(200, sender_db.get_items().size());
        ASSERT_EQ(bin_bundle_count, sender_db.get_bin_bundle_count());

        // Clear and check that items were removed
        sender_db.clear_db();
        ASSERT_TRUE(sender_db.get_items().empty());
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());

        // Insert again
        sender_db.insert_or_assign(items);
        ASSERT_EQ(200, sender_db.get_items().size());
        ASSERT_EQ(bin_bundle_count, sender_db.get_bin_bundle_count());

        // Check that all items are found
        for (auto item : items)
        {
            ASSERT_FALSE(sender_db.get_items().find(item) == sender_db.get_items().end());
        }
        ASSERT_TRUE(sender_db.get_items().find({ 200, 201 }) == sender_db.get_items().end());

        auto bundle_idx_count = params->bundle_idx_count();
        for (uint32_t i = 0; i < bundle_idx_count; i++)
        {
            // Access caches
            auto cache = sender_db.get_cache_at(i);

            // Check the cache; we have only one bundle at this index
            ASSERT_TRUE(all_of(cache.begin(), cache.end(), [](auto a) { return a.get().batched_matching_polyn; }));
            ASSERT_TRUE(none_of(cache.begin(), cache.end(), [](auto a) { return a.get().batched_interp_polyn; }));
        }

        // Accessing cache beyond range
        ASSERT_THROW(auto cache = sender_db.get_cache_at(bundle_idx_count), out_of_range);

        // Clear and check that items were removed
        sender_db.clear_db();
        ASSERT_TRUE(sender_db.get_items().empty());
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());
    }

    TEST(SenderDBTests, LabeledInsertOrAssignSingle)
    {
        auto params = get_params();
        LabeledSenderDB sender_db(*params);

        // Insert a single item with zero label
        sender_db.insert_or_assign(make_pair(HashedItem(0, 0), FullWidthLabel(0, 0)));
        ASSERT_EQ(1, sender_db.get_items().size());
        ASSERT_EQ(1, sender_db.get_bin_bundle_count());
        auto label = sender_db.get_label(HashedItem(0, 0));
        ASSERT_EQ(FullWidthLabel(0, 0), label);

        // Replace label
        sender_db.insert_or_assign(make_pair(HashedItem(0, 0), FullWidthLabel(1, 0)));
        ASSERT_EQ(1, sender_db.get_items().size());
        ASSERT_EQ(1, sender_db.get_bin_bundle_count());
        label = sender_db.get_label(HashedItem(0, 0));
        ASSERT_EQ(FullWidthLabel(1, 0), label);

        // Replace label again
        sender_db.insert_or_assign(make_pair(HashedItem(0, 0), FullWidthLabel(~uint64_t(0), ~uint64_t(0))));
        ASSERT_EQ(1, sender_db.get_items().size());
        ASSERT_EQ(1, sender_db.get_bin_bundle_count());
        label = sender_db.get_label(HashedItem(0, 0));
        ASSERT_EQ(FullWidthLabel(~uint64_t(0), ~uint64_t(0)), label);

        // Insert another item
        sender_db.insert_or_assign(make_pair(HashedItem(1, 0), FullWidthLabel(1, 1)));
        ASSERT_EQ(2, sender_db.get_items().size());
        label = sender_db.get_label(HashedItem(0, 0));
        ASSERT_EQ(FullWidthLabel(~uint64_t(0), ~uint64_t(0)), label);
        label = sender_db.get_label(HashedItem(1, 0));
        ASSERT_EQ(FullWidthLabel(1, 1), label);

        // Check that both items are found and whatever was not inserted is not found.
        auto items = sender_db.get_items();
        ASSERT_FALSE(items.empty());
        ASSERT_FALSE(sender_db.get_items().find({ 0, 0 }) == sender_db.get_items().end());
        ASSERT_FALSE(sender_db.get_items().find({ 1, 0 }) == sender_db.get_items().end());
        ASSERT_TRUE(sender_db.get_items().find({ 2, 0 }) == sender_db.get_items().end());

        // Clear and check that items were removed
        sender_db.clear_db();
        ASSERT_TRUE(sender_db.get_items().empty());
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());
        ASSERT_TRUE(sender_db.get_items().empty());
    }

    TEST(SenderDBTests, LabeledInsertOrAssignMany)
    {
        auto params = get_params();
        LabeledSenderDB sender_db(*params);

        // Create a vector of items and labels with duplicates
        unordered_map<HashedItem, FullWidthLabel> items;
        for (uint64_t i = 0; i < 200; i++)
        {
            items.emplace(make_pair(HashedItem(i, i + 1), FullWidthLabel(i, i + 1)));
        }

        // Insert all items
        sender_db.insert_or_assign(items);
        ASSERT_EQ(200, sender_db.get_items().size());
        auto bin_bundle_count = sender_db.get_bin_bundle_count();

        // Now re-insert; this should have no effect
        sender_db.insert_or_assign(items);
        ASSERT_EQ(200, sender_db.get_items().size());
        ASSERT_EQ(bin_bundle_count, sender_db.get_bin_bundle_count());

        // Clear and check that items were removed
        sender_db.clear_db();
        ASSERT_TRUE(sender_db.get_items().empty());
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());

        // Insert again
        sender_db.insert_or_assign(items);
        ASSERT_EQ(200, sender_db.get_items().size());
        ASSERT_EQ(bin_bundle_count, sender_db.get_bin_bundle_count());

        // Check that all items are found and labels are correct
        for (auto item : items)
        {
            ASSERT_FALSE(sender_db.get_items().find(item.first) == sender_db.get_items().end());
            auto label = sender_db.get_label(item.first);
            ASSERT_EQ(item.second, label);
        }
        ASSERT_TRUE(sender_db.get_items().find({ 200, 201 }) == sender_db.get_items().end());

        auto bundle_idx_count = params->bundle_idx_count();
        for (uint32_t i = 0; i < bundle_idx_count; i++)
        {
            // Access caches
            auto cache = sender_db.get_cache_at(i);

            // Check the cache; we have only one bundle at this index
            ASSERT_TRUE(all_of(cache.begin(), cache.end(), [](auto a) { return a.get().batched_matching_polyn; }));
            ASSERT_FALSE(none_of(cache.begin(), cache.end(), [](auto a) { return a.get().batched_interp_polyn; }));
        }

        // Accessing cache beyond range
        ASSERT_THROW(auto cache = sender_db.get_cache_at(bundle_idx_count), out_of_range);

        // Clear and check that items were removed
        sender_db.clear_db();
        ASSERT_TRUE(sender_db.get_items().empty());
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());
    }
}
