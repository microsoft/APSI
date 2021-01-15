// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <memory>
#include <cstddef>
#include <sstream>

// APSI
#include "apsi/sender_db.h"
#include "apsi/psi_params.h"
#include "apsi/logging/log.h"

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
                query_params.query_powers = { 1, 3, 5 };

                size_t pmd = 4096;
                PSIParams::SEALParams seal_params;
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

        ASSERT_FALSE(sender_db.get_crypto_context().encryptor());
        ASSERT_FALSE(sender_db.get_crypto_context().decryptor());
        ASSERT_TRUE(sender_db.get_crypto_context().evaluator());
        ASSERT_FALSE(sender_db.get_crypto_context().relin_keys());
        ASSERT_TRUE(sender_db.get_crypto_context().seal_context());
        ASSERT_FALSE(sender_db.get_crypto_context().secret_key());

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

        ASSERT_FALSE(sender_db.get_crypto_context().encryptor());
        ASSERT_FALSE(sender_db.get_crypto_context().decryptor());
        ASSERT_TRUE(sender_db.get_crypto_context().evaluator());
        ASSERT_FALSE(sender_db.get_crypto_context().relin_keys());
        ASSERT_TRUE(sender_db.get_crypto_context().seal_context());
        ASSERT_FALSE(sender_db.get_crypto_context().secret_key());

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
            ASSERT_TRUE(all_of(cache.begin(), cache.end(), [](auto &a) { return !!a.get().batched_matching_polyn; }));
            ASSERT_TRUE(none_of(cache.begin(), cache.end(), [](auto &a) { return !!a.get().batched_interp_polyn; }));
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

        // Create a vector of items without duplicates
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
            ASSERT_TRUE(all_of(cache.begin(), cache.end(), [](auto a) { return !!a.get().batched_matching_polyn; }));
            ASSERT_TRUE(none_of(cache.begin(), cache.end(), [](auto a) { return !!a.get().batched_interp_polyn; }));
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

        // Create a vector of items and labels without duplicates
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
            ASSERT_TRUE(all_of(cache.begin(), cache.end(), [](auto a) { return !!a.get().batched_matching_polyn; }));
            ASSERT_FALSE(none_of(cache.begin(), cache.end(), [](auto a) { return !!a.get().batched_interp_polyn; }));
        }

        // Accessing cache beyond range
        ASSERT_THROW(auto cache = sender_db.get_cache_at(bundle_idx_count), out_of_range);

        // Clear and check that items were removed
        sender_db.clear_db();
        ASSERT_TRUE(sender_db.get_items().empty());
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());
    }

    TEST(SenderDBTests, Remove)
    {
        auto params = get_params();
        UnlabeledSenderDB sender_db(*params);

        // Insert a single item
        sender_db.insert_or_assign(HashedItem(0, 0));
        ASSERT_EQ(1, sender_db.get_items().size());
        ASSERT_EQ(1, sender_db.get_bin_bundle_count());
        ASSERT_FALSE(sender_db.get_items().find({ 0, 0 }) == sender_db.get_items().end());

        // Try remove item that doesn't exist
        ASSERT_THROW(sender_db.remove(HashedItem(1, 0)), invalid_argument);

        // Remove inserted item
        sender_db.remove(HashedItem(0, 0));
        ASSERT_EQ(0, sender_db.get_items().size());
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());
        ASSERT_TRUE(sender_db.get_items().find({ 0, 0 }) == sender_db.get_items().end());

        // Now insert until we have 5 BinBundles
        uint64_t val = 0;
        while (sender_db.get_bin_bundle_count() < 5)
        {
            sender_db.insert_or_assign(HashedItem(val, ~val));
            val++;
        }

        // Check that everything was found
        ASSERT_EQ(val, sender_db.get_items().size());
        ASSERT_EQ(5, sender_db.get_bin_bundle_count());

        // Now remove the first one; we should immediately drop to 4 BinBundles
        val--;
        sender_db.remove(HashedItem(val, ~val));
        ASSERT_EQ(val, sender_db.get_items().size());
        ASSERT_EQ(4, sender_db.get_bin_bundle_count());

        // Remove all inserted items, one-by-one
        while (val > 0)
        {
            val--;
            sender_db.remove(HashedItem(val, ~val));
        }

        // No BinBundles should be left at this time
        ASSERT_TRUE(sender_db.get_items().empty());
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());

        // Again insert until we have 5 BinBundles
        val = 0;
        while (sender_db.get_bin_bundle_count() < 5)
        {
            sender_db.insert_or_assign(HashedItem(val, ~val));
            val++;
        }

        // Now remove all
        unordered_set<HashedItem> items = sender_db.get_items();
        sender_db.remove(items);

        // No BinBundles should be left at this time
        ASSERT_TRUE(sender_db.get_items().empty());
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());
    }

    TEST(SenderDBTests, SaveLoadUnlabeled)
    {
        auto params = get_params();
        shared_ptr<SenderDB> sender_db(make_shared<UnlabeledSenderDB>(*params));

        stringstream ss;
        size_t save_size = SaveSenderDB(sender_db, ss);
        auto other = LoadSenderDB(ss);
        auto other_sdb = other.first;
        ASSERT_NE(nullptr, other_sdb);

        ASSERT_EQ(save_size, other.second);
        ASSERT_EQ(params->to_string(), other_sdb->get_params().to_string());
        ASSERT_EQ(sender_db->get_items().size(), other_sdb->get_items().size());
        ASSERT_EQ(sender_db->is_compressed(), other_sdb->is_compressed());
        ASSERT_EQ(sender_db->is_labeled(), other_sdb->is_labeled());

        // Insert a single item
        sender_db->insert_or_assign(HashedItem(0, 0));

        save_size = SaveSenderDB(sender_db, ss);
        other = LoadSenderDB(ss);
        other_sdb = other.first;
        ASSERT_NE(nullptr, other_sdb);

        ASSERT_EQ(save_size, other.second);
        ASSERT_EQ(params->to_string(), other_sdb->get_params().to_string());
        ASSERT_EQ(sender_db->get_items().size(), other_sdb->get_items().size());
        ASSERT_EQ(sender_db->is_compressed(), other_sdb->is_compressed());
        ASSERT_EQ(sender_db->is_labeled(), other_sdb->is_labeled());

        // Create a vector of items without duplicates
        unordered_set<HashedItem> items;
        for (uint64_t i = 0; i < 200; i++)
        {
            items.emplace(i, i + 1);
        }

        // Insert all items
        sender_db->insert_or_assign(items);

        save_size = SaveSenderDB(sender_db, ss);
        other = LoadSenderDB(ss);
        other_sdb = other.first;
        ASSERT_NE(nullptr, other_sdb);

        ASSERT_EQ(save_size, other.second);
        ASSERT_EQ(params->to_string(), other_sdb->get_params().to_string());
        ASSERT_EQ(sender_db->get_items().size(), other_sdb->get_items().size());
        ASSERT_EQ(sender_db->is_compressed(), other_sdb->is_compressed());
        ASSERT_EQ(sender_db->is_labeled(), other_sdb->is_labeled());

        // Check that the items match
        for (auto &it : sender_db->get_items())
        {
            ASSERT_NE(other_sdb->get_items().end(), other_sdb->get_items().find(it));
        }
    }

    TEST(SenderDBTests, SaveLoadLabeled)
    {
        auto params = get_params();
        shared_ptr<SenderDB> sender_db(make_shared<LabeledSenderDB>(*params));

        stringstream ss;
        size_t save_size = SaveSenderDB(sender_db, ss);
        auto other = LoadSenderDB(ss);
        auto other_sdb = other.first;
        ASSERT_NE(nullptr, other_sdb);

        ASSERT_EQ(save_size, other.second);
        ASSERT_EQ(params->to_string(), other_sdb->get_params().to_string());
        ASSERT_EQ(sender_db->get_items().size(), other_sdb->get_items().size());
        ASSERT_EQ(sender_db->is_compressed(), other_sdb->is_compressed());
        ASSERT_EQ(sender_db->is_labeled(), other_sdb->is_labeled());

        // Insert a single item
        sender_db->insert_or_assign(make_pair(HashedItem(0, 0), FullWidthLabel(0, 0)));

        save_size = SaveSenderDB(sender_db, ss);
        other = LoadSenderDB(ss);
        other_sdb = other.first;
        ASSERT_NE(nullptr, other_sdb);

        ASSERT_EQ(save_size, other.second);
        ASSERT_EQ(params->to_string(), other_sdb->get_params().to_string());
        ASSERT_EQ(sender_db->get_items().size(), other_sdb->get_items().size());
        ASSERT_EQ(sender_db->is_compressed(), other_sdb->is_compressed());
        ASSERT_EQ(sender_db->is_labeled(), other_sdb->is_labeled());

        // Create a vector of items and labels without duplicates
        unordered_map<HashedItem, FullWidthLabel> items;
        for (uint64_t i = 0; i < 200; i++)
        {
            items.emplace(make_pair(HashedItem(i, i + 1), FullWidthLabel(i, i + 1)));
        }

        // Insert all items
        sender_db->insert_or_assign(items);

        save_size = SaveSenderDB(sender_db, ss);
        other = LoadSenderDB(ss);
        other_sdb = other.first;
        ASSERT_NE(nullptr, other_sdb);

        ASSERT_EQ(save_size, other.second);
        ASSERT_EQ(params->to_string(), other_sdb->get_params().to_string());
        ASSERT_EQ(sender_db->get_items().size(), other_sdb->get_items().size());
        ASSERT_EQ(sender_db->is_compressed(), other_sdb->is_compressed());
        ASSERT_EQ(sender_db->is_labeled(), other_sdb->is_labeled());

        // Check that the items match
        for (auto &it : sender_db->get_items())
        {
            ASSERT_NE(other_sdb->get_items().end(), other_sdb->get_items().find(it));
        }
    }
}
