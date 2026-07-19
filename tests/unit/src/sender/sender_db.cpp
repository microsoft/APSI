// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <memory>
#include <numeric>
#include <sstream>

// APSI
#include "apsi/log.h"
#include "apsi/psi_params.h"
#include "apsi/sender_db.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::sender;
using namespace seal;

namespace APSITests {
    namespace {
        shared_ptr<PSIParams> get_params1()
        {
            static shared_ptr<PSIParams> params = nullptr;
            if (!params) {
                PSIParams::ItemParams item_params;
                item_params.felts_per_item = 8;

                PSIParams::TableParams table_params;
                table_params.hash_func_count = 3;
                table_params.max_items_per_bin = 8;
                table_params.table_size = 512;

                PSIParams::QueryParams query_params;
                query_params.query_powers = { 1, 3, 5 };

                size_t pmd = 4096;
                PSIParams::SEALParams seal_params;
                seal_params.set_poly_modulus_degree(pmd);
                seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
                seal_params.set_plain_modulus(65537);

                params =
                    make_shared<PSIParams>(item_params, table_params, query_params, seal_params);
            }

            return params;
        }

        shared_ptr<PSIParams> get_params2()
        {
            static shared_ptr<PSIParams> params = nullptr;
            if (!params) {
                PSIParams::ItemParams item_params;
                item_params.felts_per_item = 7;

                PSIParams::TableParams table_params;
                table_params.hash_func_count = 3;
                table_params.max_items_per_bin = 8;
                table_params.table_size = 585;

                PSIParams::QueryParams query_params;
                query_params.query_powers = { 1, 3, 5 };

                size_t pmd = 4096;
                PSIParams::SEALParams seal_params;
                seal_params.set_poly_modulus_degree(pmd);
                seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
                seal_params.set_plain_modulus(65537);

                params =
                    make_shared<PSIParams>(item_params, table_params, query_params, seal_params);
            }

            return params;
        }

        bool oprf_keys_equal(oprf::OPRFKey key1, oprf::OPRFKey key2)
        {
            return equal(key1.key_span().begin(), key1.key_span().end(), key2.key_span().begin());
        }

        Label create_label(unsigned char start, size_t byte_count)
        {
            Label label(byte_count);
            iota(label.begin(), label.end(), start);
            return label;
        }
    } // namespace

    TEST(SenderDBTests, Constructor)
    {
        auto params = get_params1();

        oprf::OPRFKey new_key;
        stringstream ss;
        new_key.save(ss);
        string new_key_str = ss.str();

        SenderDB sender_db(*params, 0);
        stringstream ss2;
        sender_db.get_oprf_key().save(ss2);
        string db_key_str = ss2.str();

        ASSERT_EQ(db_key_str.size(), new_key_str.size());
        ASSERT_NE(0, memcmp(db_key_str.data(), new_key_str.data(), db_key_str.size()));

        SenderDB sender_db2(*params, new_key, 0);
        stringstream ss3;
        sender_db2.get_oprf_key().save(ss3);
        db_key_str = ss3.str();

        ASSERT_EQ(db_key_str.size(), new_key_str.size());
        ASSERT_EQ(0, memcmp(db_key_str.data(), new_key_str.data(), db_key_str.size()));
    }

    TEST(SenderDBTests, UnlabeledBasics)
    {
        auto test_fun = [](shared_ptr<PSIParams> params) {
            // Nonce byte count is totally ignored when label byte count is zero
            ASSERT_NO_THROW(SenderDB sender_db(*params, 0, 17));

            SenderDB sender_db(*params, 0);

            ASSERT_EQ(0, sender_db.get_bin_bundle_count());
            sender_db.clear();
            ASSERT_EQ(0, sender_db.get_bin_bundle_count());

            ASSERT_FALSE(sender_db.get_crypto_context().encryptor());
            ASSERT_FALSE(sender_db.get_crypto_context().decryptor());
            ASSERT_TRUE(sender_db.get_crypto_context().evaluator());
            ASSERT_FALSE(sender_db.get_crypto_context().relin_keys());
            ASSERT_TRUE(sender_db.get_crypto_context().seal_context());
            ASSERT_FALSE(sender_db.get_crypto_context().secret_key());

            auto items = sender_db.get_hashed_items();
            ASSERT_TRUE(items.empty());

            auto set_params = sender_db.get_params();
            ASSERT_EQ(params->to_string(), set_params.to_string());

            oprf::OPRFKey oprf_key = sender_db.get_oprf_key();
            ASSERT_FALSE(all_of(oprf_key.key_span().begin(), oprf_key.key_span().end(), [](auto b) {
                return b == 0;
            }));
        };

        test_fun(get_params1());
        test_fun(get_params2());
    }

    TEST(SenderDBTests, LabeledBasics)
    {
        auto test_fun = [](shared_ptr<PSIParams> params) {
            // Label byte count is too large
            ASSERT_THROW(SenderDB sender_db(*params, 1025, 0), invalid_argument);

            // Nonce byte count is too large
            ASSERT_THROW(SenderDB sender_db(*params, 1, 17), invalid_argument);

            SenderDB sender_db(*params, 20, 16);
            ASSERT_EQ(20, sender_db.get_label_byte_count());
            ASSERT_EQ(16, sender_db.get_nonce_byte_count());

            ASSERT_EQ(0, sender_db.get_bin_bundle_count());
            sender_db.clear();
            ASSERT_EQ(0, sender_db.get_bin_bundle_count());

            ASSERT_FALSE(sender_db.get_crypto_context().encryptor());
            ASSERT_FALSE(sender_db.get_crypto_context().decryptor());
            ASSERT_TRUE(sender_db.get_crypto_context().evaluator());
            ASSERT_FALSE(sender_db.get_crypto_context().relin_keys());
            ASSERT_TRUE(sender_db.get_crypto_context().seal_context());
            ASSERT_FALSE(sender_db.get_crypto_context().secret_key());

            auto items = sender_db.get_hashed_items();
            ASSERT_TRUE(items.empty());

            auto set_params = sender_db.get_params();
            ASSERT_EQ(params->to_string(), set_params.to_string());

            oprf::OPRFKey oprf_key = sender_db.get_oprf_key();
            ASSERT_FALSE(all_of(oprf_key.key_span().begin(), oprf_key.key_span().end(), [](auto b) {
                return b == 0;
            }));
        };

        test_fun(get_params1());
        test_fun(get_params2());
    }

    TEST(SenderDBTests, UnlabeledInsertOrAssignSingle)
    {
        auto test_fun = [](shared_ptr<PSIParams> params) {
            SenderDB sender_db(*params, 0);

            // Insert a single item
            sender_db.insert_or_assign(Item(0, 0));
            ASSERT_EQ(1, sender_db.get_hashed_items().size());
            ASSERT_EQ(1, sender_db.get_bin_bundle_count());
            ASSERT_TRUE(sender_db.has_item(Item(0, 0)));

            // Now re-insert; this should have no effect
            sender_db.insert_or_assign(Item(0, 0));
            ASSERT_EQ(1, sender_db.get_hashed_items().size());
            ASSERT_EQ(1, sender_db.get_bin_bundle_count());
            ASSERT_TRUE(sender_db.has_item(Item(0, 0)));

            // Clear and check that items were removed
            sender_db.clear();
            ASSERT_TRUE(sender_db.get_hashed_items().empty());
            ASSERT_EQ(0, sender_db.get_bin_bundle_count());
            ASSERT_FALSE(sender_db.has_item(Item(0, 0)));

            // Insert an item and then a second item separately; note that we have only one bundle
            // index
            sender_db.insert_or_assign(Item(0, 0));
            sender_db.insert_or_assign(Item(1, 0));
            ASSERT_EQ(2, sender_db.get_hashed_items().size());
            ASSERT_EQ(1, sender_db.get_bin_bundle_count());
            ASSERT_TRUE(sender_db.has_item(Item(0, 0)));
            ASSERT_TRUE(sender_db.has_item(Item(1, 0)));
            ASSERT_FALSE(sender_db.has_item(Item(2, 0)));

            auto bundle_idx_count = params->bundle_idx_count();
            for (uint32_t i = 0; i < bundle_idx_count; i++) {
                // Access caches
                auto cache = sender_db.get_cache_at(i);

                // Check the cache; we have only one bundle at this index
                ASSERT_TRUE(all_of(cache.begin(), cache.end(), [](auto &a) {
                    return !!a.get().batched_matching_polyn;
                }));
                ASSERT_TRUE(all_of(cache.begin(), cache.end(), [](auto &a) {
                    return a.get().batched_interp_polyns.empty();
                }));
            }

            // Accessing cache beyond range
            ASSERT_THROW(auto cache = sender_db.get_cache_at(bundle_idx_count), out_of_range);

            // Clear and check that items were removed
            sender_db.clear();
            ASSERT_TRUE(sender_db.get_hashed_items().empty());
            ASSERT_EQ(0, sender_db.get_bin_bundle_count());
        };

        test_fun(get_params1());
        test_fun(get_params2());
    }

    TEST(SenderDBTests, UnlabeledInsertOrAssignMany)
    {
        auto test_fun = [](shared_ptr<PSIParams> params) {
            SenderDB sender_db(*params, 0);

            // Create a vector of items without duplicates
            vector<Item> items;
            for (uint64_t i = 0; i < 200; i++) {
                items.push_back({ i, i + 1 });
            }

            // Insert all items
            sender_db.insert_or_assign(items);
            ASSERT_EQ(200, sender_db.get_hashed_items().size());
            auto bin_bundle_count = sender_db.get_bin_bundle_count();
            for (auto &item : items) {
                ASSERT_TRUE(sender_db.has_item(item));
            }
            ASSERT_FALSE(sender_db.has_item(Item(1000, 1001)));

            // Now re-insert; this should have no effect
            sender_db.insert_or_assign(items);
            ASSERT_EQ(200, sender_db.get_hashed_items().size());
            ASSERT_EQ(bin_bundle_count, sender_db.get_bin_bundle_count());
            for (auto &item : items) {
                ASSERT_TRUE(sender_db.has_item(item));
            }
            ASSERT_FALSE(sender_db.has_item(Item(1000, 1001)));

            // Clear and check that items were removed
            sender_db.clear();
            ASSERT_TRUE(sender_db.get_hashed_items().empty());
            ASSERT_EQ(0, sender_db.get_bin_bundle_count());
            for (auto &item : items) {
                ASSERT_FALSE(sender_db.has_item(item));
            }

            // Insert again
            sender_db.insert_or_assign(items);
            ASSERT_EQ(200, sender_db.get_hashed_items().size());
            ASSERT_EQ(bin_bundle_count, sender_db.get_bin_bundle_count());
            for (auto &item : items) {
                ASSERT_TRUE(sender_db.has_item(item));
            }
            ASSERT_FALSE(sender_db.has_item(Item(1000, 1001)));

            auto bundle_idx_count = params->bundle_idx_count();
            for (uint32_t i = 0; i < bundle_idx_count; i++) {
                // Access caches
                auto cache = sender_db.get_cache_at(i);

                // Check the cache; we have only one bundle at this index
                ASSERT_TRUE(all_of(cache.begin(), cache.end(), [](auto a) {
                    return !!a.get().batched_matching_polyn;
                }));
                ASSERT_TRUE(all_of(cache.begin(), cache.end(), [](auto a) {
                    return a.get().batched_interp_polyns.empty();
                }));
            }

            // Accessing cache beyond range
            ASSERT_THROW(auto cache = sender_db.get_cache_at(bundle_idx_count), out_of_range);

            // Clear and check that items were removed
            sender_db.clear();
            ASSERT_TRUE(sender_db.get_hashed_items().empty());
            ASSERT_EQ(0, sender_db.get_bin_bundle_count());
        };

        test_fun(get_params1());
        test_fun(get_params2());
    }

    TEST(SenderDBTests, LabeledInsertOrAssignSingle)
    {
        auto test_fun = [](shared_ptr<PSIParams> params) {
            SenderDB sender_db(*params, 20, 16, true);

            // Insert a single item with zero label
            sender_db.insert_or_assign(make_pair(Item(0, 0), create_label(0, 20)));
            ASSERT_EQ(1, sender_db.get_hashed_items().size());
            ASSERT_EQ(1, sender_db.get_bin_bundle_count());
            ASSERT_TRUE(sender_db.has_item(Item(0, 0)));
            auto label = sender_db.get_label(Item(0, 0));
            ASSERT_EQ(create_label(0, 20), label);

            // Replace label
            sender_db.insert_or_assign(make_pair(Item(0, 0), create_label(1, 20)));
            ASSERT_EQ(1, sender_db.get_hashed_items().size());
            ASSERT_EQ(1, sender_db.get_bin_bundle_count());
            ASSERT_TRUE(sender_db.has_item(Item(0, 0)));
            label = sender_db.get_label(Item(0, 0));
            ASSERT_EQ(create_label(1, 20), label);

            // Replace label again
            sender_db.insert_or_assign(make_pair(Item(0, 0), create_label(0xFF, 20)));
            ASSERT_EQ(1, sender_db.get_hashed_items().size());
            ASSERT_EQ(1, sender_db.get_bin_bundle_count());
            ASSERT_TRUE(sender_db.has_item(Item(0, 0)));
            label = sender_db.get_label(Item(0, 0));
            ASSERT_EQ(create_label(0xFF, 20), label);

            // Insert another item
            sender_db.insert_or_assign(make_pair(Item(1, 0), create_label(1, 20)));
            ASSERT_EQ(2, sender_db.get_hashed_items().size());
            ASSERT_TRUE(sender_db.has_item(Item(0, 0)));
            ASSERT_TRUE(sender_db.has_item(Item(1, 0)));
            label = sender_db.get_label(Item(0, 0));
            ASSERT_EQ(create_label(0xFF, 20), label);
            label = sender_db.get_label(Item(1, 0));
            ASSERT_EQ(create_label(1, 20), label);

            // Clear and check that items were removed
            sender_db.clear();
            ASSERT_TRUE(sender_db.get_hashed_items().empty());
            ASSERT_EQ(0, sender_db.get_bin_bundle_count());
            ASSERT_TRUE(sender_db.get_hashed_items().empty());
            ASSERT_FALSE(sender_db.has_item(Item(0, 0)));
            ASSERT_FALSE(sender_db.has_item(Item(1, 0)));

            ASSERT_THROW(auto label2 = sender_db.get_label(Item(0, 0)), logic_error);
            ASSERT_THROW(auto label2 = sender_db.get_label(Item(1, 0)), logic_error);
        };

        test_fun(get_params1());
        test_fun(get_params2());
    }

    TEST(SenderDBTests, LabeledInsertOrAssignMany)
    {
        auto test_fun = [](shared_ptr<PSIParams> params) {
            SenderDB sender_db(*params, 20, 16, true);

            // Create a vector of items and labels without duplicates
            vector<pair<Item, Label>> items;
            for (uint64_t i = 0; i < 200; i++) {
                items.push_back(
                    make_pair(Item(i, i + 1), create_label(static_cast<unsigned char>(i), 20)));
            }

            // Insert all items
            sender_db.insert_or_assign(items);
            ASSERT_EQ(200, sender_db.get_hashed_items().size());
            auto bin_bundle_count = sender_db.get_bin_bundle_count();
            for (auto &item : items) {
                ASSERT_TRUE(sender_db.has_item(item.first));
                ASSERT_EQ(item.second, sender_db.get_label(item.first));
            }
            ASSERT_FALSE(sender_db.has_item(Item(1000, 1001)));

            // Now re-insert; this should have no effect
            sender_db.insert_or_assign(items);
            ASSERT_EQ(200, sender_db.get_hashed_items().size());
            ASSERT_EQ(bin_bundle_count, sender_db.get_bin_bundle_count());
            for (auto &item : items) {
                ASSERT_TRUE(sender_db.has_item(item.first));
                ASSERT_EQ(item.second, sender_db.get_label(item.first));
            }
            ASSERT_FALSE(sender_db.has_item(Item(1000, 1001)));

            // Clear and check that items were removed
            sender_db.clear();
            ASSERT_TRUE(sender_db.get_hashed_items().empty());
            ASSERT_EQ(0, sender_db.get_bin_bundle_count());
            for (auto &item : items) {
                ASSERT_FALSE(sender_db.has_item(item.first));
                ASSERT_THROW(auto label2 = sender_db.get_label(item.first), logic_error);
            }

            // Insert again
            sender_db.insert_or_assign(items);
            ASSERT_EQ(200, sender_db.get_hashed_items().size());
            ASSERT_EQ(bin_bundle_count, sender_db.get_bin_bundle_count());
            for (auto &item : items) {
                ASSERT_TRUE(sender_db.has_item(item.first));
                ASSERT_EQ(item.second, sender_db.get_label(item.first));
            }
            ASSERT_FALSE(sender_db.has_item(Item(1000, 1001)));

            auto bundle_idx_count = params->bundle_idx_count();
            for (uint32_t i = 0; i < bundle_idx_count; i++) {
                // Access caches
                auto cache = sender_db.get_cache_at(i);

                // Check the cache; we have only one bundle at this index
                ASSERT_TRUE(all_of(cache.begin(), cache.end(), [](auto a) {
                    return !!a.get().batched_matching_polyn;
                }));
                ASSERT_TRUE(none_of(cache.begin(), cache.end(), [](auto a) {
                    return a.get().batched_interp_polyns.empty();
                }));
            }

            // Accessing cache beyond range
            ASSERT_THROW(auto cache = sender_db.get_cache_at(bundle_idx_count), out_of_range);

            // Clear and check that items were removed
            sender_db.clear();
            ASSERT_TRUE(sender_db.get_hashed_items().empty());
            ASSERT_EQ(0, sender_db.get_bin_bundle_count());
        };

        test_fun(get_params1());
        test_fun(get_params2());
    }

    TEST(SenderDBTests, Remove)
    {
        auto test_fun = [](shared_ptr<PSIParams> params) {
            // We use a labeled SenderDB here to end up with multiple BinBundles more quickly. This
            // happens because in the labeled case BinBundles cannot tolerate repetitions of item
            // parts (felts) in bins.
            SenderDB sender_db(*params, 20, 16, true);

            // Insert a single item
            sender_db.insert_or_assign({ Item(0, 0), create_label(0, 20) });
            ASSERT_EQ(1, sender_db.get_hashed_items().size());
            ASSERT_EQ(1, sender_db.get_bin_bundle_count());

            // Try remove item that doesn't exist
            ASSERT_THROW(sender_db.remove(Item(1, 0)), logic_error);

            // Remove inserted item
            sender_db.remove(Item(0, 0));
            ASSERT_EQ(0, sender_db.get_hashed_items().size());
            ASSERT_EQ(0, sender_db.get_bin_bundle_count());
            ASSERT_FALSE(sender_db.has_item(Item(0, 0)));

            // Now insert until we have 2 BinBundles
            uint64_t val = 0;
            while (sender_db.get_bin_bundle_count() < 2) {
                sender_db.insert_or_assign(
                    { Item(val, ~val), create_label(static_cast<unsigned char>(val), 20) });
                val++;
                APSI_LOG_ERROR(val << " " << sender_db.get_bin_bundle_count());
            }

            // Check that everything was inserted
            ASSERT_EQ(val, sender_db.get_hashed_items().size());
            ASSERT_EQ(2, sender_db.get_bin_bundle_count());

            // Now remove the first one; we should immediately drop to 2 BinBundles
            val--;
            sender_db.remove(Item(val, ~val));
            ASSERT_EQ(val, sender_db.get_hashed_items().size());
            ASSERT_EQ(1, sender_db.get_bin_bundle_count());

            // Remove all inserted items, one-by-one
            while (val > 0) {
                val--;
                sender_db.remove(Item(val, ~val));
            }

            // No BinBundles should be left at this time
            ASSERT_TRUE(sender_db.get_hashed_items().empty());
            ASSERT_EQ(0, sender_db.get_bin_bundle_count());

            // Again insert until we have 2 BinBundles
            val = 0;
            while (sender_db.get_bin_bundle_count() < 2) {
                sender_db.insert_or_assign(
                    { Item(val, ~val), create_label(static_cast<unsigned char>(val), 20) });
                val++;
            }

            // Now remove all
            sender_db.clear();

            // No BinBundles should be left at this time
            ASSERT_TRUE(sender_db.get_hashed_items().empty());
            ASSERT_EQ(0, sender_db.get_bin_bundle_count());
        };

        test_fun(get_params1());
        test_fun(get_params2());
    }

    TEST(SenderDBTests, SaveLoadUnlabeled)
    {
        auto test_fun = [](shared_ptr<PSIParams> params) {
            SenderDB sender_db(*params, 0, 0, false);

            stringstream ss;
            size_t save_size = sender_db.save(ss);
            auto other = SenderDB::Load(ss);
            auto other_sdb = std::move(other.first);

            ASSERT_EQ(save_size, other.second);
            ASSERT_EQ(params->to_string(), other_sdb.get_params().to_string());
            ASSERT_EQ(sender_db.get_hashed_items().size(), other_sdb.get_hashed_items().size());
            ASSERT_EQ(sender_db.is_compressed(), other_sdb.is_compressed());
            ASSERT_EQ(sender_db.is_labeled(), other_sdb.is_labeled());
            ASSERT_EQ(sender_db.get_label_byte_count(), other_sdb.get_label_byte_count());
            ASSERT_EQ(sender_db.get_nonce_byte_count(), other_sdb.get_nonce_byte_count());
            ASSERT_TRUE(oprf_keys_equal(sender_db.get_oprf_key(), other_sdb.get_oprf_key()));

            // Insert a single item
            sender_db.insert_or_assign(HashedItem(0, 0));

            save_size = sender_db.save(ss);
            other = SenderDB::Load(ss);
            other_sdb = std::move(other.first);

            ASSERT_EQ(save_size, other.second);
            ASSERT_EQ(params->to_string(), other_sdb.get_params().to_string());
            ASSERT_EQ(sender_db.get_hashed_items().size(), other_sdb.get_hashed_items().size());
            ASSERT_EQ(sender_db.is_compressed(), other_sdb.is_compressed());
            ASSERT_EQ(sender_db.is_labeled(), other_sdb.is_labeled());
            ASSERT_EQ(sender_db.get_label_byte_count(), other_sdb.get_label_byte_count());
            ASSERT_EQ(sender_db.get_nonce_byte_count(), other_sdb.get_nonce_byte_count());
            ASSERT_TRUE(oprf_keys_equal(sender_db.get_oprf_key(), other_sdb.get_oprf_key()));

            // Create a vector of items without duplicates
            vector<Item> items;
            for (uint64_t i = 0; i < 200; i++) {
                items.push_back({ i, i + 1 });
            }

            // Insert all items
            sender_db.insert_or_assign(items);

            save_size = sender_db.save(ss);
            other = SenderDB::Load(ss);
            other_sdb = std::move(other.first);

            ASSERT_EQ(save_size, other.second);
            ASSERT_EQ(params->to_string(), other_sdb.get_params().to_string());
            ASSERT_EQ(sender_db.get_hashed_items().size(), other_sdb.get_hashed_items().size());
            ASSERT_EQ(sender_db.is_compressed(), other_sdb.is_compressed());
            ASSERT_EQ(sender_db.is_labeled(), other_sdb.is_labeled());
            ASSERT_EQ(sender_db.get_label_byte_count(), other_sdb.get_label_byte_count());
            ASSERT_EQ(sender_db.get_nonce_byte_count(), other_sdb.get_nonce_byte_count());
            ASSERT_TRUE(oprf_keys_equal(sender_db.get_oprf_key(), other_sdb.get_oprf_key()));

            // Check that the items match
            for (auto &it : sender_db.get_hashed_items()) {
                ASSERT_NE(
                    other_sdb.get_hashed_items().end(), other_sdb.get_hashed_items().find(it));
            }
        };

        test_fun(get_params1());
        test_fun(get_params2());
    }

    TEST(SenderDBTests, SaveLoadLabeled)
    {
        auto test_fun = [](shared_ptr<PSIParams> params) {
            SenderDB sender_db(*params, 20, 8);

            stringstream ss;
            size_t save_size = sender_db.save(ss);
            auto other = SenderDB::Load(ss);
            auto other_sdb = std::move(other.first);

            ASSERT_EQ(save_size, other.second);
            ASSERT_EQ(params->to_string(), other_sdb.get_params().to_string());
            ASSERT_EQ(sender_db.get_hashed_items().size(), other_sdb.get_hashed_items().size());
            ASSERT_EQ(sender_db.is_compressed(), other_sdb.is_compressed());
            ASSERT_EQ(sender_db.is_labeled(), other_sdb.is_labeled());
            ASSERT_EQ(sender_db.get_label_byte_count(), other_sdb.get_label_byte_count());
            ASSERT_EQ(sender_db.get_nonce_byte_count(), other_sdb.get_nonce_byte_count());
            ASSERT_TRUE(oprf_keys_equal(sender_db.get_oprf_key(), other_sdb.get_oprf_key()));

            // Insert a single item
            sender_db.insert_or_assign(make_pair(Item(0, 0), create_label(0, 20)));

            save_size = sender_db.save(ss);
            other = SenderDB::Load(ss);
            other_sdb = std::move(other.first);

            ASSERT_EQ(save_size, other.second);
            ASSERT_EQ(params->to_string(), other_sdb.get_params().to_string());
            ASSERT_EQ(sender_db.get_hashed_items().size(), other_sdb.get_hashed_items().size());
            ASSERT_EQ(sender_db.is_compressed(), other_sdb.is_compressed());
            ASSERT_EQ(sender_db.is_labeled(), other_sdb.is_labeled());
            ASSERT_EQ(sender_db.get_label_byte_count(), other_sdb.get_label_byte_count());
            ASSERT_EQ(sender_db.get_nonce_byte_count(), other_sdb.get_nonce_byte_count());
            ASSERT_TRUE(oprf_keys_equal(sender_db.get_oprf_key(), other_sdb.get_oprf_key()));

            // Create a vector of items and labels without duplicates
            vector<pair<Item, Label>> items;
            for (uint64_t i = 0; i < 200; i++) {
                items.push_back(
                    make_pair(Item(i, i + 1), create_label(static_cast<unsigned char>(i), 20)));
            }

            // Insert all items
            sender_db.insert_or_assign(items);

            save_size = sender_db.save(ss);
            other = SenderDB::Load(ss);
            other_sdb = std::move(other.first);

            ASSERT_EQ(save_size, other.second);
            ASSERT_EQ(params->to_string(), other_sdb.get_params().to_string());
            ASSERT_EQ(sender_db.get_hashed_items().size(), other_sdb.get_hashed_items().size());
            ASSERT_EQ(sender_db.is_compressed(), other_sdb.is_compressed());
            ASSERT_EQ(sender_db.is_labeled(), other_sdb.is_labeled());
            ASSERT_EQ(sender_db.get_label_byte_count(), other_sdb.get_label_byte_count());
            ASSERT_EQ(sender_db.get_nonce_byte_count(), other_sdb.get_nonce_byte_count());
            ASSERT_TRUE(oprf_keys_equal(sender_db.get_oprf_key(), other_sdb.get_oprf_key()));

            // Check that the items match
            for (auto &it : sender_db.get_hashed_items()) {
                ASSERT_NE(
                    other_sdb.get_hashed_items().end(), other_sdb.get_hashed_items().find(it));
            }
        };

        test_fun(get_params1());
        test_fun(get_params2());
    }

    TEST(SenderDBTests, StripUnlabeled)
    {
        auto test_fun = [](shared_ptr<PSIParams> params) {
            SenderDB sender_db(*params, 0, 0, false);

            // Strip and reset
            ASSERT_FALSE(sender_db.is_stripped());
            sender_db.strip();
            ASSERT_TRUE(sender_db.is_stripped());
            sender_db.clear();
            ASSERT_FALSE(sender_db.is_stripped());

            // Insert one item and check data
            sender_db.insert_or_assign(Item(0, 0));
            ASSERT_EQ(1, sender_db.get_hashed_items().size());
            ASSERT_EQ(1, sender_db.get_item_count());
            ASSERT_EQ(1, sender_db.get_bin_bundle_count());
            ASSERT_TRUE(sender_db.has_item(Item(0, 0)));
            auto pr = sender_db.get_packing_rate();

            // Strip and check sizes
            sender_db.strip();
            ASSERT_TRUE(sender_db.is_stripped());
            ASSERT_EQ(0, sender_db.get_hashed_items().size());
            ASSERT_EQ(1, sender_db.get_item_count());
            ASSERT_EQ(1, sender_db.get_bin_bundle_count());
            ASSERT_EQ(pr, sender_db.get_packing_rate());

            // Attempt operations on a stripped SenderDB
            ASSERT_THROW(sender_db.has_item(Item(0, 0)), logic_error);
            ASSERT_THROW(sender_db.insert_or_assign(Item(1, 2)), logic_error);
            ASSERT_THROW(sender_db.remove(Item(0, 0)), logic_error);

            // Save, load, and check sizes
            stringstream ss;
            sender_db.save(ss);
            SenderDB sender_db2 = SenderDB::Load(ss).first;
            ASSERT_TRUE(sender_db2.is_stripped());
            ASSERT_EQ(0, sender_db2.get_hashed_items().size());
            ASSERT_EQ(1, sender_db2.get_item_count());
            ASSERT_EQ(1, sender_db2.get_bin_bundle_count());
            ASSERT_EQ(pr, sender_db2.get_packing_rate());

            sender_db2.clear();
            ASSERT_FALSE(sender_db2.is_stripped());
        };

        test_fun(get_params1());
        test_fun(get_params2());
    }

    TEST(SenderDBTests, StripLabeled)
    {
        auto test_fun = [](shared_ptr<PSIParams> params) {
            SenderDB sender_db(*params, 20, 8, false);

            // Strip and reset
            ASSERT_FALSE(sender_db.is_stripped());
            sender_db.strip();
            ASSERT_TRUE(sender_db.is_stripped());
            sender_db.clear();
            ASSERT_FALSE(sender_db.is_stripped());

            // Insert one item and check data
            sender_db.insert_or_assign(make_pair(Item(0, 0), create_label(0, 20)));
            ASSERT_EQ(1, sender_db.get_hashed_items().size());
            ASSERT_EQ(1, sender_db.get_item_count());
            ASSERT_EQ(1, sender_db.get_bin_bundle_count());
            ASSERT_TRUE(sender_db.has_item(Item(0, 0)));
            auto pr = sender_db.get_packing_rate();

            // Strip and check sizes
            sender_db.strip();
            ASSERT_TRUE(sender_db.is_stripped());
            ASSERT_EQ(0, sender_db.get_hashed_items().size());
            ASSERT_EQ(1, sender_db.get_item_count());
            ASSERT_EQ(1, sender_db.get_bin_bundle_count());
            ASSERT_EQ(pr, sender_db.get_packing_rate());

            // Attempt operations on a stripped SenderDB
            ASSERT_THROW(sender_db.has_item(Item(0, 0)), logic_error);
            ASSERT_THROW(sender_db.get_label(Item(0, 0)), logic_error);
            ASSERT_THROW(sender_db.insert_or_assign(Item(1, 2)), logic_error);
            ASSERT_THROW(sender_db.remove(Item(0, 0)), logic_error);

            // Save, load, and check sizes
            stringstream ss;
            sender_db.save(ss);
            SenderDB sender_db2 = SenderDB::Load(ss).first;
            ASSERT_TRUE(sender_db2.is_stripped());
            ASSERT_EQ(0, sender_db2.get_hashed_items().size());
            ASSERT_EQ(1, sender_db2.get_item_count());
            ASSERT_EQ(1, sender_db2.get_bin_bundle_count());
            ASSERT_EQ(pr, sender_db2.get_packing_rate());

            sender_db2.clear();
            ASSERT_FALSE(sender_db2.is_stripped());
        };

        test_fun(get_params1());
        test_fun(get_params2());
    }
} // namespace APSITests
