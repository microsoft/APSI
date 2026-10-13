// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstring>
#include <memory>
#include <numeric>
#include <set>
#include <sstream>
#include <string>
#include <thread>

// APSI
#include "apsi/log.h"
#include "apsi/network/stream_channel.h"
#include "apsi/oprf/oprf_common.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/psi_params.h"
#include "apsi/query.h"
#include "apsi/receiver.h"
#include "apsi/sender.h"
#include "apsi/sender_db.h"
#include "apsi/sender_db_generated.h"
#include "apsi/util/db_encoding.h"
#include "apsi/util/label_encryptor.h"

// Kuku
#include "kuku/locfunc.h"

// SEAL
#include "seal/util/uintarithsmallmod.h"

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

        bool oprf_keys_equal(const oprf::OPRFKey &key1, const oprf::OPRFKey &key2)
        {
            return equal(key1.key_span().begin(), key1.key_span().end(), key2.key_span().begin());
        }

        Label create_label(unsigned char start, size_t byte_count)
        {
            Label label(byte_count);
            iota(label.begin(), label.end(), start);
            return label;
        }

        /**
        A known OPRF key, so that a test whose shape depends on where items hash behaves the same
        on every run. The key is a scalar read as native-endian machine words: it must be nonzero
        and below the group order, and OPRFKey::load checks neither. The low bytes make it
        nonzero; the top eight must stay zero, because the order is just under 2^246 and filling
        the whole buffer would give a value near 2^253.
        */
        oprf::OPRFKey fixed_oprf_key()
        {
            constexpr size_t set_byte_count = oprf::oprf_key_size - 8;

            oprf::OPRFKey key;
            array<unsigned char, oprf::oprf_key_size> bytes{};
            for (size_t i = 0; i < set_byte_count; i++) {
                bytes[i] = static_cast<unsigned char>(i + 1);
            }
            key.load(oprf::oprf_key_span_const_type(bytes));
            return key;
        }

        /**
        The given parameters with a smaller max_items_per_bin, so that a test inserting one item
        at a time reaches a second bin bundle after tens of items rather than hundreds. Each
        insert regenerates the bundle's cache, so that count dominates the test's cost.
        */
        PSIParams with_shallow_bins(const PSIParams &params, uint32_t max_items_per_bin)
        {
            PSIParams::TableParams table_params = params.table_params();
            table_params.max_items_per_bin = max_items_per_bin;

            // The parameters must stay consistent for the queries that some tests run: a query
            // power may not exceed max_items_per_bin, so drop the ones that no longer fit.
            PSIParams::QueryParams query_params = params.query_params();
            set<uint32_t> query_powers;
            for (uint32_t power : query_params.query_powers) {
                if (power <= max_items_per_bin) {
                    query_powers.insert(power);
                }
            }
            query_params.query_powers = std::move(query_powers);

            return { params.item_params(), table_params, query_params, params.seal_params() };
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

    TEST(SenderDBTests, LabeledSenderDBAcceptsAZeroNonce)
    {
        auto params = get_params1();

        // A zero nonce makes label encryption deterministic, which is safe for a SenderDB whose
        // labels are never rewritten and saves the nonce bytes on every item. It is warned about
        // rather than refused: the operator is the only party that knows whether labels will be
        // rewritten, and refusing zero while accepting one would draw an arbitrary line, since a
        // one-byte nonce repeats after a handful of updates anyway.
        ASSERT_NO_THROW(SenderDB(*params, 16, 0));

        oprf::OPRFKey key;
        ASSERT_NO_THROW(SenderDB(*params, key, 16, 0));

        // Short nonces stay available for the same reason.
        ASSERT_NO_THROW(SenderDB(*params, 16, 1));

        // An unlabeled SenderDB has no labels to encrypt, so zero is simply the correct value.
        ASSERT_NO_THROW(SenderDB(*params, 0, 0));

        // A nonce larger than the maximum is still refused; that bound is structural rather than
        // a judgement about the deployment.
        ASSERT_THROW(SenderDB(*params, 16, max_nonce_byte_count + 1), invalid_argument);
    }

    TEST(SenderDBTests, BadBatchIsRejectedWithoutModifyingTheDatabase)
    {
        auto params = get_params1();
        SenderDB sender_db(*params, 8, 16);

        vector<pair<Item, Label>> good;
        good.emplace_back(Item(1, 1), create_label(1, 8));
        good.emplace_back(Item(2, 2), create_label(2, 8));
        sender_db.insert_or_assign(good);
        ASSERT_EQ(size_t(2), sender_db.get_item_count());

        // A batch naming the same item twice: the two labels cannot both be meant, so the batch
        // is refused before anything in it is inserted.
        vector<pair<Item, Label>> duplicated;
        duplicated.emplace_back(Item(7, 7), create_label(7, 8));
        duplicated.emplace_back(Item(9, 9), create_label(9, 8));
        duplicated.emplace_back(Item(7, 7), create_label(11, 8));
        ASSERT_THROW(sender_db.insert_or_assign(duplicated), invalid_argument);

        // A label longer than the database holds. Truncating it would store something the
        // receiver cannot tell apart from a correct label.
        vector<pair<Item, Label>> too_long;
        too_long.emplace_back(Item(3, 3), create_label(3, 9));
        ASSERT_THROW(sender_db.insert_or_assign(too_long), invalid_argument);

        // Nothing from either rejected batch reached the database, and the items that were
        // already there are still whole: present, and with retrievable labels.
        ASSERT_EQ(size_t(2), sender_db.get_item_count());
        for (const auto &bad : { Item(7, 7), Item(9, 9), Item(3, 3) }) {
            ASSERT_FALSE(sender_db.has_item(bad));
        }
        for (uint64_t i : { static_cast<uint64_t>(1), static_cast<uint64_t>(2) }) {
            Item item(i, i);
            ASSERT_TRUE(sender_db.has_item(item));
            ASSERT_NO_THROW((void)sender_db.get_label(item));
        }

        // A batch that is merely rejected must not poison later inserts.
        vector<pair<Item, Label>> retry;
        retry.emplace_back(Item(7, 7), create_label(7, 8));
        retry.emplace_back(Item(9, 9), create_label(9, 8));
        ASSERT_NO_THROW(sender_db.insert_or_assign(retry));
        ASSERT_EQ(size_t(4), sender_db.get_item_count());
        ASSERT_NO_THROW((void)sender_db.get_label(Item(7, 7)));
    }

    TEST(SenderDBTests, RepeatedUnlabeledItemInOneBatchIsCollapsed)
    {
        auto params = get_params1();
        SenderDB sender_db(*params, 0);

        // Unlike a labeled batch, a repeat here carries no ambiguity: inserting the same item
        // twice is idempotent, so it is collapsed rather than refused.
        vector<Item> repeated;
        repeated.emplace_back(1, 1);
        repeated.emplace_back(2, 2);
        repeated.emplace_back(1, 1);
        ASSERT_NO_THROW(sender_db.insert_or_assign(repeated));

        ASSERT_EQ(size_t(2), sender_db.get_item_count());
        ASSERT_TRUE(sender_db.has_item(Item(1, 1)));
        ASSERT_TRUE(sender_db.has_item(Item(2, 2)));
    }

    TEST(SenderDBTests, UnlabeledBasics)
    {
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
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
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
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
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
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
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
            SenderDB sender_db(*params, 0);

            // Create a vector of items without duplicates
            vector<Item> items;
            items.reserve(200);
            for (uint64_t i = 0; i < 200; i++) {
                items.emplace_back(i, i + 1);
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
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
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
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
            SenderDB sender_db(*params, 20, 16, true);

            // Create a vector of items and labels without duplicates
            vector<pair<Item, Label>> items;
            items.reserve(200);
            for (uint64_t i = 0; i < 200; i++) {
                items.emplace_back(Item(i, i + 1), create_label(static_cast<unsigned char>(i), 20));
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
        auto test_fun = [](const shared_ptr<PSIParams> &base_params) {
            // We use a labeled SenderDB here to end up with multiple BinBundles more quickly. This
            // happens because in the labeled case BinBundles cannot tolerate repetitions of item
            // parts (felts) in bins.
            //
            // Shallow bins and a known key, so the loops below reach a second BinBundle after a
            // fixed, small number of items. The bookkeeping under test does not depend on how
            // many that takes.
            PSIParams params = with_shallow_bins(*base_params, 3);
            SenderDB sender_db(params, fixed_oprf_key(), 20, 16, true);

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

    TEST(SenderDBTests, OverwriteChangesTheItemWhereItIsStored)
    {
        // An item being given a new label need not be in the newest bin bundle at its bundle
        // index, and a newer bin bundle may well have room for it. The update must change the
        // item where it is stored and nowhere else. Storing a second copy with the new label
        // instead leaves the old copy answering queries with the old label, makes get_label --
        // which reads the first bin bundle holding the item -- return the old label, and leaves a
        // copy behind when the item is removed.
        auto test_fun = [](const shared_ptr<PSIParams> &base_params) {
            // Shallow bins and a known key, so that a few hundred items spill into further bin
            // bundles at every bundle index, the same way on every run
            PSIParams params = with_shallow_bins(*base_params, 3);
            SenderDB sender_db(params, fixed_oprf_key(), 20, 16, true);

            vector<pair<Item, Label>> data;
            for (uint64_t i = 0; i < 300; i++) {
                data.emplace_back(Item(i, ~i), create_label(static_cast<unsigned char>(i), 20));
            }
            sender_db.set_data(data);

            // Make sure the case this test is about exists: more than one bin bundle at a bundle
            // index, so that items in the older ones can be updated while the newer ones have
            // room
            size_t max_bundles = 0;
            for (uint32_t b = 0; b < params.bundle_idx_count(); b++) {
                max_bundles = max(max_bundles, sender_db.get_bin_bundle_count(b));
            }
            ASSERT_LE(size_t(3), max_bundles);
            size_t bin_bundle_count = sender_db.get_bin_bundle_count();

            // Give every item a new label, all in one batch, and then a few one at a time
            for (auto &item_label : data) {
                item_label.second =
                    create_label(static_cast<unsigned char>(item_label.second[0] + 100), 20);
            }
            sender_db.insert_or_assign(data);
            for (size_t i = 0; i < data.size(); i += 29) {
                data[i].second =
                    create_label(static_cast<unsigned char>(data[i].second[0] + 50), 20);
                sender_db.insert_or_assign(data[i]);
            }

            ASSERT_EQ(data.size(), sender_db.get_item_count());
            ASSERT_EQ(bin_bundle_count, sender_db.get_bin_bundle_count());
            for (const auto &item_label : data) {
                ASSERT_EQ(item_label.second, sender_db.get_label(item_label.first));
            }

            // Removing every item leaves nothing behind
            vector<Item> items;
            for (const auto &item_label : data) {
                items.push_back(item_label.first);
            }
            sender_db.remove(items);
            ASSERT_EQ(0, sender_db.get_item_count());
            ASSERT_EQ(0, sender_db.get_bin_bundle_count());
        };

        test_fun(get_params1());
        test_fun(get_params2());
    }

    TEST(SenderDBTests, FailedRemovalChangesNothing)
    {
        // A removal that cannot be completed must leave the database as it was: the item set and
        // the bin bundles describing the same items, and the bin bundles ready to answer a query.
        // The only way to reach the failure is a database whose item set names an item its bin
        // bundles do not hold, so one is spliced together here from the item set of one database
        // and the bin bundles of another built with the same key.
        auto params = get_params1();
        oprf::OPRFKey key = fixed_oprf_key();

        SenderDB fewer(*params, key, 0, 0, true);
        fewer.set_data(vector<Item>{ Item(1, 1), Item(2, 2) });
        SenderDB more(*params, key, 0, 0, true);
        more.set_data(vector<Item>{ Item(1, 1), Item(2, 2), Item(3, 3) });
        ASSERT_EQ(fewer.get_bin_bundle_count(), more.get_bin_bundle_count());

        // A saved SenderDB is a size-prefixed header followed by the bin bundles
        auto header_size = [](const string &bytes) {
            uint32_t size = 0;
            memcpy(&size, bytes.data(), sizeof(size));
            return sizeof(size) + size;
        };
        stringstream fewer_ss;
        fewer.save(fewer_ss);
        string fewer_bytes = fewer_ss.str();
        stringstream more_ss;
        more.save(more_ss);
        string more_bytes = more_ss.str();

        stringstream spliced_ss;
        spliced_ss << more_bytes.substr(0, header_size(more_bytes))
                   << fewer_bytes.substr(header_size(fewer_bytes));
        SenderDB sender_db = SenderDB::Load(spliced_ss).first;
        ASSERT_EQ(3, sender_db.get_item_count());
        ASSERT_TRUE(sender_db.has_item(Item(3, 3)));

        // Item 3 is in the item set but in no bin bundle, so this removal cannot be completed
        ASSERT_THROW(sender_db.remove(vector<Item>{ Item(1, 1), Item(3, 3) }), logic_error);

        // Nothing changed
        ASSERT_EQ(3, sender_db.get_item_count());
        ASSERT_EQ(3, sender_db.get_hashed_items().size());
        ASSERT_TRUE(sender_db.has_item(Item(1, 1)));
        ASSERT_TRUE(sender_db.has_item(Item(3, 3)));
        ASSERT_EQ(fewer.get_bin_bundle_count(), sender_db.get_bin_bundle_count());
        for (uint32_t b = 0; b < params->bundle_idx_count(); b++) {
            ASSERT_NO_THROW(static_cast<void>(sender_db.get_cache_at(b)));
        }
        stringstream after_ss;
        sender_db.save(after_ss);
        ASSERT_EQ(
            fewer_bytes.substr(header_size(fewer_bytes)),
            after_ss.str().substr(header_size(after_ss.str())));

        // The items that are there can still be removed
        sender_db.remove(vector<Item>{ Item(1, 1), Item(2, 2) });
        ASSERT_EQ(1, sender_db.get_item_count());
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());
    }

    TEST(SenderDBTests, RemovalOfAMissingItemChangesNothing)
    {
        auto test_fun = [](size_t label_byte_count) {
            auto params = get_params1();
            SenderDB sender_db(*params, label_byte_count);
            Item stored(1, 1);
            if (label_byte_count) {
                sender_db.insert_or_assign({ stored, create_label(1, label_byte_count) });
            } else {
                sender_db.insert_or_assign(stored);
            }
            ASSERT_EQ(size_t(1), sender_db.get_item_count());

            // A batch naming an item that is not in the database is refused before any of its
            // items is removed
            Item missing(2, 2);
            ASSERT_THROW(sender_db.remove(vector<Item>{ stored, missing }), logic_error);
            ASSERT_EQ(size_t(1), sender_db.get_item_count());
            ASSERT_TRUE(sender_db.has_item(stored));
            for (uint32_t b = 0; b < params->bundle_idx_count(); b++) {
                ASSERT_NO_THROW(static_cast<void>(sender_db.get_cache_at(b)));
            }
        };

        test_fun(0);
        test_fun(8);
    }

    TEST(SenderDBTests, RepeatedItemInOneRemovalIsCollapsed)
    {
        auto test_fun = [](size_t label_byte_count) {
            auto params = get_params1();
            SenderDB sender_db(*params, label_byte_count);
            Item a(1, 1);
            Item b(2, 2);
            Item c(3, 3);
            if (label_byte_count) {
                vector<pair<Item, Label>> data;
                data.emplace_back(a, create_label(1, label_byte_count));
                data.emplace_back(b, create_label(2, label_byte_count));
                data.emplace_back(c, create_label(3, label_byte_count));
                sender_db.insert_or_assign(data);
            } else {
                sender_db.insert_or_assign(vector<Item>{ a, b, c });
            }
            ASSERT_EQ(size_t(3), sender_db.get_item_count());

            // Removing an item twice in one batch is the same as removing it once
            ASSERT_NO_THROW(sender_db.remove(vector<Item>{ a, a, b }));
            ASSERT_EQ(size_t(1), sender_db.get_item_count());
            ASSERT_FALSE(sender_db.has_item(a));
            ASSERT_FALSE(sender_db.has_item(b));
            ASSERT_TRUE(sender_db.has_item(c));
        };

        test_fun(0);
        test_fun(8);
    }

    TEST(SenderDBTests, LoadRejectsABufferMissingRequiredFields)
    {
        // A serialized SenderDB carrying params, oprf_key and hashed_items but omitting info.
        // SenderDB::Load reads info unconditionally -- item_count, label_byte_count,
        // nonce_byte_count, compressed and stripped all come from it -- so a buffer that leaves it
        // out would be dereferenced as a null pointer. The schema marks it required so the
        // verifier refuses the buffer before any field is read, and Load checks the same fields
        // again so the guarantee does not rest on the schema alone.
        //
        // The params field must carry a VALID serialized PSIParams: PSIParams::Load runs first,
        // so a garbage blob there would make this test pass without ever reaching the info
        // dereference it exists to cover.
        auto real_params = get_params1();
        stringstream params_ss;
        real_params->save(params_ss);
        string params_str = params_ss.str();
        vector<uint8_t> params_bytes(params_str.cbegin(), params_str.cend());

        flatbuffers::FlatBufferBuilder fbs_builder(1024);

        auto params = fbs_builder.CreateVector(params_bytes);
        auto oprf_key = fbs_builder.CreateVector(vector<uint8_t>(apsi::oprf::oprf_key_size, 0));
        auto hashed_items = fbs_builder.CreateVectorOfStructs(vector<fbs::HashedItem>{});

        // Written through the underlying table API rather than the generated SenderDBBuilder.
        // That builder's Finish() asserts that every required field is present, and the assert
        // is live in Debug builds, so it cannot express a buffer that omits one. These are the
        // same calls it would make, minus those asserts.
        auto table_start = fbs_builder.StartTable();
        fbs_builder.AddOffset(fbs::SenderDB::VT_PARAMS, params);
        fbs_builder.AddOffset(fbs::SenderDB::VT_OPRF_KEY, oprf_key);
        fbs_builder.AddOffset(fbs::SenderDB::VT_HASHED_ITEMS, hashed_items);
        auto sdb = flatbuffers::Offset<fbs::SenderDB>(fbs_builder.EndTable(table_start));
        fbs_builder.FinishSizePrefixed(sdb);

        stringstream ss;
        ss.write(
            reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
            static_cast<streamsize>(fbs_builder.GetSize()));

        ASSERT_THROW((void)SenderDB::Load(ss), runtime_error);
    }

    TEST(SenderDBTests, SaveLoadUnlabeled)
    {
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
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
            items.reserve(200);
            for (uint64_t i = 0; i < 200; i++) {
                items.emplace_back(i, i + 1);
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
            for (const auto &it : sender_db.get_hashed_items()) {
                ASSERT_NE(
                    other_sdb.get_hashed_items().end(), other_sdb.get_hashed_items().find(it));
            }
        };

        test_fun(get_params1());
        test_fun(get_params2());
    }

    TEST(SenderDBTests, SaveLoadLabeled)
    {
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
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
            items.reserve(200);
            for (uint64_t i = 0; i < 200; i++) {
                items.emplace_back(Item(i, i + 1), create_label(static_cast<unsigned char>(i), 20));
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
            for (const auto &it : sender_db.get_hashed_items()) {
                ASSERT_NE(
                    other_sdb.get_hashed_items().end(), other_sdb.get_hashed_items().find(it));
            }
        };

        test_fun(get_params1());
        test_fun(get_params2());
    }

    TEST(SenderDBTests, StripUnlabeled)
    {
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
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
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
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

    TEST(SenderDBTests, PackingRateAndSaveDoNotDeadlockAgainstAWriter)
    {
        // get_packing_rate, save and Sender::RunQuery read the bin bundle count while already
        // holding the SenderDB lock, so each uses the unlocked accessor: the locking one takes
        // the lock a second time on that thread, which blocks once a writer queues between the
        // two acquisitions, and the writer then waits on a reader blocked on itself. A writer
        // runs alongside throughout so that window is available.
        //
        // Only a lock where a queued writer bars new readers can show this, which is libc++,
        // MSVC's SRWLOCK, and the winpthreads rwlock libstdc++ uses on MinGW. On Linux
        // libstdc++ wraps a reader-preferring pthread_rwlock_t on which the second acquisition
        // succeeds, so a pass there says nothing either way.
        //
        // Each thread holds a shared_ptr to everything it touches, so one left running cannot
        // outlive what it uses, and each reports when it leaves its loop.
        struct State {
            shared_ptr<SenderDB> db;
            atomic<bool> stop{ false };
            atomic<bool> done{ false };
            atomic<bool> writer_done{ false };
        };

        auto state = make_shared<State>();
        state->db = make_shared<SenderDB>(*get_params1(), 0);
        state->db->insert_or_assign(Item(0, 0));

        // What the deadlock needs is a writer queued between the two acquisitions, not a large
        // database: get_packing_rate and save read the bin bundle count whatever the contents.
        // Inserting one item and clearing it keeps the database at one item, so each round stays
        // short enough that a Debug build finishes well inside the deadline, while still
        // exercising a bin bundle's own save path.
        thread writer([state] {
            for (uint64_t i = 1; !state->stop; i++) {
                // Yield after each acquisition, not only at the end of the pair: a writer that
                // never yields can starve the reader where a queued writer bars new readers, and
                // yielding only after the clear would leave the reader serializing an empty
                // database nearly every time.
                state->db->insert_or_assign(Item(i, 0));
                this_thread::yield();
                state->db->clear();
                this_thread::yield();
            }
            state->writer_done = true;
        });

        thread reader([state] {
            constexpr int reader_rounds = 300;
            for (int i = 0; i < reader_rounds; i++) {
                state->db->get_packing_rate();
                stringstream ss;
                state->db->save(ss);
            }
            state->done = true;
        });

        auto deadline = chrono::steady_clock::now() + chrono::seconds(60);
        while (!state->done && chrono::steady_clock::now() < deadline) {
            this_thread::sleep_for(chrono::milliseconds(10));
        }

        // Stop the writer before judging the reader. A writer that re-queues immediately can
        // starve a reader outright where a queued writer bars new readers, and a deadline
        // alone cannot tell that from the deadlock this guards: a starved reader finishes
        // within a round or two once the writer stops, while a reader blocked on itself never
        // does, because the writer it queues behind is blocked too and never observes the stop.
        state->stop = true;
        auto drain_deadline = chrono::steady_clock::now() + chrono::seconds(10);
        while ((!state->done || !state->writer_done) &&
               chrono::steady_clock::now() < drain_deadline) {
            this_thread::sleep_for(chrono::milliseconds(10));
        }

        // Join the threads that left their loops, which is what guarantees neither is inside
        // the SenderDB once the process starts destroying its globals; a flag alone only says
        // the loop was left. A thread still wedged is detached so a deadlock fails the test
        // rather than hanging the binary. Both are resolved before the assertion, because a
        // failing ASSERT returns and would destroy a joinable thread.
        const bool reader_finished = state->done.load();
        const bool writer_finished = state->writer_done.load();
        if (writer_finished) {
            writer.join();
        } else {
            writer.detach();
        }
        if (reader_finished) {
            reader.join();
        } else {
            reader.detach();
        }

        // Both must have stopped: a run that leaves the writer going has a thread loose in the
        // SenderDB, whatever the reader did.
        ASSERT_TRUE(reader_finished)
            << "get_packing_rate or save deadlocked against a concurrent writer";
        ASSERT_TRUE(writer_finished) << "the writer never stopped";
    }

    TEST(SenderDBTests, KeyConsumersAreSafeAgainstAConcurrentStrip)
    {
        // strip() moves out of oprf_key_ and then replaces it, both under the writer lock. A key
        // consumer that reads oprf_key_ before taking its own lock can therefore observe the
        // moved-from key, whose key_span() is a span of 32 bytes over a null pointer. That span
        // violates gsl::span's precondition, so the process aborts on a thread pool worker.
        // Every consumer must read the key under the lock, so each call either completes
        // normally or reports the stripped database.
        //
        // The window between the move and the replacement is a few instructions wide, so a single
        // round is very unlikely to land in it. Many rounds are run, each with readers already
        // hammering the key when the strip begins.
        //
        // A reader stops on the strip or on its own deadline, whichever comes first. The deadline
        // is what guarantees termination: where a queued writer does not bar new readers, as with
        // libstdc++'s reader-preferring pthread_rwlock_t, readers waiting only for the strip
        // starve it indefinitely. The sleep is what lets the strip land while calls are still in
        // flight; a yield is not enough, because four readers cycling through one leave no gap.
        constexpr int round_count = 50;
        constexpr int reader_count = 4;
        constexpr auto reader_time_limit = chrono::milliseconds(250);

        // A call refused because the database is stripped is one that took the lock after the
        // strip committed, so a round that records none had no reader still looping by the time
        // the strip got the lock. That is a liveness check on the test itself, not proof that a
        // call was in flight when the strip began: every assertion above passes trivially on a
        // run where the readers finish first, so without this the test can quietly stop covering
        // anything.
        atomic<int> refusals{ 0 };
        int rounds_with_refusal = 0;

        for (int round = 0; round < round_count; round++) {
            // A labeled database so that get_label is exercised alongside has_item; both read
            // the key before looking the item up.
            auto db = make_shared<SenderDB>(*get_params1(), 20);
            Label original_label = create_label(7, 20);
            db->insert_or_assign(make_pair(Item(0, 0), original_label));
            auto original_key = db->get_oprf_key();

            atomic<bool> start{ false };
            atomic<bool> strip_pending{ false };
            atomic<bool> stripped{ false };
            atomic<int> readers_running{ 0 };
            const int refusals_before_round = refusals.load();
            atomic<bool> saw_missing_item{ false };
            atomic<bool> saw_wrong_key{ false };
            atomic<bool> saw_missing_label{ false };
            atomic<bool> saw_wrong_label{ false };

            vector<thread> readers;
            readers.reserve(reader_count);
            for (int i = 0; i < reader_count; i++) {
                readers.emplace_back([&] {
                    readers_running++;
                    while (!start) {
                        this_thread::yield();
                    }
                    auto reader_deadline = chrono::steady_clock::now() + reader_time_limit;
                    while (!stripped && chrono::steady_clock::now() < reader_deadline) {
                        // The item is in the database until strip() removes it, and strip()
                        // removes it under the same lock that makes the database report itself
                        // stripped. A reader therefore either finds the item or is refused;
                        // reporting the item absent means it looked in a database that the key
                        // it hashed with no longer describes.
                        try {
                            if (!db->has_item(Item(0, 0))) {
                                saw_missing_item = true;
                            }
                        } catch (const logic_error &) {
                            refusals++;
                        }

                        // Likewise the key is either the one the database was built with, or the
                        // database refuses to hand it over.
                        try {
                            if (!(db->get_oprf_key() == original_key)) {
                                saw_wrong_key = true;
                            }
                        } catch (const logic_error &) {
                            refusals++;
                        }

                        // get_label answers for the same item, so it is subject to the same rule:
                        // the stored label, or a refusal. Reporting the item absent means the
                        // lookup ran against a database the key it hashed with does not describe.
                        // invalid_argument derives from logic_error, so it is caught first.
                        try {
                            if (db->get_label(Item(0, 0)) != original_label) {
                                saw_wrong_label = true;
                            }
                        } catch (const invalid_argument &) {
                            saw_missing_label = true;
                        } catch (const logic_error &) {
                            refusals++;
                        }

                        // Leave the lock free between calls so the strip can land while the
                        // readers are still looping. Where a queued writer does not bar new
                        // readers the writer only gets in when every reader happens to be out of
                        // the lock at once, which a short sleep makes rare and a slow build makes
                        // rarer still, so back off once the strip is known to be waiting.
                        this_thread::sleep_for(
                            strip_pending ? chrono::microseconds(1000) : chrono::microseconds(50));
                    }
                });
            }

            // Release the readers first and let them get into the key before stripping, so the
            // strip lands while calls are in flight rather than before any have started.
            while (readers_running < reader_count) {
                this_thread::yield();
            }
            start = true;
            this_thread::sleep_for(chrono::microseconds(200));

            strip_pending = true;
            db->strip();
            stripped = true;

            for (auto &reader : readers) {
                reader.join();
            }

            ASSERT_FALSE(saw_missing_item.load())
                << "has_item reported an item absent that was in the database";
            ASSERT_FALSE(saw_wrong_key.load())
                << "get_oprf_key returned a key other than the database's";
            ASSERT_FALSE(saw_missing_label.load())
                << "get_label reported an item absent that was in the database";
            ASSERT_FALSE(saw_wrong_label.load())
                << "get_label returned a label other than the stored one";
            ASSERT_TRUE(db->is_stripped());
            ASSERT_THROW(db->get_oprf_key(), logic_error);
            if (refusals.load() > refusals_before_round) {
                rounds_with_refusal++;
            }
        }

        ASSERT_LT(0, rounds_with_refusal)
            << "no round had a reader still looping when the strip took the lock, so the readers "
               "always finished first and this test covered nothing";
    }
    TEST(SenderDBTests, Log2FppAccountsForBinBundleMultiplicity)
    {
        // PSIParams::log2_fpp_per_bin_bundle describes one bin bundle. A location holding more
        // items than max_items_per_bin spills into further bundles at the same index, each with its
        // own matching polynomial, and a match from any of them is reported, so the probability the
        // database exhibits is higher than the parameters alone suggest.
        auto params = *get_params2();
        SenderDB sender_db(params, 0);

        // Empty: nothing has spilled, so there is nothing to add.
        ASSERT_EQ(params.log2_fpp_per_bin_bundle(), sender_db.log2_fpp(1));

        vector<Item> items;
        items.reserve(500);
        for (uint64_t i = 0; i < 500; i++) {
            items.emplace_back(i + 1, i + 1);
        }
        sender_db.insert_or_assign(items);

        size_t max_bundles = 0;
        for (uint32_t b = 0; b < params.bundle_idx_count(); b++) {
            max_bundles = max(max_bundles, sender_db.get_bin_bundle_count(b));
        }
        ASSERT_LT(size_t(0), max_bundles);

        ASSERT_DOUBLE_EQ(
            params.log2_fpp_per_bin_bundle() + log2(static_cast<double>(max_bundles)),
            sender_db.log2_fpp(1));

        // The query size is the caller's to supply, and cannot be left out.
        ASSERT_DOUBLE_EQ(sender_db.log2_fpp(1) + 10.0, sender_db.log2_fpp(1024));
        ASSERT_THROW(static_cast<void>(sender_db.log2_fpp(0)), invalid_argument);

        // Never optimistic: the database figure is at least the single-bundle one.
        ASSERT_LE(params.log2_fpp_per_bin_bundle(), sender_db.log2_fpp(1));
    }

    namespace {
        apsi::util::felt_t evaluate_polyn(
            const FEltPolyn &polyn, apsi::util::felt_t x, const Modulus &mod)
        {
            apsi::util::felt_t result = 0;
            for (size_t i = polyn.size(); i-- > 0;) {
                result = seal::util::multiply_uint_mod(result, x, mod);
                result = seal::util::add_uint_mod(result, polyn[i], mod);
            }
            return result;
        }

        /**
        Computes the locations of a HashedItem as a SenderDB with the given parameters does, as
        pairs of a bundle index and the first bin of the location in that bundle.
        */
        vector<pair<uint32_t, size_t>> places_of(
            const HashedItem &hashed_item, const PSIParams &params)
        {
            kuku::item_type kuku_item;
            memcpy(&kuku_item, hashed_item.value().data(), sizeof(kuku_item));

            set<uint32_t> locations;
            for (uint32_t i = 0; i < params.table_params().hash_func_count; i++) {
                kuku::LocFunc hash_func(params.table_params().table_size, kuku::make_item(i, 0));
                locations.insert(hash_func(kuku_item));
            }

            vector<pair<uint32_t, size_t>> places;
            for (uint32_t location : locations) {
                places.emplace_back(
                    location / params.items_per_bundle(),
                    (location % params.items_per_bundle()) * params.item_params().felts_per_item);
            }
            return places;
        }

        /**
        Returns the SenderDB that sender_db would be if it also held the bin bundles of others,
        after its own: what an older version of APSI could leave behind when it stored an item a
        second time on updating the item's label. The others must have been built with the same
        parameters and OPRF key, and hold only items sender_db holds.
        */
        SenderDB with_extra_bin_bundles(
            const SenderDB &sender_db, const vector<const SenderDB *> &others)
        {
            // A saved SenderDB is a size-prefixed header followed by the bin bundles
            auto saved = [](const SenderDB &db) {
                stringstream ss;
                db.save(ss);
                return ss.str();
            };
            auto header_size = [](const string &bytes) {
                uint32_t size = 0;
                memcpy(&size, bytes.data(), sizeof(size));
                return sizeof(size) + size;
            };

            string bytes = saved(sender_db);
            const auto *header = fbs::GetSizePrefixedSenderDB(bytes.data());
            uint32_t bin_bundle_count = header->bin_bundle_count();
            string bin_bundles = bytes.substr(header_size(bytes));
            for (const SenderDB *other : others) {
                string other_bytes = saved(*other);
                bin_bundle_count +=
                    fbs::GetSizePrefixedSenderDB(other_bytes.data())->bin_bundle_count();
                bin_bundles += other_bytes.substr(header_size(other_bytes));
            }

            // The same header, counting the bin bundles appended
            flatbuffers::FlatBufferBuilder builder(1024);
            auto params = builder.CreateVector(header->params()->data(), header->params()->size());
            auto oprf_key =
                builder.CreateVector(header->oprf_key()->data(), header->oprf_key()->size());
            vector<fbs::HashedItem> hashed_items;
            for (const auto *hashed_item : *header->hashed_items()) {
                hashed_items.push_back(*hashed_item);
            }
            auto hashed_items_vec = builder.CreateVectorOfStructs(hashed_items);
            fbs::SenderDBBuilder sender_db_builder(builder);
            sender_db_builder.add_params(params);
            sender_db_builder.add_info(header->info());
            sender_db_builder.add_oprf_key(oprf_key);
            sender_db_builder.add_hashed_items(hashed_items_vec);
            sender_db_builder.add_bin_bundle_count(bin_bundle_count);
            builder.FinishSizePrefixed(sender_db_builder.Finish());

            stringstream ss;
            ss.write(
                reinterpret_cast<const char *>(builder.GetBufferPointer()),
                static_cast<streamsize>(builder.GetSize()));
            ss << bin_bundles;
            return SenderDB::Load(ss).first;
        }

        /**
        Returns, for each location of the item, the label of every copy of it the SenderDB stores
        there, in sorted order: the label decrypted from the label polynomials of each bin bundle
        that holds the item, as a query matching that bin bundle would give it. Unlike get_label,
        which reads one copy, this sees every copy.
        */
        vector<vector<Label>> stored_labels(
            SenderDB &sender_db, const Item &item, const oprf::OPRFKey &key)
        {
            const PSIParams &params = sender_db.get_params();
            const Modulus &mod = params.seal_params().plain_modulus();
            size_t felts_per_item = params.item_params().felts_per_item;

            auto [hashed_item, label_key] = oprf::OPRFSender::GetItemHash(item, key);
            vector<apsi::util::felt_t> felts =
                apsi::util::algebraize_item(hashed_item, params.item_bit_count(), mod);

            vector<vector<Label>> labels;
            for (const auto &place : places_of(hashed_item, params)) {
                labels.emplace_back();
                for (const BinBundleCache &cache : sender_db.get_cache_at(place.first)) {
                    // Whether this bin bundle holds the item: its matching polynomials vanish at
                    // the item's field elements
                    bool holds = true;
                    for (size_t s = 0; holds && (s < felts_per_item); s++) {
                        size_t bin = place.second + s;
                        holds = evaluate_polyn(cache.felt_matching_polyns[bin], felts[s], mod) == 0;
                    }
                    if (!holds) {
                        continue;
                    }

                    // The label parts in the item's slots, part by part, as a receiver collects
                    // them
                    apsi::util::AlgLabel alg_label;
                    size_t part_count = cache.felt_interp_polyns.size();
                    for (size_t p = 0; p < part_count; p++) {
                        for (size_t s = 0; s < felts_per_item; s++) {
                            alg_label.push_back(evaluate_polyn(
                                cache.felt_interp_polyns[p][place.second + s], felts[s], mod));
                        }
                    }
                    EncryptedLabel encrypted_label = apsi::util::dealgebraize_label(
                        alg_label, part_count * params.item_bit_count(), mod);
                    encrypted_label.resize(
                        sender_db.get_nonce_byte_count() + sender_db.get_label_byte_count());
                    labels.back().push_back(
                        apsi::util::decrypt_label(
                            encrypted_label, label_key, sender_db.get_nonce_byte_count()));
                }
                sort(labels.back().begin(), labels.back().end());
            }
            return labels;
        }

        /**
        Queries the SenderDB for the given items through the whole protocol, and returns for each
        item, in sorted order, the label of every match a result package gives it. The packages
        are processed one by one, so this sees every copy of an item the query reaches, where
        process_result would keep only the first match.
        */
        vector<vector<Label>> query_labels(
            const shared_ptr<SenderDB> &sender_db,
            const oprf::OPRFKey &key,
            const vector<Item> &items)
        {
            vector<HashedItem> hashed_items;
            LabelKeyVector label_keys;
            for (const auto &item : items) {
                auto [hashed_item, label_key] = oprf::OPRFSender::GetItemHash(item, key);
                hashed_items.push_back(hashed_item);
                label_keys.push_back(label_key);
            }

            apsi::receiver::Receiver recv(sender_db->get_params());
            auto [request, itt] = recv.create_query(hashed_items);

            stringstream ss;
            network::StreamChannel chl(ss);
            chl.send(std::move(request));
            Query query(
                to_query_request(chl.receive_operation(sender_db->get_seal_context())), sender_db);
            Sender::RunQuery(query, chl);

            QueryResponse query_response = to_query_response(chl.receive_response());
            vector<vector<Label>> labels(items.size());
            for (uint32_t i = 0; i < query_response->package_count; i++) {
                ResultPart result_part = chl.receive_result(recv.get_seal_context());
                vector<apsi::receiver::MatchRecord> mrs =
                    recv.process_result_part(label_keys, itt, result_part);
                for (size_t j = 0; j < mrs.size(); j++) {
                    if (mrs[j].found) {
                        labels[j].push_back(mrs[j].label.value());
                    }
                }
            }
            for (auto &item_labels : labels) {
                sort(item_labels.begin(), item_labels.end());
            }
            return labels;
        }

        /**
        Collects the warnings logged while it exists, and restores the global logger and log
        level when it is destroyed.
        */
        class WarningCapture {
        public:
            WarningCapture() : saved_level_(GetLogLevel())
            {
                array<Logger::log_handler_t, Logger::level_count> log_handlers{};
                log_handlers[static_cast<size_t>(LogLevel::warning)] = [this](const string &msg) {
                    warnings_.push_back(msg);
                };
                SetLogger(Logger::Create(std::move(log_handlers), {}, {}));
                SetLogLevel(LogLevel::warning);
            }

            ~WarningCapture()
            {
                CloseLogger();
                SetLogLevel(saved_level_);
            }

            WarningCapture(const WarningCapture &) = delete;

            WarningCapture &operator=(const WarningCapture &) = delete;

            /**
            Returns how many of the warnings contain the given text.
            */
            size_t count(const string &text) const
            {
                return static_cast<size_t>(
                    count_if(warnings_.begin(), warnings_.end(), [&](const string &warning) {
                        return warning.find(text) != string::npos;
                    }));
            }

        private:
            LogLevel saved_level_;

            vector<string> warnings_;
        };
    } // namespace

    TEST(SenderDBTests, OverwriteChangesEveryCopyOfAnItemStoredMoreThanOnce)
    {
        // An older version of APSI could store an item a second time when it updated the item's
        // label (see OverwriteChangesTheItemWhereItIsStored), leaving the copy with the old label
        // in an older bin bundle to answer queries. Such a database is put together here: the bin
        // bundles of two more databases, built with the same key and holding some of the same
        // items with other labels, are appended to those of a first one. Updating one of these
        // items must change every copy, so that every copy a query can match gives the new label,
        // and must warn, naming how many copies there are. Removing the item drops every copy.
        auto test_fun = [](const PSIParams &params) {
            oprf::OPRFKey key = fixed_oprf_key();
            constexpr size_t label_byte_count = 20;
            unsigned char next_label = 0;
            auto make_data = [&](uint64_t count) {
                vector<pair<Item, Label>> data;
                for (uint64_t i = 0; i < count; i++) {
                    data.emplace_back(Item(i, ~i), create_label(next_label++, label_byte_count));
                }
                return data;
            };

            // Items 0 to 4 end up stored three times, items 5 to 9 twice, and the rest once
            vector<pair<Item, Label>> first = make_data(100);
            vector<pair<Item, Label>> second = make_data(10);
            vector<pair<Item, Label>> third = make_data(5);
            SenderDB first_db(params, key, label_byte_count, 16, true);
            first_db.set_data(first);
            SenderDB second_db(params, key, label_byte_count, 16, true);
            second_db.set_data(second);
            SenderDB third_db(params, key, label_byte_count, 16, true);
            third_db.set_data(third);
            auto sender_db =
                make_shared<SenderDB>(with_extra_bin_bundles(first_db, { &second_db, &third_db }));
            size_t bin_bundle_count = sender_db->get_bin_bundle_count();
            ASSERT_EQ(
                first_db.get_bin_bundle_count() + second_db.get_bin_bundle_count() +
                    third_db.get_bin_bundle_count(),
                bin_bundle_count);
            ASSERT_EQ(first.size(), sender_db->get_item_count());

            // The labels of the copies of an item, as they were stored
            auto labels_of = [&](size_t i) {
                vector<Label> labels{ first[i].second };
                if (i < second.size()) {
                    labels.push_back(second[i].second);
                }
                if (i < third.size()) {
                    labels.push_back(third[i].second);
                }
                sort(labels.begin(), labels.end());
                return labels;
            };

            // Every location of each of the first 15 items holds its copies, each with its own
            // label, and a query matches every one of them
            constexpr size_t checked = 15;
            vector<Item> items;
            array<size_t, 4> locations_by_copy_count{};
            for (size_t i = 0; i < checked; i++) {
                items.push_back(first[i].first);
                vector<vector<Label>> stored = stored_labels(*sender_db, items[i], key);
                ASSERT_FALSE(stored.empty());
                for (const auto &at_location : stored) {
                    ASSERT_EQ(labels_of(i), at_location) << "item " << i;
                }
                locations_by_copy_count[labels_of(i).size()] += stored.size();
            }
            vector<vector<Label>> queried = query_labels(sender_db, key, items);
            for (size_t i = 0; i < checked; i++) {
                ASSERT_EQ(labels_of(i), queried[i]) << "item " << i;
            }

            // Updating them overwrites every copy, and warns once for each location of an item
            // stored more than once
            vector<pair<Item, Label>> update = make_data(checked);
            {
                WarningCapture capture;
                ASSERT_NO_THROW(sender_db->insert_or_assign(update));
                ASSERT_EQ(locations_by_copy_count[3], capture.count("overwriting all 3 copies"));
                ASSERT_EQ(locations_by_copy_count[2], capture.count("overwriting all 2 copies"));
                ASSERT_EQ(
                    locations_by_copy_count[2] + locations_by_copy_count[3],
                    capture.count(
                        "Removing the item and inserting it again drops the extra copies"));
            }
            ASSERT_EQ(first.size(), sender_db->get_item_count());
            ASSERT_EQ(bin_bundle_count, sender_db->get_bin_bundle_count());

            for (size_t i = 0; i < checked; i++) {
                vector<Label> expected(labels_of(i).size(), update[i].second);
                for (const auto &at_location : stored_labels(*sender_db, items[i], key)) {
                    ASSERT_EQ(expected, at_location) << "item " << i;
                }
                ASSERT_EQ(update[i].second, sender_db->get_label(items[i])) << "item " << i;
            }

            queried = query_labels(sender_db, key, items);
            for (size_t i = 0; i < checked; i++) {
                ASSERT_EQ(vector<Label>(labels_of(i).size(), update[i].second), queried[i])
                    << "item " << i;
            }

            for (size_t i = checked; i < first.size(); i += 7) {
                ASSERT_EQ(first[i].second, sender_db->get_label(first[i].first)) << "item " << i;
            }

            // Removing the items stored more than once drops every copy, and inserting them again
            // stores one, which a later update finds without a warning
            vector<Item> removed(
                items.begin(), items.begin() + static_cast<ptrdiff_t>(second.size()));
            sender_db->remove(removed);
            ASSERT_GE(first_db.get_bin_bundle_count(), sender_db->get_bin_bundle_count());
            for (const auto &item : removed) {
                ASSERT_FALSE(sender_db->has_item(item));
                for (const auto &at_location : stored_labels(*sender_db, item, key)) {
                    ASSERT_TRUE(at_location.empty());
                }
            }
            vector<pair<Item, Label>> reinserted = make_data(second.size());
            sender_db->insert_or_assign(reinserted);
            ASSERT_EQ(first.size(), sender_db->get_item_count());
            vector<pair<Item, Label>> last_update = make_data(checked);
            {
                WarningCapture capture;
                sender_db->insert_or_assign(last_update);
                ASSERT_EQ(0, capture.count("copies of an item"));
            }
            for (size_t i = 0; i < checked; i++) {
                for (const auto &at_location : stored_labels(*sender_db, items[i], key)) {
                    ASSERT_EQ(vector<Label>{ last_update[i].second }, at_location) << "item " << i;
                }
                ASSERT_EQ(last_update[i].second, sender_db->get_label(items[i]));
            }
        };

        test_fun(with_shallow_bins(*get_params1(), 3));
    }
} // namespace APSITests
