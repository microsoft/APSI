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
#include <map>
#include <memory>
#include <numeric>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <tuple>
#include <unordered_map>

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
#include "apsi/util/match_tag.h"

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

    namespace {
        /**
        Returns the size of the size-prefixed buffer at the given offset of saved, including the
        size prefix.
        */
        size_t prefixed_size_at(const string &saved, size_t offset)
        {
            uint32_t size = 0;
            memcpy(&size, saved.data() + offset, sizeof(size));
            return sizeof(size) + size;
        }

        /**
        Returns the header of a saved SenderDB, rebuilt to declare the given number of bin
        bundles.
        */
        string header_declaring(const string &saved, uint32_t bin_bundle_count)
        {
            const auto *header = fbs::GetSizePrefixedSenderDB(saved.data());

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

            return { reinterpret_cast<const char *>(builder.GetBufferPointer()),
                     builder.GetSize() };
        }

        /**
        Returns the message of the std::runtime_error SenderDB::Load throws for the given data, or
        an empty string if it throws none.
        */
        string load_error(const string &data)
        {
            stringstream ss(data);
            try {
                (void)SenderDB::Load(ss);
            } catch (const runtime_error &ex) {
                return ex.what();
            }
            return {};
        }
    } // namespace

    TEST(SenderDBTests, LoadRefusesTruncatedData)
    {
        // A saved SenderDB is a size-prefixed header followed by a size-prefixed buffer for each
        // bin bundle. Cut short anywhere, it must be refused, and at the point where it was cut
        // rather than after reading on for the bin bundles it still declares.
        PSIParams params = with_shallow_bins(*get_params1(), 3);
        SenderDB sender_db(params, fixed_oprf_key(), 20, 16, true);
        for (uint64_t val = 0; sender_db.get_bin_bundle_count() < 2; val++) {
            sender_db.insert_or_assign(
                { Item(val, ~val), create_label(static_cast<unsigned char>(val), 20) });
        }

        stringstream ss;
        sender_db.save(ss);
        string saved = ss.str();
        ASSERT_EQ(string(), load_error(saved));

        size_t header_end = prefixed_size_at(saved, 0);
        size_t first_bin_bundle_end = header_end + prefixed_size_at(saved, header_end);
        ASSERT_LT(first_bin_bundle_end, saved.size());

        // Inside the header: in its size prefix, and after it
        vector<size_t> header_cuts{ 0, 1, 3, 4, header_end - 1 };
        for (size_t cut : header_cuts) {
            SCOPED_TRACE(cut);
            ASSERT_EQ(size_t(0), load_error(saved.substr(0, cut)).find("read_from_stream: "));
        }

        // After the header, which declares how many bin bundles follow: right after it, in the
        // size prefix of the first bin bundle and right after it, inside the first bin bundle,
        // between the first two, and inside the last one
        for (size_t cut : { header_end,
                            header_end + 1,
                            header_end + 2,
                            header_end + 3,
                            header_end + 4,
                            (header_end + first_bin_bundle_end) / 2,
                            first_bin_bundle_end,
                            saved.size() - 1 }) {
            SCOPED_TRACE(cut);
            ASSERT_EQ(
                string("failed to load SenderDB: the data is truncated"),
                load_error(saved.substr(0, cut)));
        }
    }

    TEST(SenderDBTests, LoadRefusesDataEndingBeforeTheBinBundlesItDeclares)
    {
        // A header declaring as many bin bundles as Load accepts for its parameters, over a
        // million, with nothing after it. Load must not set memory aside for bin bundles that are
        // not there, nor go on reading once the first is missing.
        PSIParams::TableParams table_params = get_params1()->table_params();
        table_params.table_size = 16 * get_params1()->items_per_bundle();
        PSIParams params(
            get_params1()->item_params(),
            table_params,
            get_params1()->query_params(),
            get_params1()->seal_params());
        ASSERT_EQ(uint32_t(16), params.bundle_idx_count());

        SenderDB sender_db(params, 0);
        stringstream ss;
        sender_db.save(ss);
        uint32_t declared = params.bundle_idx_count() * 65536;

        auto start = chrono::steady_clock::now();
        ASSERT_EQ(
            string("failed to load SenderDB: the data is truncated"),
            load_error(header_declaring(ss.str(), declared)));

        // The bound is loose on purpose: it only catches a pathological regression, not a slow
        // machine
        ASSERT_LT(chrono::steady_clock::now() - start, 30s);

        // One more is more than Load accepts, and is refused before any bin bundle is read
        ASSERT_EQ(
            string("failed to load SenderDB"),
            load_error(header_declaring(ss.str(), declared + 1)));
    }

    TEST(SenderDBTests, LoadRefusesABinBundleSizeLargerThanAnyBuffer)
    {
        // A size prefix that no buffer can have is refused as it is read, like a truncated one,
        // but the data is not reported as truncated
        SenderDB sender_db(*get_params1(), 0);
        stringstream ss;
        sender_db.save(ss);
        string data = header_declaring(ss.str(), 1) + string(sizeof(uint32_t), '\xFF');

        ASSERT_EQ(string("failed to load SenderDB"), load_error(data));
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
        /**
        Parameters with match tags. The table holds bundle_idx_count bundle indices.
        */
        PSIParams create_tag_params(
            uint32_t felts_per_item,
            uint32_t tag_part_count,
            uint32_t hash_func_count,
            uint32_t max_items_per_bin,
            size_t poly_modulus_degree,
            uint64_t plain_modulus,
            uint32_t bundle_idx_count = 1)
        {
            PSIParams::ItemParams item_params;
            item_params.felts_per_item = felts_per_item;
            item_params.tag_part_count = tag_part_count;

            PSIParams::TableParams table_params;
            table_params.hash_func_count = hash_func_count;
            table_params.max_items_per_bin = max_items_per_bin;
            table_params.table_size =
                static_cast<uint32_t>(poly_modulus_degree / felts_per_item) * bundle_idx_count;

            PSIParams::QueryParams query_params;
            query_params.query_powers = { 1 };
            if (max_items_per_bin >= 3) {
                query_params.query_powers.insert(3);
            }

            PSIParams::SEALParams seal_params;
            seal_params.set_poly_modulus_degree(poly_modulus_degree);
            seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
            seal_params.set_plain_modulus(plain_modulus);

            return PSIParams(item_params, table_params, query_params, seal_params);
        }

        /**
        Parameters with match tags of 48 bits, and 16 bits per item, over two bundle indices.
        */
        PSIParams create_tag_params()
        {
            return create_tag_params(1, 3, 3, 8, 4096, 65537, 2);
        }

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
        What a test needs to know of an item stored with match tags: its HashedItem, its field
        elements and its tag, and, for each of its locations, the bundle index and the first bin
        of the location.
        */
        struct TaggedItemView {
            HashedItem hashed_item;

            vector<apsi::util::felt_t> felts;

            vector<apsi::util::felt_t> tag;

            vector<pair<uint32_t, size_t>> places;
        };

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
        Computes what a SenderDB with the given OPRF key and parameters stores of an item,
        independently of the SenderDB: the tag comes from the item's label key, which is what
        the receiver computes it from too.
        */
        TaggedItemView view_of(const Item &item, const oprf::OPRFKey &key, const PSIParams &params)
        {
            auto [hashed_item, label_key] = oprf::OPRFSender::GetItemHash(item, key);

            TaggedItemView view;
            view.hashed_item = hashed_item;
            view.felts = apsi::util::algebraize_item(
                hashed_item, params.item_bit_count(), params.seal_params().plain_modulus());
            view.tag = apsi::util::compute_match_tag(
                label_key,
                params.tag_part_count() * params.item_params().felts_per_item,
                params.item_bit_count_per_felt());
            view.places = places_of(hashed_item, params);
            return view;
        }

        /**
        Returns, for each location of the item, how many bin bundles there hold its tag where a
        query for the item looks for it: how many give the tag's values for the item's field
        elements in their tag polynomials. A stored item is held by exactly one bin bundle at
        each of its locations, and a removed item by none, except with probability 2^-48 or less
        per bin bundle.
        */
        vector<size_t> tag_holders(SenderDB &sender_db, const TaggedItemView &view)
        {
            const PSIParams &params = sender_db.get_params();
            const Modulus &mod = params.seal_params().plain_modulus();
            size_t felts_per_item = params.item_params().felts_per_item;

            vector<size_t> holders;
            for (const auto &place : view.places) {
                size_t count = 0;
                for (const BinBundleCache &cache : sender_db.get_cache_at(place.first)) {
                    bool holds = true;
                    for (size_t p = 0; holds && (p < params.tag_part_count()); p++) {
                        for (size_t s = 0; holds && (s < felts_per_item); s++) {
                            const FEltPolyn &polyn = cache.felt_interp_polyns[p][place.second + s];
                            holds = evaluate_polyn(polyn, view.felts[s], mod) ==
                                    view.tag[(p * felts_per_item) + s];
                        }
                    }
                    count += holds ? 1 : 0;
                }
                holders.push_back(count);
            }
            return holders;
        }

        vector<size_t> held_once(const TaggedItemView &view)
        {
            return vector<size_t>(view.places.size(), 1);
        }

        vector<size_t> not_held(const TaggedItemView &view)
        {
            return vector<size_t>(view.places.size(), 0);
        }

        /**
        Finds groups of items that share their place, their bin and their field element, among
        the items Item(i, 0x5eed) for i from 1 to candidate_count, for parameters with a single
        hash function and a single field element per item.
        */
        vector<vector<Item>> find_items_sharing_places(
            const PSIParams &params, const oprf::OPRFKey &key, uint64_t candidate_count)
        {
            vector<Item> candidates;
            candidates.reserve(candidate_count);
            for (uint64_t i = 1; i <= candidate_count; i++) {
                candidates.emplace_back(i, 0x5eed);
            }
            vector<HashedItem> hashed_items = oprf::OPRFSender::ComputeHashes(candidates, key);

            map<tuple<uint32_t, size_t, apsi::util::felt_t>, vector<size_t>> by_place;
            for (size_t i = 0; i < candidates.size(); i++) {
                auto place = places_of(hashed_items[i], params).front();
                apsi::util::felt_t felt = apsi::util::algebraize_item(
                    hashed_items[i],
                    params.item_bit_count(),
                    params.seal_params().plain_modulus())[0];
                by_place[make_tuple(place.first, place.second, felt)].push_back(i);
            }

            vector<vector<Item>> groups;
            for (const auto &entry : by_place) {
                if (entry.second.size() > 1) {
                    groups.emplace_back();
                    for (size_t i : entry.second) {
                        groups.back().push_back(candidates[i]);
                    }
                }
            }
            return groups;
        }
    } // namespace

    TEST(SenderDBTagTests, TagPartsPrecedeTheNonceAndLabel)
    {
        PSIParams params = create_tag_params();

        // Without labels there is nothing to encrypt, and no nonce, whatever is asked for
        SenderDB unlabeled(params, 0, 16);
        ASSERT_FALSE(unlabeled.is_labeled());
        ASSERT_EQ(0, unlabeled.get_nonce_byte_count());

        // With labels the nonce is as given, as without match tags
        SenderDB labeled(params, 10, 16);
        ASSERT_TRUE(labeled.is_labeled());
        ASSERT_EQ(16, labeled.get_nonce_byte_count());
        SenderDB labeled_no_nonce(params, 10, 0);
        ASSERT_EQ(0, labeled_no_nonce.get_nonce_byte_count());
        ASSERT_THROW(SenderDB(params, 10, max_nonce_byte_count + 1), invalid_argument);

        // And so it is saved
        for (SenderDB *sender_db : { &unlabeled, &labeled, &labeled_no_nonce }) {
            stringstream ss;
            sender_db->save(ss);
            SenderDB loaded = SenderDB::Load(ss).first;
            ASSERT_EQ(sender_db->get_nonce_byte_count(), loaded.get_nonce_byte_count());
            ASSERT_EQ(sender_db->get_label_byte_count(), loaded.get_label_byte_count());
            ASSERT_TRUE(loaded.get_params().uses_tags());
        }

        // A BinBundle holds the tag parts, followed by the parts of the encrypted label, if any:
        // 26 bytes of nonce and label make 13 parts of 16 bits
        unlabeled.insert_or_assign(Item(1, 1));
        labeled.insert_or_assign(make_pair(Item(1, 1), create_label(1, 10)));
        for (auto [sender_db, label_size] :
             { make_pair(&unlabeled, size_t(3)), make_pair(&labeled, size_t(3 + 13)) }) {
            ASSERT_LT(0, sender_db->get_bin_bundle_count());
            for (uint32_t b = 0; b < params.bundle_idx_count(); b++) {
                for (const BinBundleCache &cache : sender_db->get_cache_at(b)) {
                    ASSERT_TRUE(cache.felt_matching_polyns.empty());
                    ASSERT_FALSE(cache.batched_matching_polyn);
                    ASSERT_EQ(label_size, cache.felt_interp_polyns.size());
                    ASSERT_EQ(label_size, cache.batched_interp_polyns.size());
                }
            }
        }
    }

    TEST(SenderDBTagTests, UnlabeledBasics)
    {
        PSIParams params = create_tag_params();
        oprf::OPRFKey key = fixed_oprf_key();
        SenderDB sender_db(params, key, 0, 16, true);

        vector<Item> items;
        for (uint64_t i = 0; i < 100; i++) {
            items.emplace_back(i + 1, ~i);
        }
        sender_db.insert_or_assign(items);
        ASSERT_EQ(items.size(), sender_db.get_item_count());
        size_t bin_bundle_count = sender_db.get_bin_bundle_count();
        for (const auto &item : items) {
            ASSERT_TRUE(sender_db.has_item(item));
            TaggedItemView view = view_of(item, key, params);
            ASSERT_EQ(held_once(view), tag_holders(sender_db, view));
        }

        // There are no labels
        ASSERT_THROW(static_cast<void>(sender_db.get_label(items[0])), logic_error);
        ASSERT_THROW(
            sender_db.insert_or_assign(make_pair(items[0], create_label(0, 1))), logic_error);

        // Inserting items that are there already, or the same item twice, changes nothing
        sender_db.insert_or_assign(vector<Item>{ items[0], items[1], items[1] });
        ASSERT_EQ(items.size(), sender_db.get_item_count());
        ASSERT_EQ(bin_bundle_count, sender_db.get_bin_bundle_count());
        for (size_t i = 0; i < 2; i++) {
            TaggedItemView view = view_of(items[i], key, params);
            ASSERT_EQ(held_once(view), tag_holders(sender_db, view));
        }

        // Removing takes exactly the items removed
        ASSERT_THROW(sender_db.remove(Item(1000, 1000)), logic_error);
        ASSERT_EQ(items.size(), sender_db.get_item_count());
        vector<Item> removed(items.begin(), items.begin() + 50);
        sender_db.remove(removed);
        ASSERT_EQ(items.size() - removed.size(), sender_db.get_item_count());
        for (size_t i = 0; i < items.size(); i++) {
            TaggedItemView view = view_of(items[i], key, params);
            ASSERT_EQ(i >= removed.size(), sender_db.has_item(items[i]));
            ASSERT_EQ(
                i >= removed.size() ? held_once(view) : not_held(view),
                tag_holders(sender_db, view));
        }

        // And they can come back
        sender_db.insert_or_assign(removed);
        ASSERT_EQ(items.size(), sender_db.get_item_count());
        for (const auto &item : items) {
            TaggedItemView view = view_of(item, key, params);
            ASSERT_EQ(held_once(view), tag_holders(sender_db, view));
        }

        sender_db.remove(items);
        ASSERT_EQ(0, sender_db.get_item_count());
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());
    }

    TEST(SenderDBTagTests, LabeledBasics)
    {
        PSIParams params = create_tag_params();
        oprf::OPRFKey key = fixed_oprf_key();
        SenderDB sender_db(params, key, 20, 16, true);

        vector<pair<Item, Label>> data;
        for (uint64_t i = 0; i < 100; i++) {
            data.emplace_back(Item(i + 1, ~i), create_label(static_cast<unsigned char>(i), 20));
        }
        sender_db.insert_or_assign(data);
        ASSERT_EQ(data.size(), sender_db.get_item_count());
        size_t bin_bundle_count = sender_db.get_bin_bundle_count();
        for (const auto &item_label : data) {
            ASSERT_TRUE(sender_db.has_item(item_label.first));
            ASSERT_EQ(item_label.second, sender_db.get_label(item_label.first));
            TaggedItemView view = view_of(item_label.first, key, params);
            ASSERT_EQ(held_once(view), tag_holders(sender_db, view));
        }

        // A shorter label is padded, as without match tags
        sender_db.insert_or_assign(make_pair(data[0].first, Label{ 1, 2, 3 }));
        Label padded(20);
        padded[0] = 1;
        padded[1] = 2;
        padded[2] = 3;
        ASSERT_EQ(padded, sender_db.get_label(data[0].first));

        // Updating changes the label and keeps the tag
        for (auto &item_label : data) {
            item_label.second =
                create_label(static_cast<unsigned char>(item_label.second[0] + 100), 20);
        }
        sender_db.insert_or_assign(data);
        ASSERT_EQ(data.size(), sender_db.get_item_count());
        ASSERT_EQ(bin_bundle_count, sender_db.get_bin_bundle_count());
        for (const auto &item_label : data) {
            ASSERT_EQ(item_label.second, sender_db.get_label(item_label.first));
            TaggedItemView view = view_of(item_label.first, key, params);
            ASSERT_EQ(held_once(view), tag_holders(sender_db, view));
        }

        // A bad batch is refused whole, as without match tags
        vector<pair<Item, Label>> duplicated{ data[0], data[0] };
        ASSERT_THROW(sender_db.insert_or_assign(duplicated), invalid_argument);
        ASSERT_THROW(
            sender_db.insert_or_assign(make_pair(Item(1000, 1000), create_label(0, 21))),
            invalid_argument);
        ASSERT_THROW(sender_db.insert_or_assign(Item(1000, 1000)), logic_error);
        ASSERT_EQ(data.size(), sender_db.get_item_count());
        ASSERT_FALSE(sender_db.has_item(Item(1000, 1000)));

        // Removing takes exactly the items removed
        vector<Item> removed;
        for (size_t i = 0; i < data.size(); i += 2) {
            removed.push_back(data[i].first);
        }
        sender_db.remove(removed);
        for (size_t i = 0; i < data.size(); i++) {
            TaggedItemView view = view_of(data[i].first, key, params);
            if (i % 2) {
                ASSERT_EQ(data[i].second, sender_db.get_label(data[i].first));
                ASSERT_EQ(held_once(view), tag_holders(sender_db, view));
            } else {
                ASSERT_FALSE(sender_db.has_item(data[i].first));
                ASSERT_THROW(
                    static_cast<void>(sender_db.get_label(data[i].first)), invalid_argument);
                ASSERT_EQ(not_held(view), tag_holders(sender_db, view));
            }
        }
    }

    TEST(SenderDBTagTests, ItemsSharingTheirPlaceAreToldApart)
    {
        // With 13 bits per item, two items in a bin share their field element one time in 8192,
        // so among thousands of items some share their bin and their field element: 16 pairs of
        // the 15000 searched here. Such items go into different bin bundles at the same bundle
        // index, and every operation on one of them must act on it alone. Every item here shares
        // its place with another.
        PSIParams params = create_tag_params(1, 4, 1, 16, 1024, 12289);
        ASSERT_EQ(13, params.item_bit_count());
        ASSERT_EQ(52, params.tag_bit_count());
        oprf::OPRFKey key = fixed_oprf_key();

        vector<vector<Item>> groups = find_items_sharing_places(params, key, 15000);
        ASSERT_LE(size_t(10), groups.size());
        size_t largest_group = 0;
        vector<Item> items;
        vector<Item> firsts;
        for (const auto &group : groups) {
            largest_group = max(largest_group, group.size());
            items.insert(items.end(), group.begin(), group.end());
            firsts.push_back(group.front());
        }
        unordered_map<Item, TaggedItemView> views;
        for (const auto &item : items) {
            views[item] = view_of(item, key, params);
        }

        for (size_t label_byte_count : { 0U, 8U }) {
            SenderDB sender_db(params, key, label_byte_count, 16, true);

            // Every label stored is new
            unordered_map<Item, Label> labels;
            unsigned char next_label = 0;
            auto store = [&](const vector<Item> &to_store) {
                if (!label_byte_count) {
                    sender_db.insert_or_assign(to_store);
                    return;
                }
                vector<pair<Item, Label>> data;
                for (const auto &item : to_store) {
                    labels[item] = create_label(next_label++, label_byte_count);
                    data.emplace_back(item, labels[item]);
                }
                sender_db.insert_or_assign(data);
            };
            auto check = [&](const Item &item, bool present) {
                const TaggedItemView &view = views.at(item);
                ASSERT_EQ(present, sender_db.has_item(item));
                ASSERT_EQ(present ? held_once(view) : not_held(view), tag_holders(sender_db, view));
                if (label_byte_count && present) {
                    ASSERT_EQ(labels.at(item), sender_db.get_label(item));
                } else if (label_byte_count) {
                    ASSERT_THROW(static_cast<void>(sender_db.get_label(item)), invalid_argument);
                }
            };

            store(items);
            ASSERT_EQ(items.size(), sender_db.get_item_count());
            size_t bin_bundle_count = sender_db.get_bin_bundle_count();
            ASSERT_LE(largest_group, bin_bundle_count);
            for (const auto &item : items) {
                check(item, true);
            }

            // Store the first of each group again: with labels, as a batch and then one at a
            // time, which updates their labels; without, which does nothing
            store(firsts);
            for (const auto &item : firsts) {
                store({ item });
            }
            ASSERT_EQ(items.size(), sender_db.get_item_count());
            ASSERT_EQ(bin_bundle_count, sender_db.get_bin_bundle_count());
            for (const auto &item : items) {
                check(item, true);
            }

            // Remove the first of each group, and put them back
            sender_db.remove(firsts);
            ASSERT_EQ(items.size() - firsts.size(), sender_db.get_item_count());
            for (size_t g = 0; g < groups.size(); g++) {
                for (size_t i = 0; i < groups[g].size(); i++) {
                    check(groups[g][i], i != 0);
                }
            }
            store(firsts);
            ASSERT_EQ(items.size(), sender_db.get_item_count());
            for (const auto &item : items) {
                check(item, true);
            }

            // The same through a save and a load
            stringstream ss;
            sender_db.save(ss);
            sender_db = SenderDB::Load(ss).first;
            ASSERT_EQ(bin_bundle_count, sender_db.get_bin_bundle_count());
            for (const auto &item : items) {
                check(item, true);
            }
            vector<Item> rest;
            for (const auto &group : groups) {
                sender_db.remove(group.back());
                check(group.back(), false);
                for (size_t i = 0; i + 1 < group.size(); i++) {
                    check(group[i], true);
                    rest.push_back(group[i]);
                }
            }

            sender_db.remove(rest);
            ASSERT_EQ(0, sender_db.get_item_count());
            ASSERT_EQ(0, sender_db.get_bin_bundle_count());
        }
    }

    TEST(SenderDBTagTests, OverwriteChangesTheItemWhereItIsStored)
    {
        // See SenderDBTests.OverwriteChangesTheItemWhereItIsStored: an update must change the
        // item where it is stored, however many bin bundles its bundle index has
        PSIParams params = create_tag_params(1, 3, 3, 2, 2048, 65537);
        oprf::OPRFKey key = fixed_oprf_key();
        SenderDB sender_db(params, key, 20, 16, true);

        vector<pair<Item, Label>> data;
        for (uint64_t i = 0; i < 800; i++) {
            data.emplace_back(Item(i, ~i), create_label(static_cast<unsigned char>(i), 20));
        }
        sender_db.set_data(data);
        ASSERT_LE(size_t(3), sender_db.get_bin_bundle_count(0));
        size_t bin_bundle_count = sender_db.get_bin_bundle_count();

        for (auto &item_label : data) {
            item_label.second =
                create_label(static_cast<unsigned char>(item_label.second[0] + 100), 20);
        }
        sender_db.insert_or_assign(data);
        for (size_t i = 0; i < data.size(); i += 37) {
            data[i].second = create_label(static_cast<unsigned char>(data[i].second[0] + 50), 20);
            sender_db.insert_or_assign(data[i]);
        }

        ASSERT_EQ(data.size(), sender_db.get_item_count());
        ASSERT_EQ(bin_bundle_count, sender_db.get_bin_bundle_count());
        for (const auto &item_label : data) {
            ASSERT_EQ(item_label.second, sender_db.get_label(item_label.first));
            TaggedItemView view = view_of(item_label.first, key, params);
            ASSERT_EQ(held_once(view), tag_holders(sender_db, view));
        }

        vector<Item> items;
        for (const auto &item_label : data) {
            items.push_back(item_label.first);
        }
        sender_db.remove(items);
        ASSERT_EQ(0, sender_db.get_item_count());
        ASSERT_EQ(0, sender_db.get_bin_bundle_count());
    }

    TEST(SenderDBTagTests, BinsHoldMaxItemsPerBin)
    {
        // Without match tags a bin holds fewer than max_items_per_bin items, as its matching
        // polynomial has one more coefficient than it has items. With match tags there is no
        // matching polynomial, and a bin holds max_items_per_bin items, whose label polynomials
        // have max_items_per_bin coefficients.
        auto largest = [](SenderDB &sender_db, bool matching) {
            size_t largest_coeff_count = 0;
            for (uint32_t b = 0; b < sender_db.get_params().bundle_idx_count(); b++) {
                for (const BinBundleCache &cache : sender_db.get_cache_at(b)) {
                    const auto &polyns =
                        matching ? cache.felt_matching_polyns : cache.felt_interp_polyns[0];
                    for (const auto &polyn : polyns) {
                        largest_coeff_count = max(largest_coeff_count, polyn.size());
                    }
                }
            }
            return largest_coeff_count;
        };

        constexpr uint32_t max_items_per_bin = 4;

        PSIParams tag_params = create_tag_params(1, 3, 3, max_items_per_bin, 2048, 65537);
        SenderDB tag_db(tag_params, fixed_oprf_key(), 0, 0, true);
        vector<Item> items;
        for (uint64_t i = 0; i < 3000; i++) {
            items.emplace_back(i, i);
        }
        tag_db.insert_or_assign(items);
        ASSERT_LE(size_t(2), tag_db.get_bin_bundle_count());
        ASSERT_EQ(max_items_per_bin, largest(tag_db, false));

        PSIParams untagged_params = with_shallow_bins(*get_params1(), max_items_per_bin);
        SenderDB untagged_db(untagged_params, fixed_oprf_key(), 4, 0, true);
        vector<pair<Item, Label>> data;
        for (uint64_t i = 0; i < 1000; i++) {
            data.emplace_back(Item(i, i), create_label(static_cast<unsigned char>(i), 4));
        }
        untagged_db.insert_or_assign(data);
        ASSERT_LE(size_t(2), untagged_db.get_bin_bundle_count());
        ASSERT_EQ(max_items_per_bin - 1, largest(untagged_db, false));
        ASSERT_EQ(max_items_per_bin, largest(untagged_db, true));
    }

    TEST(SenderDBTagTests, SaveLoadStripAndPackingRate)
    {
        for (bool labeled : { false, true }) {
            // Two field elements and two tag parts per item
            PSIParams params = create_tag_params(2, 2, 3, 8, 4096, 65537, 2);
            oprf::OPRFKey key = fixed_oprf_key();
            size_t label_byte_count = labeled ? 12 : 0;
            SenderDB sender_db(params, key, label_byte_count, 16, true);

            vector<pair<Item, Label>> data;
            for (uint64_t i = 0; i < 2000; i++) {
                data.emplace_back(
                    Item(i, i + 1), create_label(static_cast<unsigned char>(i), label_byte_count));
            }
            if (labeled) {
                sender_db.set_data(data);
            } else {
                vector<Item> items;
                for (const auto &item_label : data) {
                    items.push_back(item_label.first);
                }
                sender_db.set_data(items);
            }
            double packing_rate = sender_db.get_packing_rate();
            ASSERT_LT(0.0, packing_rate);
            ASSERT_GE(1.0, packing_rate);

            stringstream ss;
            size_t save_size = sender_db.save(ss);
            auto [loaded, load_size] = SenderDB::Load(ss);
            ASSERT_EQ(save_size, load_size);
            ASSERT_EQ(params.to_string(), loaded.get_params().to_string());
            ASSERT_EQ(sender_db.get_item_count(), loaded.get_item_count());
            ASSERT_EQ(sender_db.get_bin_bundle_count(), loaded.get_bin_bundle_count());
            ASSERT_EQ(sender_db.get_hashed_items(), loaded.get_hashed_items());
            ASSERT_EQ(packing_rate, loaded.get_packing_rate());
            ASSERT_EQ(sender_db.log2_fpp(1), loaded.log2_fpp(1));
            ASSERT_TRUE(oprf_keys_equal(key, loaded.get_oprf_key()));
            for (size_t i = 0; i < data.size(); i += 97) {
                TaggedItemView view = view_of(data[i].first, key, params);
                ASSERT_EQ(held_once(view), tag_holders(loaded, view));
                if (labeled) {
                    ASSERT_EQ(data[i].second, loaded.get_label(data[i].first));
                }
            }

            // The loaded SenderDB can be changed as the original can
            loaded.remove(data[0].first);
            ASSERT_FALSE(loaded.has_item(data[0].first));
            TaggedItemView removed_view = view_of(data[0].first, key, params);
            ASSERT_EQ(not_held(removed_view), tag_holders(loaded, removed_view));

            // Stripping keeps what a query needs, and the stripped SenderDB saves and loads
            sender_db.strip();
            ASSERT_TRUE(sender_db.is_stripped());
            ASSERT_THROW(sender_db.insert_or_assign(vector<Item>{ Item(1, 1) }), logic_error);
            ASSERT_THROW(static_cast<void>(sender_db.get_label(data[1].first)), logic_error);
            stringstream stripped_ss;
            sender_db.save(stripped_ss);
            auto stripped = SenderDB::Load(stripped_ss).first;
            ASSERT_TRUE(stripped.is_stripped());
            ASSERT_EQ(sender_db.get_bin_bundle_count(), stripped.get_bin_bundle_count());
            ASSERT_EQ(packing_rate, stripped.get_packing_rate());
            for (uint32_t b = 0; b < params.bundle_idx_count(); b++) {
                for (const BinBundleCache &cache : stripped.get_cache_at(b)) {
                    ASSERT_TRUE(cache.felt_interp_polyns.empty());
                    ASSERT_FALSE(cache.batched_matching_polyn);
                    ASSERT_EQ(
                        loaded.get_cache_at(0)[0].get().batched_interp_polyns.size(),
                        cache.batched_interp_polyns.size());
                }
            }
        }
    }

    TEST(SenderDBTagTests, Log2Fpp)
    {
        // With match tags, an item matches a bin bundle wrongly only if the bundle gives its
        // tag, with probability 2^-48 here, however many items the bin holds
        PSIParams params = create_tag_params();
        ASSERT_EQ(48, params.tag_bit_count());
        SenderDB sender_db(params, fixed_oprf_key(), 0, 0, true);
        ASSERT_EQ(-48.0, sender_db.log2_fpp(1));

        vector<Item> items;
        for (uint64_t i = 0; i < 10000; i++) {
            items.emplace_back(i + 1, i + 1);
        }
        sender_db.insert_or_assign(items);

        size_t max_bundles = 0;
        for (uint32_t b = 0; b < params.bundle_idx_count(); b++) {
            max_bundles = max(max_bundles, sender_db.get_bin_bundle_count(b));
        }
        ASSERT_LE(size_t(2), max_bundles);
        ASSERT_DOUBLE_EQ(-48.0 + log2(static_cast<double>(max_bundles)), sender_db.log2_fpp(1));
        ASSERT_DOUBLE_EQ(sender_db.log2_fpp(1) + 10.0, sender_db.log2_fpp(1024));

        // Tags come from a 128-bit key, so longer ones count as 128 bits
        PSIParams long_tags = create_tag_params(2, 8, 3, 8, 4096, 65537);
        ASSERT_EQ(256, long_tags.tag_bit_count());
        ASSERT_EQ(-128.0, SenderDB(long_tags, 0).log2_fpp(1));
    }

    namespace {
        /**
        Returns the SenderDB with the parameters, OPRF key and item set of header_db, and the bin
        bundles of each of bundle_dbs in turn, all of which must have been built with the same
        parameters and OPRF key.
        */
        SenderDB assemble_sender_db(
            const SenderDB &header_db, const vector<const SenderDB *> &bundle_dbs)
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

            string bytes = saved(header_db);
            const auto *header = fbs::GetSizePrefixedSenderDB(bytes.data());
            uint32_t bin_bundle_count = 0;
            string bin_bundles;
            for (const SenderDB *bundle_db : bundle_dbs) {
                string bundle_bytes = saved(*bundle_db);
                bin_bundle_count +=
                    fbs::GetSizePrefixedSenderDB(bundle_bytes.data())->bin_bundle_count();
                bin_bundles += bundle_bytes.substr(header_size(bundle_bytes));
            }

            // The same header, counting those bin bundles
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
        Returns the SenderDB that sender_db would be if it also held the bin bundles of others,
        after its own: what an older version of APSI could leave behind when it stored an item a
        second time on updating the item's label. The others must have been built with the same
        parameters and OPRF key, and hold only items sender_db holds.
        */
        SenderDB with_extra_bin_bundles(
            const SenderDB &sender_db, const vector<const SenderDB *> &others)
        {
            vector<const SenderDB *> bundle_dbs{ &sender_db };
            bundle_dbs.insert(bundle_dbs.end(), others.begin(), others.end());
            return assemble_sender_db(sender_db, bundle_dbs);
        }

        /**
        Returns the SenderDB that sender_db would be if its item set were that of other: what an
        older version of APSI could leave behind when an insertion failed partway, as it recorded
        the new items before storing them. other must have been built with the same parameters
        and OPRF key, and hold the items of sender_db and more.
        */
        SenderDB with_item_set_of(const SenderDB &sender_db, const SenderDB &other)
        {
            return assemble_sender_db(other, { &sender_db });
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
            size_t tag_part_count = params.tag_part_count();

            auto [hashed_item, label_key] = oprf::OPRFSender::GetItemHash(item, key);
            vector<apsi::util::felt_t> felts =
                apsi::util::algebraize_item(hashed_item, params.item_bit_count(), mod);
            vector<apsi::util::felt_t> tag;
            if (params.uses_tags()) {
                tag = apsi::util::compute_match_tag(
                    label_key, tag_part_count * felts_per_item, params.item_bit_count_per_felt());
            }

            vector<vector<Label>> labels;
            for (const auto &place : places_of(hashed_item, params)) {
                labels.emplace_back();
                for (const BinBundleCache &cache : sender_db.get_cache_at(place.first)) {
                    // Whether this bin bundle holds the item: without match tags its matching
                    // polynomials vanish at the item's field elements, and with match tags its
                    // tag polynomials give the item's tag there
                    bool holds = true;
                    for (size_t s = 0; holds && (s < felts_per_item); s++) {
                        size_t bin = place.second + s;
                        if (!params.uses_tags()) {
                            holds =
                                evaluate_polyn(cache.felt_matching_polyns[bin], felts[s], mod) == 0;
                        }
                        for (size_t p = 0; holds && (p < tag_part_count); p++) {
                            holds =
                                evaluate_polyn(cache.felt_interp_polyns[p][bin], felts[s], mod) ==
                                tag[(p * felts_per_item) + s];
                        }
                    }
                    if (!holds) {
                        continue;
                    }

                    // The label parts in the item's slots, part by part, as a receiver collects
                    // them
                    apsi::util::AlgLabel alg_label;
                    size_t part_count = cache.felt_interp_polyns.size();
                    for (size_t p = tag_part_count; p < part_count; p++) {
                        for (size_t s = 0; s < felts_per_item; s++) {
                            alg_label.push_back(evaluate_polyn(
                                cache.felt_interp_polyns[p][place.second + s], felts[s], mod));
                        }
                    }
                    EncryptedLabel encrypted_label = apsi::util::dealgebraize_label(
                        alg_label, (part_count - tag_part_count) * params.item_bit_count(), mod);
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

        // Without match tags, as an older version of APSI would have left the database, and with
        // them, which take the same path
        test_fun(with_shallow_bins(*get_params1(), 3));
        test_fun(create_tag_params());
    }

    namespace {
        /**
        Installs a logger whose handler throws for every message, at the levels from debug up,
        that contains any of the given texts, and restores the global logger and log level when it
        is destroyed.
        */
        class ThrowingLog {
        public:
            explicit ThrowingLog(vector<string> texts)
                : saved_level_(GetLogLevel()), texts_(std::move(texts))
            {
                array<Logger::log_handler_t, Logger::level_count> log_handlers{};
                for (LogLevel level :
                     { LogLevel::debug, LogLevel::info, LogLevel::warning, LogLevel::error }) {
                    log_handlers[static_cast<size_t>(level)] = [this](const string &msg) {
                        for (const string &text : texts_) {
                            if (msg.find(text) != string::npos) {
                                throw runtime_error("the log handler failed");
                            }
                        }
                    };
                }
                SetLogger(Logger::Create(std::move(log_handlers), {}, {}));
                SetLogLevel(LogLevel::debug);
            }

            ~ThrowingLog()
            {
                CloseLogger();
                SetLogLevel(saved_level_);
            }

            ThrowingLog(const ThrowingLog &) = delete;

            ThrowingLog &operator=(const ThrowingLog &) = delete;

        private:
            LogLevel saved_level_;

            vector<string> texts_;
        };
    } // namespace

    TEST(SenderDBTests, UpdatesCompleteWhenTheyCannotLog)
    {
        // Logging allocates and calls the user's handler, either of which can throw. An update
        // also logs once it has begun to change the BinBundles: its workers once they have changed
        // those at their bundle index, the preprocessing of the new items once the existing ones
        // have their new labels, and the regeneration of the caches once the change is recorded
        // in the item set. A throw there would leave the item set and the BinBundles describing
        // different databases, or the caches stale. The handler here throws for those messages,
        // and every update still completes.
        auto test_fun = [](const PSIParams &params) {
            oprf::OPRFKey key = fixed_oprf_key();
            auto sender_db = make_shared<SenderDB>(params, key, 8, 16, true);
            unordered_map<Item, Label> expected;
            vector<pair<Item, Label>> data;
            for (uint64_t i = 0; i < 200; i++) {
                data.emplace_back(Item(i, ~i), create_label(static_cast<unsigned char>(i), 8));
                expected[data.back().first] = data.back().second;
            }

            // New labels for 20 items, 20 new items, and 20 items to remove
            vector<pair<Item, Label>> update;
            vector<Item> removed;
            for (uint64_t i = 0; i < 20; i++) {
                update.emplace_back(
                    Item(i, ~i), create_label(static_cast<unsigned char>(200 + i), 8));
                update.emplace_back(
                    Item(1000 + i, i), create_label(static_cast<unsigned char>(220 + i), 8));
                removed.emplace_back(20 + i, ~(20 + i));
            }

            {
                ThrowingLog log({ "finished processing bundle index", "preprocessing", "caches" });
                ASSERT_NO_THROW(sender_db->set_data(data));
                ASSERT_NO_THROW(sender_db->insert_or_assign(update));
                ASSERT_NO_THROW(sender_db->remove(removed));
            }

            vector<Item> queried;
            for (const auto &item_label : update) {
                expected[item_label.first] = item_label.second;
            }
            for (const auto &item : removed) {
                expected.erase(item);
                queried.push_back(item);
            }
            ASSERT_EQ(expected.size(), sender_db->get_item_count());
            for (const auto &[item, label] : expected) {
                ASSERT_EQ(label, sender_db->get_label(item));
                queried.push_back(item);
            }

            vector<vector<Label>> results = query_labels(sender_db, key, queried);
            for (size_t i = 0; i < queried.size(); i++) {
                auto where = expected.find(queried[i]);
                vector<Label> expected_labels;
                if (where != expected.end()) {
                    expected_labels.push_back(where->second);
                }
                ASSERT_EQ(expected_labels, results[i]) << "item " << i;
            }
        };

        test_fun(*get_params1());
        test_fun(create_tag_params());
    }

    TEST(SenderDBTests, AnUpdateThatFailsPartwayRegeneratesTheCaches)
    {
        // An older version of APSI recorded new items before storing them, so that an insertion
        // that failed partway could leave, and save, a SenderDB whose item set names an item that
        // no BinBundle holds. Such a database is put together here. An update that gives that
        // item and the others new labels fails with std::logic_error, once the workers at the
        // bundle indices without the item have given the items there their new labels: the
        // item's three locations are at no more than three of the four bundle indices. The update
        // regenerates the caches of the BinBundles it changed before passing on the exception, so
        // the SenderDB still answers a query: each item has its old label or its new one, and
        // some have the new one.
        PSIParams::TableParams table_params = get_params1()->table_params();
        table_params.table_size = 4 * get_params1()->items_per_bundle();
        PSIParams params(
            get_params1()->item_params(),
            table_params,
            get_params1()->query_params(),
            get_params1()->seal_params());
        ASSERT_EQ(uint32_t(4), params.bundle_idx_count());
        ASSERT_EQ(uint32_t(3), params.table_params().hash_func_count);

        oprf::OPRFKey key = fixed_oprf_key();
        constexpr size_t label_byte_count = 8;
        vector<Item> items;
        vector<pair<Item, Label>> data;
        vector<pair<Item, Label>> update;
        for (uint64_t i = 0; i < 100; i++) {
            items.emplace_back(i, ~i);
            data.emplace_back(
                items.back(), create_label(static_cast<unsigned char>(i), label_byte_count));
            update.emplace_back(
                items.back(), create_label(static_cast<unsigned char>(100 + i), label_byte_count));
        }
        Item unstored(1000, 1000);

        SenderDB stored_db(params, key, label_byte_count, 16, true);
        stored_db.set_data(data);
        vector<pair<Item, Label>> recorded = data;
        recorded.emplace_back(unstored, create_label(200, label_byte_count));
        SenderDB recorded_db(params, key, label_byte_count, 16, true);
        recorded_db.set_data(recorded);
        auto sender_db = make_shared<SenderDB>(with_item_set_of(stored_db, recorded_db));
        ASSERT_EQ(recorded.size(), sender_db->get_item_count());
        ASSERT_TRUE(sender_db->has_item(unstored));

        update.emplace_back(unstored, create_label(250, label_byte_count));
        ASSERT_THROW(sender_db->insert_or_assign(update), logic_error);

        for (uint32_t b = 0; b < params.bundle_idx_count(); b++) {
            ASSERT_NO_THROW(auto caches = sender_db->get_cache_at(b)) << "bundle index " << b;
        }
        vector<vector<Label>> labels = query_labels(sender_db, key, items);
        size_t updated_count = 0;
        for (size_t i = 0; i < items.size(); i++) {
            ASSERT_EQ(size_t(1), labels[i].size()) << "item " << i;
            if (labels[i][0] == update[i].second) {
                updated_count++;
            } else {
                ASSERT_EQ(data[i].second, labels[i][0]) << "item " << i;
            }
        }
        ASSERT_LT(size_t(0), updated_count);
    }
} // namespace APSITests
