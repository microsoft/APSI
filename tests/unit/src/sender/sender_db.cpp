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
#include <functional>
#include <map>
#include <memory>
#include <numeric>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

// APSI
#include "apsi/bin_bundle.h"
#include "apsi/bin_bundle_generated.h"
#include "apsi/crypto_context.h"
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
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/db_encoding.h"
#include "apsi/util/label_encryptor.h"
#include "apsi/util/match_tag.h"
#include "apsi/util/save_size.h"
#include "apsi/util/utils.h"

// Kuku
#include "kuku/locfunc.h"

// SEAL
#include "seal/serialization.h"
#include "seal/util/blake2.h"
#include "seal/util/uintarithsmallmod.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::sender;
using namespace seal;
using apsi::sender::util::ScopedSaveSizeLimit;
using apsi::sender::util::sender_db_header_save_size_bounds;

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

    TEST(SenderDBTests, SaveRefusesWhatLoadCannotRead)
    {
        // SenderDB::Load reads the header of a saved SenderDB, and then each of its BinBundles, as
        // a buffer of at most apsi::util::max_buffer_size bytes, and SenderDB::save refuses a
        // SenderDB that might have any larger before it writes anything, with both overloads and
        // in both plaintext save modes. The limit is lowered on this thread so that a small
        // SenderDB can stand for one of gigabytes; nothing else changes.
        PSIParams params = with_shallow_bins(*get_params1(), 3);
        ASSERT_EQ(uint32_t(1), params.bundle_idx_count());
        SenderDB sender_db(params, fixed_oprf_key(), 20, 16, true);
        vector<pair<Item, Label>> data;
        for (uint64_t val = 0; sender_db.get_bin_bundle_count() < 3; val++) {
            data.emplace_back(Item(val, ~val), create_label(static_cast<unsigned char>(val), 20));
            sender_db.insert_or_assign(data.back());
        }

        // The header holds the HashedItem of every item unless the SenderDB is stripped. What save
        // writes of it is within the bounds on its size.
        stringstream params_ss;
        size_t params_byte_count = sender_db.get_params().save(params_ss);
        auto header_bounds = [&](size_t hashed_item_count) {
            return sender_db_header_save_size_bounds(
                params_byte_count, oprf::oprf_key_size, hashed_item_count, 3);
        };
        auto check_header_size = [&](const string &saved, size_t hashed_item_count) {
            size_t header_size = prefixed_size_at(saved, 0);
            ASSERT_LE(header_bounds(hashed_item_count).lower, header_size);
            ASSERT_GE(header_bounds(hashed_item_count).upper, header_size);
        };
        size_t unstripped_header_upper = header_bounds(data.size()).upper;

        // Returns the message with which save refuses the SenderDB under the limit, having
        // written nothing
        auto refusal = [&](const function<size_t(ostream &)> &save, size_t limit) {
            ScopedSaveSizeLimit scoped_limit(limit);
            stringstream ss;
            string what;
            try {
                save(ss);
                ADD_FAILURE() << "the SenderDB was saved";
            } catch (const length_error &ex) {
                what = ex.what();
            }
            EXPECT_TRUE(ss.str().empty());
            return what;
        };
        auto more_than = [](size_t limit) {
            return " bytes, more than the " + to_string(limit) + " bytes SenderDB::Load reads";
        };

        vector<pair<string, function<size_t(ostream &)>>> saves{
            { "save", [&](ostream &out) { return sender_db.save(out); } },
            { "as_stored",
              [&](ostream &out) {
                  return sender_db.save(out, SenderDB::PlaintextSaveMode::as_stored);
              } },
            { "apsi_1x",
              [&](ostream &out) {
                  return sender_db.save(out, SenderDB::PlaintextSaveMode::apsi_1x);
              } }
        };
        for (const auto &[save_name, save] : saves) {
            SCOPED_TRACE(save_name);
            stringstream ss;
            size_t size = save(ss);
            ASSERT_EQ(ss.str().size(), size);
            ASSERT_NO_FATAL_FAILURE(check_header_size(ss.str(), data.size()));
            auto [loaded, loaded_size] = SenderDB::Load(ss);
            ASSERT_EQ(size, loaded_size);
            ASSERT_EQ(data.size(), loaded.get_item_count());
            for (const auto &[item, label] : data) {
                ASSERT_EQ(label, loaded.get_label(item));
            }

            // Under a limit that the header fits, the first BinBundle, with the labels and cache
            // of its items, takes more; under one that the header might not fit, it is refused for
            // the items
            size_t limit = unstripped_header_upper;
            string what = refusal(save, limit);
            ASSERT_EQ(
                size_t(0),
                what.find(
                    "failed to save SenderDB: BinBundle 1 of 3 at bundle index 0 takes at "
                    "least "));
            ASSERT_NE(string::npos, what.find(more_than(limit)));
            ASSERT_EQ(
                "failed to save SenderDB: its " + to_string(data.size()) +
                    " items are too many to save unstripped, as its header, which holds their "
                    "HashedItems, takes up to " +
                    to_string(limit) + more_than(limit - 1) + "; SenderDB::strip() removes them",
                refusal(save, limit - 1));
        }

        // Stripped, the SenderDB saves no HashedItems, so that under the same limit the first
        // BinBundle is refused instead. Under a limit that even a stripped header might not fit,
        // which no real limit is, the items are not blamed.
        sender_db.strip();
        auto save = [&](ostream &out) {
            return sender_db.save(out);
        };
        string what = refusal(save, unstripped_header_upper - 1);
        ASSERT_EQ(
            size_t(0), what.find("failed to save SenderDB: BinBundle 1 of 3 at bundle index 0 "));
        size_t stripped_header_upper = header_bounds(0).upper;
        ASSERT_EQ(
            "failed to save SenderDB: its header takes up to " + to_string(stripped_header_upper) +
                more_than(stripped_header_upper - 1),
            refusal(save, stripped_header_upper - 1));

        stringstream stripped_ss;
        size_t stripped_size = save(stripped_ss);
        ASSERT_NO_FATAL_FAILURE(check_header_size(stripped_ss.str(), 0));
        auto [loaded, loaded_size] = SenderDB::Load(stripped_ss);
        ASSERT_TRUE(loaded.is_stripped());
        ASSERT_EQ(stripped_size, loaded_size);
        ASSERT_EQ(data.size(), loaded.get_item_count());
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

    namespace {
        /**
        Returns the 32 bytes that the given 64 hexadecimal digits spell out.
        */
        array<unsigned char, 32> hash_from_hex(const string &hex)
        {
            array<unsigned char, 32> hash{};
            for (size_t i = 0; i < hash.size(); i++) {
                hash[i] = static_cast<unsigned char>(stoul(hex.substr(2 * i, 2), nullptr, 16));
            }
            return hash;
        }

        /**
        Returns the saved SenderDB with the records of its hashed_items vector sorted.
        SenderDB::save writes the hashed items in the iteration order of an std::unordered_set,
        which differs between standard libraries. The records are 16 bytes each, and FlatBuffers
        writes them in little-endian order on every platform, so sorting them as bytes moves
        nothing else and gives the same order everywhere.
        */
        string with_sorted_hashed_items(string saved)
        {
            using record_type = array<unsigned char, sizeof(fbs::HashedItem)>;
            static_assert(sizeof(record_type) == 16);

            const auto *hashed_items = fbs::GetSizePrefixedSenderDB(saved.data())->hashed_items();
            auto offset = static_cast<size_t>(
                reinterpret_cast<const char *>(hashed_items->data()) - saved.data());
            vector<record_type> records(hashed_items->size());
            memcpy(records.data(), saved.data() + offset, records.size() * sizeof(record_type));

            sort(records.begin(), records.end());
            memcpy(saved.data() + offset, records.data(), records.size() * sizeof(record_type));
            return saved;
        }

        /**
        The parameters of the SenderDB that UncompressedSaveWithoutMatchTagsIsAsInAPSI1x and
        CompressedSaveForAPSI1xIsAsInAPSI1x save; see the former.
        */
        PSIParams create_apsi1x_kat_params()
        {
            PSIParams::ItemParams item_params;
            item_params.felts_per_item = 5;

            PSIParams::TableParams table_params;
            table_params.hash_func_count = 3;
            table_params.max_items_per_bin = 16;
            table_params.table_size = 3276;

            PSIParams::QueryParams query_params;
            query_params.ps_low_degree = 4;
            query_params.query_powers = { 1, 3, 5 };

            PSIParams::SEALParams seal_params;
            seal_params.set_poly_modulus_degree(8192);
            seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(8192));
            seal_params.set_plain_modulus(65537);

            return { item_params, table_params, query_params, seal_params };
        }

        /**
        The items and 12-byte labels of the SenderDB that
        UncompressedSaveWithoutMatchTagsIsAsInAPSI1x and CompressedSaveForAPSI1xIsAsInAPSI1x save.
        */
        vector<pair<Item, Label>> create_apsi1x_kat_data()
        {
            vector<pair<Item, Label>> data;
            for (uint64_t i = 0; i < 100; i++) {
                Label label(12);
                for (size_t j = 0; j < label.size(); j++) {
                    label[j] = static_cast<unsigned char>(i + j);
                }
                data.emplace_back(Item(i + 1, ~i), std::move(label));
            }
            return data;
        }

        /**
        Returns the Microsoft SEAL header of every plaintext in the caches of the bin bundles of a
        saved SenderDB.
        */
        vector<Serialization::SEALHeader> saved_plaintext_headers(const string &saved)
        {
            stringstream ss(saved);
            vector<unsigned char> sender_db_data = apsi::util::read_from_stream(ss);
            uint32_t bin_bundle_count =
                fbs::GetSizePrefixedSenderDB(sender_db_data.data())->bin_bundle_count();

            vector<Serialization::SEALHeader> headers;
            auto add_headers = [&](const fbs::BatchedPlaintextPolyn &polyn) {
                for (const auto *pt : *polyn.coeffs()) {
                    Serialization::SEALHeader header;
                    static_cast<void>(Serialization::LoadHeader(
                        reinterpret_cast<const seal_byte *>(pt->data()->data()),
                        pt->data()->size(),
                        header));
                    headers.push_back(header);
                }
            };
            for (uint32_t i = 0; i < bin_bundle_count; i++) {
                vector<unsigned char> bin_bundle_data = apsi::util::read_from_stream(ss);
                const auto *cache = fbs::GetSizePrefixedBinBundle(bin_bundle_data.data())->cache();
                if (cache->batched_matching_polyn()) {
                    add_headers(*cache->batched_matching_polyn());
                }
                for (const auto *polyn : *cache->batched_interp_polyns()) {
                    add_headers(*polyn);
                }
            }

            return headers;
        }

        /**
        Returns a saved SenderDB with every plaintext of its bin bundles saved again in the given
        compression mode: the SenderDB as it was saved, followed by each of its bin bundles loaded
        and saved with BinBundle::save in that mode. With seal::compr_mode_type::none, the result
        does not depend on how the plaintexts were compressed.
        */
        string with_plaintexts_in(
            const string &saved, const PSIParams &params, compr_mode_type compr_mode)
        {
            stringstream ss(saved);
            vector<unsigned char> sender_db_data = apsi::util::read_from_stream(ss);
            uint32_t bin_bundle_count =
                fbs::GetSizePrefixedSenderDB(sender_db_data.data())->bin_bundle_count();

            CryptoContext context(params);
            context.set_evaluator();

            stringstream out;
            out.write(
                reinterpret_cast<const char *>(sender_db_data.data()),
                static_cast<streamsize>(sender_db_data.size()));
            for (uint32_t i = 0; i < bin_bundle_count; i++) {
                vector<unsigned char> bin_bundle_data = apsi::util::read_from_stream(ss);
                const auto *saved_bb = fbs::GetSizePrefixedBinBundle(bin_bundle_data.data());
                BinBundle bb(
                    context,
                    saved_bb->cache()->batched_interp_polyns()->size(),
                    params.table_params().max_items_per_bin,
                    params.query_params().ps_low_degree,
                    params.bins_per_bundle(),
                    true,
                    saved_bb->stripped(),
                    params.tag_part_count());
                uint32_t bundle_idx = bb.load(bin_bundle_data).first;
                bb.save(out, bundle_idx, compr_mode);
            }

            return out.str();
        }
    } // namespace

    TEST(SenderDBTests, UncompressedSaveWithoutMatchTagsIsAsInAPSI1x)
    {
        // An uncompressed SenderDB without match tags saves exactly as APSI 1.x saves it, so that
        // either version loads what the other saved. The hash below is the Blake2b-256 of what
        // APSI 1.1.0's code, built with Microsoft SEAL 4.6, saves for this SenderDB, with its
        // hashed items sorted: two bin bundles, each with its matching polynomials and two label
        // parts, with Paterson-Stockmeyer. It saves the same bytes with
        // SenderDB::PlaintextSaveMode::apsi_1x, and so does an uncompressed SenderDB that holds
        // bit-packed plaintexts. A version of Microsoft SEAL that saves the parameters or the
        // plaintexts differently calls for recording the hash again.
        //
        // The hashed items are sorted because their order depends on the standard library; see
        // with_sorted_hashed_items. Nothing else depends on the platform: the parameters and the
        // plaintexts are saved without compression, the labels have no nonce, which makes
        // encrypting them deterministic, every bin holds its items in the order they are given,
        // and every bundle index has a single BinBundle, so the order in which an item's
        // locations are visited does not matter. The SenderDB is built with one thread and with
        // several, which must not change what it saves.
        PSIParams params = create_apsi1x_kat_params();
        ASSERT_FALSE(params.uses_tags());
        ASSERT_EQ(2, params.bundle_idx_count());

        vector<pair<Item, Label>> data = create_apsi1x_kat_data();

        array<unsigned char, 32> expected =
            hash_from_hex("81dee5a89f4b74c8783ce18329f549ad928599bc66e1bccbada8341221543fbb");

        vector<pair<size_t, string>> saved;
        for (size_t thread_count : { 1U, 4U }) {
            ThreadPoolMgr::SetThreadCount(thread_count);
            SenderDB sender_db(params, fixed_oprf_key(), 12, 0, false);
            sender_db.set_data(data);

            stringstream ss;
            sender_db.save(ss);
            saved.emplace_back(
                sender_db.get_bin_bundle_count(), with_sorted_hashed_items(ss.str()));

            stringstream apsi_1x_ss;
            sender_db.save(apsi_1x_ss, SenderDB::PlaintextSaveMode::apsi_1x);
            saved.emplace_back(
                sender_db.get_bin_bundle_count(), with_sorted_hashed_items(apsi_1x_ss.str()));
        }
        ThreadPoolMgr::SetThreadCount(0);

        // An uncompressed SenderDB that holds bit-packed plaintexts
        stringstream packed_ss(
            with_plaintexts_in(saved.front().second, params, compr_mode_type::bitpack));
        SenderDB packed_db = SenderDB::Load(packed_ss).first;
        ASSERT_FALSE(packed_db.is_compressed());
        stringstream held_ss;
        packed_db.save(held_ss);
        for (const auto &header : saved_plaintext_headers(held_ss.str())) {
            ASSERT_EQ(compr_mode_type::bitpack, header.compr_mode);
        }

        stringstream apsi_1x_ss;
        packed_db.save(apsi_1x_ss, SenderDB::PlaintextSaveMode::apsi_1x);
        saved.emplace_back(
            packed_db.get_bin_bundle_count(), with_sorted_hashed_items(apsi_1x_ss.str()));

        for (const auto &[bin_bundle_count, bytes] : saved) {
            ASSERT_EQ(size_t(2), bin_bundle_count);
            ASSERT_EQ(size_t(4196680), bytes.size());

            array<unsigned char, 32> hash{};
            ASSERT_EQ(
                0, APSI_blake2b(hash.data(), hash.size(), bytes.data(), bytes.size(), nullptr, 0));
            ASSERT_EQ(expected, hash);
        }
    }

#ifdef SEAL_USE_ZSTD
    TEST(SenderDBTests, CompressedSaveForAPSI1xIsAsInAPSI1x)
    {
        // A compressed SenderDB without match tags saved with SenderDB::PlaintextSaveMode::apsi_1x
        // saves exactly as APSI 1.x saves it, with every plaintext compressed with Zstandard, so
        // that APSI 1.x, which cannot load bit-packed plaintexts, can answer queries from it. This
        // is the SenderDB of UncompressedSaveWithoutMatchTagsIsAsInAPSI1x, built compressed. The
        // first hash below is the Blake2b-256 of what APSI 1.1.0's code saves for it, built with
        // Microsoft SEAL 4.6.1 and Zstandard 1.5.7, with its hashed items sorted, and the second
        // that of the same bytes with every plaintext loaded and saved again uncompressed by
        // with_plaintexts_in. The latter bytes differ from those
        // UncompressedSaveWithoutMatchTagsIsAsInAPSI1x hashes only in the flag that says that the
        // SenderDB is compressed.
        //
        // The second hash does not depend on Zstandard, and is always compared. The first does:
        // Zstandard compresses the same data alike within a version, but not across versions, and
        // 1.5.4 to 1.5.6 compress these plaintexts otherwise than 1.5.7. Should only the first
        // hash differ, only Zstandard can explain it, and its comparison is skipped. A version of
        // Microsoft SEAL that saves the plaintexts differently calls for recording both hashes
        // again.
        //
        // The SenderDB is built with one thread and with several, which must not change what it
        // saves.
        PSIParams params = create_apsi1x_kat_params();
        vector<pair<Item, Label>> data = create_apsi1x_kat_data();

        auto blake2b_256 = [](const string &bytes) {
            array<unsigned char, 32> hash{};
            if (APSI_blake2b(hash.data(), hash.size(), bytes.data(), bytes.size(), nullptr, 0)) {
                throw runtime_error("failed to compute Blake2b");
            }
            return hash;
        };
        array<unsigned char, 32> expected =
            hash_from_hex("4a874d359fbab6eb06876f867e6126b422db62aa8a85c68ede35052616082471");
        array<unsigned char, 32> expected_uncompressed =
            hash_from_hex("7adcbf15dafb8d51efc73fd6dea06358dcda51dce78fa7b49e980cbee7e4ad74");

        vector<string> saved;
        for (size_t thread_count : { 1U, 4U }) {
            ThreadPoolMgr::SetThreadCount(thread_count);
            SenderDB sender_db(params, fixed_oprf_key(), 12, 0, true);
            sender_db.set_data(data);
            ASSERT_EQ(size_t(2), sender_db.get_bin_bundle_count());

            stringstream ss;
            sender_db.save(ss, SenderDB::PlaintextSaveMode::apsi_1x);
            saved.push_back(with_sorted_hashed_items(ss.str()));
        }
        ThreadPoolMgr::SetThreadCount(0);
        ASSERT_TRUE(saved.front() == saved.back());

        const string &bytes = saved.front();
        vector<Serialization::SEALHeader> headers = saved_plaintext_headers(bytes);
        ASSERT_FALSE(headers.empty());
        for (const auto &header : headers) {
            ASSERT_EQ(compr_mode_type::zstd, header.compr_mode);
        }

        string uncompressed = with_plaintexts_in(bytes, params, compr_mode_type::none);
        ASSERT_EQ(size_t(4196680), uncompressed.size());
        ASSERT_EQ(expected_uncompressed, blake2b_256(uncompressed));

        // The plaintexts are as recorded, so only Zstandard can explain a difference here
        if ((bytes.size() != 3595288) || (blake2b_256(bytes) != expected)) {
            GTEST_SKIP() << "The plaintexts are as recorded, but this version of Zstandard "
                            "compresses them otherwise than the one the hash was recorded with";
        }
    }
#endif

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
        // The first item goes in alone, so that the others are placed one at a time and fill
        // bins, rather than being packed into equally full BinBundles
        tag_db.insert_or_assign(items[0]);
        tag_db.insert_or_assign(vector<Item>(items.begin() + 1, items.end()));
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

    TEST(SenderDBTagTests, SaveForAPSI1xIsRefused)
    {
        // APSI 1.x cannot use match tags, so a SenderDB with match tags refuses
        // PlaintextSaveMode::apsi_1x before writing anything, compressed or not, as any SenderDB
        // refuses a mode that does not exist. Saved with PlaintextSaveMode::as_stored, it loads.
        PSIParams params = create_tag_params();
        for (bool compressed : { true, false }) {
            SenderDB sender_db(params, fixed_oprf_key(), 0, 0, compressed);
            sender_db.set_data(vector<Item>{ Item(1, 2), Item(3, 4) });

            stringstream ss;
            ASSERT_THROW(sender_db.save(ss, SenderDB::PlaintextSaveMode::apsi_1x), logic_error);
            ASSERT_TRUE(ss.str().empty());
            ASSERT_THROW(
                sender_db.save(ss, static_cast<SenderDB::PlaintextSaveMode>(2)), invalid_argument);
            ASSERT_TRUE(ss.str().empty());

            size_t save_size = sender_db.save(ss, SenderDB::PlaintextSaveMode::as_stored);
            ASSERT_EQ(ss.str().size(), save_size);
            ASSERT_EQ(sender_db.get_item_count(), SenderDB::Load(ss).first.get_item_count());
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
        Answers, from the SenderDB, the query that request holds as a StreamChannel sends it, and
        returns the result packages as the sender's StreamChannel writes them, in sorted order, as
        the order in which they are sent depends on the threads.
        */
        vector<string> answer_query(const shared_ptr<SenderDB> &sender_db, const string &request)
        {
            stringstream in(request);
            stringstream out;
            network::StreamChannel chl(in, out);
            Query query(
                to_query_request(chl.receive_operation(sender_db->get_seal_context())), sender_db);
            Sender::RunQuery(query, chl);

            network::StreamChannel response_chl(out, out);
            QueryResponse query_response = to_query_response(response_chl.receive_response());
            vector<string> packages;
            for (uint32_t i = 0; i < query_response->package_count; i++) {
                vector<unsigned char> package = apsi::util::read_from_stream(out);
                packages.emplace_back(package.begin(), package.end());
            }
            sort(packages.begin(), packages.end());
            return packages;
        }

        /**
        Collects the debug messages and the warnings logged while it exists, and restores the
        global logger and log level when it is destroyed.
        */
        class LogCapture {
        public:
            LogCapture() : saved_level_(GetLogLevel())
            {
                array<Logger::log_handler_t, Logger::level_count> log_handlers{};
                log_handlers[static_cast<size_t>(LogLevel::debug)] = [this](const string &msg) {
                    messages_.push_back(msg);
                };
                log_handlers[static_cast<size_t>(LogLevel::warning)] = [this](const string &msg) {
                    warnings_.push_back(msg);
                };
                SetLogger(Logger::Create(std::move(log_handlers), {}, {}));
                SetLogLevel(LogLevel::debug);
            }

            ~LogCapture()
            {
                CloseLogger();
                SetLogLevel(saved_level_);
            }

            LogCapture(const LogCapture &) = delete;

            LogCapture &operator=(const LogCapture &) = delete;

            /**
            Returns the sum of the numbers that follow the given text in the debug messages.
            */
            size_t sum(const string &text) const
            {
                size_t total = 0;
                for (const auto &msg : messages_) {
                    size_t pos = msg.find(text);
                    if (pos != string::npos) {
                        total += static_cast<size_t>(stoull(msg.substr(pos + text.size())));
                    }
                }
                return total;
            }

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

            [[nodiscard]] const vector<string> &messages() const
            {
                return messages_;
            }

            [[nodiscard]] const vector<string> &warnings() const
            {
                return warnings_;
            }

        private:
            LogLevel saved_level_;

            vector<string> messages_;

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
                LogCapture capture;
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
                LogCapture capture;
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
                ThrowingLog log(
                    { "finished processing bundle index",
                      "preprocessing",
                      "caches",
                      "polynomials" });
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

    TEST(SenderDBTests, SaveForAPSI1xLoadsAndAnswersAlike)
    {
        // Saved with SenderDB::PlaintextSaveMode::apsi_1x, a SenderDB without match tags writes
        // every plaintext as APSI 1.x stores it, with a header that Microsoft SEAL 4.0 loads:
        // compressed with Zstandard if the SenderDB is compressed, and otherwise uncompressed, so
        // that an uncompressed SenderDB is written as PlaintextSaveMode::as_stored writes it,
        // which is what SenderDB::save writes. Saving changes nothing in memory. The file loads
        // into a SenderDB with the same items and labels, which holds the plaintexts as they were
        // saved and answers a query with the same result packages as the SenderDB that was saved,
        // and as one loaded from what it saves as stored. This holds compressed or not, labeled or
        // not, stripped or not, and with Paterson-Stockmeyer. Without Zstandard, a compressed
        // SenderDB refuses the mode before writing anything.
        auto test_fun = [](const PSIParams &params,
                           size_t label_byte_count,
                           bool compressed,
                           bool strip) {
            SCOPED_TRACE(
                string(compressed ? "compressed" : "uncompressed") + ", label_byte_count " +
                to_string(label_byte_count) + (strip ? ", stripped" : ""));
            oprf::OPRFKey key = fixed_oprf_key();
            auto sender_db = make_shared<SenderDB>(params, key, label_byte_count, 16, compressed);

            vector<pair<Item, Label>> data;
            vector<Item> items;
            for (uint64_t i = 0; i < 300; i++) {
                items.emplace_back(i + 1, ~i);
                data.emplace_back(
                    items.back(), create_label(static_cast<unsigned char>(i), label_byte_count));
            }
            if (label_byte_count) {
                sender_db->set_data(data);
            } else {
                sender_db->set_data(items);
            }
            if (strip) {
                sender_db->strip();
            }

#ifdef SEAL_USE_ZSTD
            compr_mode_type apsi_1x_compr_mode =
                compressed ? compr_mode_type::zstd : compr_mode_type::none;
#else
            if (compressed) {
                stringstream ss;
                ASSERT_THROW(
                    sender_db->save(ss, SenderDB::PlaintextSaveMode::apsi_1x), invalid_argument);
                ASSERT_TRUE(ss.str().empty());
                return;
            }
            compr_mode_type apsi_1x_compr_mode = compr_mode_type::none;
#endif

            // PlaintextSaveMode::as_stored writes what SenderDB::save writes
            stringstream saved_ss;
            size_t saved_size = sender_db->save(saved_ss);
            string saved = saved_ss.str();

            stringstream as_stored_ss;
            ASSERT_EQ(
                saved_size, sender_db->save(as_stored_ss, SenderDB::PlaintextSaveMode::as_stored));
            ASSERT_TRUE(saved == as_stored_ss.str());

            // PlaintextSaveMode::apsi_1x writes every plaintext as APSI 1.x stores it, and changes
            // nothing in memory
            stringstream apsi_1x_ss;
            size_t apsi_1x_size = sender_db->save(apsi_1x_ss, SenderDB::PlaintextSaveMode::apsi_1x);
            ASSERT_EQ(apsi_1x_ss.str().size(), apsi_1x_size);
            if (!compressed) {
                ASSERT_TRUE(saved == apsi_1x_ss.str());
            }

            vector<Serialization::SEALHeader> headers = saved_plaintext_headers(apsi_1x_ss.str());
            ASSERT_FALSE(headers.empty());
            ASSERT_EQ(saved_plaintext_headers(saved).size(), headers.size());
            for (const auto &header : headers) {
                ASSERT_TRUE(Serialization::IsValidHeader(header));
                ASSERT_EQ(apsi_1x_compr_mode, header.compr_mode);
                ASSERT_EQ(4, header.version_major);
                ASSERT_EQ(0, header.version_minor);
            }

            stringstream again_ss;
            sender_db->save(again_ss);
            ASSERT_TRUE(saved == again_ss.str());

            // The file loads, and the SenderDB loaded keeps the plaintexts as they were saved
            auto [loaded_db, load_size] = SenderDB::Load(apsi_1x_ss);
            ASSERT_EQ(apsi_1x_size, load_size);
            ASSERT_EQ(sender_db->is_compressed(), loaded_db.is_compressed());
            ASSERT_EQ(sender_db->is_stripped(), loaded_db.is_stripped());
            ASSERT_EQ(sender_db->get_item_count(), loaded_db.get_item_count());
            ASSERT_EQ(sender_db->get_hashed_items(), loaded_db.get_hashed_items());
            ASSERT_EQ(sender_db->get_bin_bundle_count(), loaded_db.get_bin_bundle_count());
            if (label_byte_count && !strip) {
                for (const auto &[item, label] : data) {
                    ASSERT_EQ(label, loaded_db.get_label(item));
                }
            }

            stringstream resaved_ss;
            ASSERT_EQ(apsi_1x_size, loaded_db.save(resaved_ss));
            for (const auto &header : saved_plaintext_headers(resaved_ss.str())) {
                ASSERT_EQ(apsi_1x_compr_mode, header.compr_mode);
            }

            // Two items the SenderDB holds and one it does not
            vector<Item> query_items{ items[0], items[150], Item(1000, 1000) };
            vector<HashedItem> hashed_items;
            LabelKeyVector label_keys;
            for (const auto &item : query_items) {
                auto [hashed_item, label_key] = oprf::OPRFSender::GetItemHash(item, key);
                hashed_items.push_back(hashed_item);
                label_keys.push_back(label_key);
            }
            apsi::receiver::Receiver recv(params);
            auto [request, itt] = recv.create_query(hashed_items);
            stringstream request_ss;
            network::StreamChannel request_chl(request_ss);
            request_chl.send(std::move(request));

            // The three SenderDBs answer with the same result packages, which find the items
            vector<string> packages = answer_query(sender_db, request_ss.str());
            ASSERT_TRUE(
                packages ==
                answer_query(
                    make_shared<SenderDB>(SenderDB::Load(saved_ss).first), request_ss.str()));
            ASSERT_TRUE(
                packages ==
                answer_query(make_shared<SenderDB>(std::move(loaded_db)), request_ss.str()));

            vector<ResultPart> result;
            for (const auto &package : packages) {
                stringstream package_ss(package);
                auto result_part = make_unique<network::ResultPackage>();
                result_part->load(package_ss, recv.get_seal_context(), params);
                result.push_back(std::move(result_part));
            }
            vector<apsi::receiver::MatchRecord> records =
                recv.process_result(label_keys, itt, result);
            ASSERT_TRUE(records[0].found);
            ASSERT_TRUE(records[1].found);
            ASSERT_FALSE(records[2].found);
            if (label_byte_count) {
                ASSERT_EQ(data[0].second, records[0].label.value());
                ASSERT_EQ(data[150].second, records[1].label.value());
            }
        };

        // Shallow bins keep the noise of the results low enough to decrypt
        PSIParams params = with_shallow_bins(*get_params1(), 3);
        test_fun(params, 0, true, false);
        test_fun(params, 20, true, false);
        test_fun(params, 20, false, false);
        test_fun(params, 20, true, true);
        test_fun(create_apsi1x_kat_params(), 12, true, false);
        test_fun(create_apsi1x_kat_params(), 12, false, false);
    }

    namespace {
        /**
        Parameters with match tags and 13 bits per item that can be queried: every power up to
        max_items_per_bin is sent, so that the sender multiplies no two ciphertexts, which the
        single 54-bit prime has no room for. The table holds one bundle index.
        */
        PSIParams create_queryable_tag_params(
            uint32_t felts_per_item,
            uint32_t tag_part_count,
            uint32_t hash_func_count,
            uint32_t max_items_per_bin)
        {
            PSIParams::ItemParams item_params;
            item_params.felts_per_item = felts_per_item;
            item_params.tag_part_count = tag_part_count;

            PSIParams::TableParams table_params;
            table_params.hash_func_count = hash_func_count;
            table_params.max_items_per_bin = max_items_per_bin;
            table_params.table_size = 2048 / felts_per_item;

            PSIParams::QueryParams query_params;
            for (uint32_t power = 1; power <= max_items_per_bin; power++) {
                query_params.query_powers.insert(power);
            }

            PSIParams::SEALParams seal_params;
            seal_params.set_poly_modulus_degree(2048);
            seal_params.set_coeff_modulus(CoeffModulus::Create(2048, { 54 }));
            seal_params.set_plain_modulus(12289);

            return { item_params, table_params, query_params, seal_params };
        }

        /**
        Returns the hash functions with which a SenderDB with the given parameters finds the
        locations of an item. Making one takes time, so they are made once for many items.
        */
        vector<kuku::LocFunc> hash_functions_of(const PSIParams &params)
        {
            vector<kuku::LocFunc> hash_funcs;
            for (uint32_t i = 0; i < params.table_params().hash_func_count; i++) {
                hash_funcs.emplace_back(params.table_params().table_size, kuku::make_item(i, 0));
            }
            return hash_funcs;
        }

        /**
        Returns the locations of a HashedItem in the order in which a SenderDB with the given
        parameters processes them, as pairs of a bundle index and the first bin of the location.
        The order matters to newest-first placement when two locations share a bundle index.
        */
        vector<pair<uint32_t, size_t>> places_in_insertion_order(
            const HashedItem &hashed_item,
            const PSIParams &params,
            const vector<kuku::LocFunc> &hash_funcs)
        {
            kuku::item_type kuku_item;
            memcpy(&kuku_item, hashed_item.value().data(), sizeof(kuku_item));

            unordered_set<kuku::location_type> locations;
            for (const auto &hash_func : hash_funcs) {
                locations.emplace(hash_func(kuku_item));
            }

            vector<pair<uint32_t, size_t>> places;
            for (auto location : locations) {
                places.emplace_back(
                    location / params.items_per_bundle(),
                    (location % params.items_per_bundle()) * params.item_params().felts_per_item);
            }
            return places;
        }

        /**
        Computes what a SenderDB with the given OPRF key and parameters stores of each of the
        given items, as view_of does, for many items at once.
        */
        vector<TaggedItemView> views_of(
            const vector<Item> &items, const oprf::OPRFKey &key, const PSIParams &params)
        {
            size_t felts_per_item = params.item_params().felts_per_item;
            auto hashes_and_tags = oprf::OPRFSender::ComputeHashesAndMatchTags(
                items,
                key,
                params.tag_part_count() * felts_per_item,
                params.item_bit_count_per_felt());

            vector<kuku::LocFunc> hash_funcs = hash_functions_of(params);
            vector<TaggedItemView> views;
            views.reserve(items.size());
            for (auto &[hashed_item, tag] : hashes_and_tags) {
                TaggedItemView view;
                view.hashed_item = hashed_item;
                view.felts = apsi::util::algebraize_item(
                    hashed_item, params.item_bit_count(), params.seal_params().plain_modulus());
                view.tag = std::move(tag);
                for (const auto &place :
                     places_in_insertion_order(hashed_item, params, hash_funcs)) {
                    view.places.push_back(place);
                }
                sort(view.places.begin(), view.places.end());
                views.push_back(std::move(view));
            }
            return views;
        }

        /**
        Computes what a SenderDB with the given OPRF key and parameters stores of items, as
        views_of does, and keeps what it has computed: a view takes hashing its item with the
        OPRF, which is most of what checking where items are stored costs when the same items are
        checked again.
        */
        class ViewCache {
        public:
            ViewCache(const oprf::OPRFKey &key, const PSIParams &params)
                : key_(key), params_(params)
            {}

            [[nodiscard]] const PSIParams &params() const
            {
                return params_;
            }

            /**
            Returns the views of the given items, in the same order
            */
            vector<TaggedItemView> of(const vector<Item> &items)
            {
                vector<Item> missing;
                for (const auto &item : items) {
                    if (views_.find(item) == views_.end()) {
                        missing.push_back(item);
                    }
                }

                vector<TaggedItemView> computed = views_of(missing, key_, params_);
                for (size_t i = 0; i < missing.size(); i++) {
                    views_.emplace(missing[i], std::move(computed[i]));
                }

                vector<TaggedItemView> views;
                views.reserve(items.size());
                for (const auto &item : items) {
                    views.push_back(views_.at(item));
                }
                return views;
            }

        private:
            oprf::OPRFKey key_;

            PSIParams params_;

            unordered_map<Item, TaggedItemView> views_;
        };

        /**
        Returns how many BinBundles each bundle index would have if the given batches of items,
        none of them stored before, were inserted one after another into an empty SenderDB with
        match tags that places items newest BinBundle first and never moves one: at each
        location, an item goes into the newest BinBundle whose bins there have room and hold
        none of its field elements, and into a new BinBundle if there is none.
        */
        vector<size_t> newest_first_bundle_counts(
            ViewCache &views, const vector<vector<Item>> &batches)
        {
            const PSIParams &params = views.params();
            size_t max_items_per_bin = params.table_params().max_items_per_bin;
            size_t felts_per_item = params.item_params().felts_per_item;

            // For each bundle index, the BinBundles; for each of them, the field elements of the
            // items at each location, by the first bin of the location
            vector<vector<unordered_map<size_t, vector<vector<apsi::util::felt_t>>>>> bundles(
                params.bundle_idx_count());
            vector<kuku::LocFunc> hash_funcs = hash_functions_of(params);
            for (const auto &batch : batches) {
                for (const auto &view : views.of(batch)) {
                    const vector<apsi::util::felt_t> &felts = view.felts;
                    for (const auto &[bundle_idx, start_bin] :
                         places_in_insertion_order(view.hashed_item, params, hash_funcs)) {
                        auto &bundle_set = bundles[bundle_idx];
                        bool placed = false;
                        for (size_t i = bundle_set.size(); !placed && (i-- > 0);) {
                            auto &stored = bundle_set[i][start_bin];
                            bool clash = any_of(stored.begin(), stored.end(), [&](const auto &s) {
                                for (size_t j = 0; j < felts_per_item; j++) {
                                    if (s[j] == felts[j]) {
                                        return true;
                                    }
                                }
                                return false;
                            });
                            if ((stored.size() < max_items_per_bin) && !clash) {
                                stored.push_back(felts);
                                placed = true;
                            }
                        }
                        if (!placed) {
                            bundle_set.emplace_back();
                            bundle_set.back()[start_bin].push_back(felts);
                        }
                    }
                }
            }

            vector<size_t> counts;
            for (const auto &bundle_set : bundles) {
                counts.push_back(bundle_set.size());
            }
            return counts;
        }

        /**
        Returns the fewest BinBundles that each bundle index can hold the given items in, with one
        field element per item: no BinBundle holds more than max_items_per_bin items in a bin, or
        a field element twice in one, so a bin of n items in which no field element appears more
        than m times needs max(ceil(n / max_items_per_bin), m) of them.
        */
        vector<size_t> fewest_bundle_counts(ViewCache &views, const vector<Item> &items)
        {
            const PSIParams &params = views.params();
            size_t max_items_per_bin = params.table_params().max_items_per_bin;
            map<pair<uint32_t, size_t>, map<apsi::util::felt_t, size_t>> bins;
            for (const auto &view : views.of(items)) {
                for (const auto &place : view.places) {
                    bins[place][view.felts[0]]++;
                }
            }

            vector<size_t> counts(params.bundle_idx_count(), 0);
            for (const auto &[place, felt_counts] : bins) {
                size_t item_count = 0;
                size_t repeat_count = 0;
                for (const auto &felt_count : felt_counts) {
                    item_count += felt_count.second;
                    repeat_count = max(repeat_count, felt_count.second);
                }
                size_t fill_count = (item_count + max_items_per_bin - 1) / max_items_per_bin;
                counts[place.first] = max({ counts[place.first], fill_count, repeat_count });
            }
            return counts;
        }

        /**
        Returns the BinBundles of a SenderDB with match tags that is not stripped, read back from
        what it saves, by bundle index and in the order the SenderDB keeps them.
        */
        vector<vector<BinBundle>> saved_bin_bundles(const SenderDB &sender_db)
        {
            const PSIParams &params = sender_db.get_params();
            stringstream ss;
            sender_db.save(ss);
            static_cast<void>(apsi::util::read_from_stream(ss));

            CryptoContext crypto_context(params);
            crypto_context.set_evaluator();
            size_t label_part_count = params.tag_part_count();
            if (sender_db.is_labeled()) {
                size_t label_bit_count =
                    (sender_db.get_nonce_byte_count() + sender_db.get_label_byte_count()) * 8;
                label_part_count +=
                    (label_bit_count + params.item_bit_count() - 1) / params.item_bit_count();
            }

            vector<vector<BinBundle>> bundles(params.bundle_idx_count());
            for (size_t i = 0; i < sender_db.get_bin_bundle_count(); i++) {
                vector<unsigned char> data = apsi::util::read_from_stream(ss);
                BinBundle bundle(
                    crypto_context,
                    label_part_count,
                    params.table_params().max_items_per_bin,
                    params.query_params().ps_low_degree,
                    params.bins_per_bundle(),
                    sender_db.is_compressed(),
                    false,
                    params.tag_part_count());
                uint32_t bundle_idx = bundle.load(data).first;
                bundles.at(bundle_idx).push_back(std::move(bundle));
            }
            return bundles;
        }

        /**
        Checks everything a SenderDB with match tags that is not stripped stores against what it
        should store: in every bin, distinct field elements, at most max_items_per_bin of them,
        each with its HashedItem and every label part; each of the given items at each of its
        locations in exactly one BinBundle, found there by BinBundle::multi_contains, with its tag
        and the same label parts at every location; and nothing else. If labels are given,
        SenderDB::get_label must give them, for every item or, of many, for a sample of about a
        hundred: the label parts are checked for every item above, and get_label hashes each item
        it is given with the OPRF.
        */
        void check_tag_layout(
            SenderDB &sender_db,
            ViewCache &views,
            const vector<Item> &items,
            const unordered_map<Item, Label> *labels = nullptr)
        {
            const PSIParams &params = sender_db.get_params();
            vector<vector<BinBundle>> bundles = saved_bin_bundles(sender_db);

            size_t stored_count = 0;
            for (const auto &bundle_set : bundles) {
                for (const BinBundle &bundle : bundle_set) {
                    ASSERT_FALSE(bundle.empty());
                    const auto &item_bins = bundle.get_item_bins();
                    const auto &hashed_item_bins = bundle.get_hashed_item_bins();
                    for (size_t bin = 0; bin < item_bins.size(); bin++) {
                        const auto &item_bin = item_bins[bin];
                        ASSERT_LE(item_bin.size(), params.table_params().max_items_per_bin);
                        ASSERT_EQ(item_bin.size(), hashed_item_bins[bin].size());
                        set<apsi::util::felt_t> distinct(item_bin.begin(), item_bin.end());
                        ASSERT_EQ(item_bin.size(), distinct.size()) << "bin " << bin;
                        for (const auto &label_bins : bundle.get_label_bins()) {
                            ASSERT_EQ(item_bin.size(), label_bins[bin].size());
                        }
                        stored_count += item_bin.size();
                    }
                }
            }

            size_t expected_count = 0;
            for (const auto &view : views.of(items)) {
                vector<apsi::util::felt_t> first_alg_label;
                for (const auto &[bundle_idx, start_bin] : view.places) {
                    expected_count += params.item_params().felts_per_item;
                    size_t holder_count = 0;
                    for (const BinBundle &bundle : bundles[bundle_idx]) {
                        if (!bundle.multi_contains(view.felts, view.hashed_item, start_bin)) {
                            continue;
                        }
                        holder_count++;

                        vector<apsi::util::felt_t> alg_label;
                        ASSERT_TRUE(bundle.try_get_multi_label(
                            view.felts, view.hashed_item, start_bin, alg_label));
                        ASSERT_TRUE(equal(view.tag.begin(), view.tag.end(), alg_label.begin()));
                        if (first_alg_label.empty()) {
                            first_alg_label = alg_label;
                        }
                        ASSERT_EQ(first_alg_label, alg_label);
                    }
                    ASSERT_EQ(1, holder_count);
                }
            }
            ASSERT_EQ(expected_count, stored_count);

            if (labels) {
                size_t step = max<size_t>(1, items.size() / 100);
                for (size_t i = 0; i < items.size(); i += step) {
                    ASSERT_EQ(labels->at(items[i]), sender_db.get_label(items[i]));
                }
            }
        }

        /**
        Returns, for each of the given items and each of its locations, the position at its
        bundle index of the BinBundle that holds it there: what changes when an item is moved.
        */
        vector<vector<size_t>> holders_of(
            const SenderDB &sender_db, ViewCache &views, const vector<Item> &items)
        {
            vector<vector<BinBundle>> bundles = saved_bin_bundles(sender_db);
            vector<vector<size_t>> holders;
            for (const auto &view : views.of(items)) {
                holders.emplace_back();
                for (const auto &[bundle_idx, start_bin] : view.places) {
                    const auto &bundle_set = bundles[bundle_idx];
                    size_t holder = bundle_set.size();
                    for (size_t i = 0; i < bundle_set.size(); i++) {
                        if (bundle_set[i].multi_contains(view.felts, view.hashed_item, start_bin)) {
                            holder = i;
                        }
                    }
                    holders.back().push_back(holder);
                }
            }
            return holders;
        }

        // What the debug messages of an insertion say
        const string moved_text = " BinBundles; moved ";
        const string declined_text = "items to make room; declined ";
        const string opened_text = "; opened ";
        const string regenerated_text = "Regenerated the caches of ";

        /**
        Searches the items Item(i, 0x5eed), for i from 1 to candidate_count, for four at one
        location of parameters with a single hash function, so that inserted one at a time into
        bins that hold two items, a and b fill a first BinBundle, c goes into a second, and d
        fits into neither, as it shares a field element with c, while it would fit into the
        first BinBundle had a been moved to the second: a and b share no field element with each
        other or with d, and a shares none with c. Returns them in the order a, b, c, d, or
        nothing if there are none.
        */
        vector<Item> find_items_forcing_a_move(
            const PSIParams &params, const oprf::OPRFKey &key, uint64_t candidate_count)
        {
            vector<Item> candidates;
            for (uint64_t i = 1; i <= candidate_count; i++) {
                candidates.emplace_back(i, 0x5eed);
            }
            vector<TaggedItemView> views = views_of(candidates, key, params);

            map<pair<uint32_t, size_t>, vector<size_t>> by_place;
            for (size_t i = 0; i < candidates.size(); i++) {
                by_place[views[i].places.front()].push_back(i);
            }
            auto share = [&](size_t x, size_t y) {
                for (size_t j = 0; j < views[x].felts.size(); j++) {
                    if (views[x].felts[j] == views[y].felts[j]) {
                        return true;
                    }
                }
                return false;
            };

            for (const auto &entry : by_place) {
                const vector<size_t> &at = entry.second;
                for (size_t c : at) {
                    for (size_t d : at) {
                        if ((c == d) || !share(c, d)) {
                            continue;
                        }
                        for (size_t a : at) {
                            if ((a == c) || (a == d) || share(a, c) || share(a, d)) {
                                continue;
                            }
                            for (size_t b : at) {
                                if ((b != a) && (b != c) && (b != d) && !share(b, a) &&
                                    !share(b, d)) {
                                    return {
                                        candidates[a], candidates[b], candidates[c], candidates[d]
                                    };
                                }
                            }
                        }
                    }
                }
            }
            return {};
        }

        vector<Item> make_items(uint64_t first, size_t count)
        {
            vector<Item> items;
            for (uint64_t i = first; i < first + count; i++) {
                items.emplace_back(i, 0xc0ffee);
            }
            return items;
        }
    } // namespace

    TEST(SenderDBTagTests, BulkInsertionUsesTheFewestBinBundlesPossible)
    {
        // With one field element per item, the items inserted into a bundle index that holds no
        // BinBundles go into as few as any placement can use: in each bin, max(ceil(n / K), m),
        // for n items of which no field element appears more than m times. Nothing is moved, and
        // every BinBundle is generated once.
        oprf::OPRFKey key = fixed_oprf_key();
        for (uint32_t hash_func_count : { 1U, 3U }) {
            PSIParams params = create_tag_params(1, 4, hash_func_count, 16, 1024, 12289, 2);
            ViewCache views(key, params);
            vector<Item> items = make_items(1, hash_func_count == 1 ? 12000 : 6000);
            vector<size_t> fewest = fewest_bundle_counts(views, items);
            vector<size_t> newest = newest_first_bundle_counts(views, { items });

            for (size_t label_byte_count : { 0U, 8U }) {
                SenderDB sender_db(params, key, label_byte_count, 16, true);
                unordered_map<Item, Label> labels;
                {
                    LogCapture capture;
                    if (label_byte_count) {
                        vector<pair<Item, Label>> data;
                        for (const auto &item : items) {
                            labels[item] = create_label(
                                static_cast<unsigned char>(labels.size()), label_byte_count);
                            data.emplace_back(item, labels[item]);
                        }
                        sender_db.set_data(data);
                    } else {
                        sender_db.set_data(items);
                    }
                    ASSERT_EQ(0, capture.sum(moved_text));
                    ASSERT_EQ(sender_db.get_bin_bundle_count(), capture.sum(regenerated_text));
                }

                for (uint32_t b = 0; b < params.bundle_idx_count(); b++) {
                    ASSERT_EQ(fewest[b], sender_db.get_bin_bundle_count(b));
                    ASSERT_LE(fewest[b], newest[b]);
                }
                ASSERT_NO_FATAL_FAILURE(check_tag_layout(
                    sender_db, views, items, label_byte_count ? &labels : nullptr));
            }
        }
    }

    TEST(SenderDBTagTests, ItemsAreMovedOnlyBetweenBinBundlesTheBatchChanges)
    {
        // Bins hold two items, and four items share a location: inserted one at a time, a and b
        // fill a first BinBundle, c goes into a second, and d fits into neither, as it shares a
        // field element with c. Moving a to the second BinBundle makes room for d in the first.
        for (uint32_t felts_per_item : { 1U, 2U }) {
            PSIParams params =
                create_queryable_tag_params(felts_per_item, 4 / felts_per_item, 1, 2);
            oprf::OPRFKey key = fixed_oprf_key();
            ViewCache views(key, params);
            vector<Item> all = find_items_forcing_a_move(params, key, 10000);
            ASSERT_EQ(4, all.size());
            const Item &a = all[0];
            const Item &b = all[1];
            const Item &c = all[2];
            const Item &d = all[3];
            uint32_t bundle_idx = view_of(a, key, params).places.front().first;

            // Newest-first placement needs three BinBundles for them, inserted at once or not.
            // Inserted at once, they go into two: with one field element per item they are
            // packed, and otherwise every BinBundle is new and a is moved for d.
            ASSERT_EQ(3, newest_first_bundle_counts(views, { all })[bundle_idx]);
            ASSERT_EQ(
                3, newest_first_bundle_counts(views, { { a }, { b }, { c }, { d } })[bundle_idx]);
            {
                SenderDB sender_db(params, key, 0, 0, true);
                LogCapture capture;
                sender_db.set_data(all);
                ASSERT_EQ(2, sender_db.get_bin_bundle_count(bundle_idx));
                ASSERT_EQ(felts_per_item == 1 ? 0 : 1, capture.sum(moved_text));
                ASSERT_NO_FATAL_FAILURE(check_tag_layout(sender_db, views, all));
            }

            // Inserted alone, d would need a to be moved between two BinBundles whose caches are
            // valid, and both would be regenerated in full. It goes into a third BinBundle
            // instead, which costs almost nothing to generate.
            {
                SenderDB sender_db(params, key, 0, 0, true);
                for (const auto &item : { a, b, c }) {
                    sender_db.insert_or_assign(item);
                }
                ASSERT_EQ(2, sender_db.get_bin_bundle_count(bundle_idx));
                LogCapture capture;
                sender_db.insert_or_assign(d);
                ASSERT_EQ(3, sender_db.get_bin_bundle_count(bundle_idx));
                ASSERT_EQ(1, capture.sum(declined_text));
                ASSERT_EQ(0, capture.sum(moved_text));
                ASSERT_EQ(1, capture.sum(regenerated_text));
                ASSERT_NO_FATAL_FAILURE(check_tag_layout(sender_db, views, all));
            }

            // A batch that also updates the labels of a and c changes both BinBundles anyway, and
            // then moves a to make room for d
            auto sender_db = make_shared<SenderDB>(params, key, 8, 16, true);
            unordered_map<Item, Label> labels;
            unsigned char next_label = 1;
            auto label = [&](const Item &item) {
                labels[item] = create_label(next_label++, 8);
                return make_pair(item, labels[item]);
            };
            for (const auto &item : { a, b, c }) {
                sender_db->insert_or_assign(label(item));
            }
            vector<vector<size_t>> before = holders_of(*sender_db, views, { a, b, c });
            {
                LogCapture capture;
                sender_db->insert_or_assign(
                    vector<pair<Item, Label>>{ label(a), label(c), label(d) });
                ASSERT_EQ(1, capture.sum(moved_text));
                ASSERT_EQ(0, capture.sum(opened_text));
                ASSERT_EQ(2, capture.sum(regenerated_text));
            }
            ASSERT_EQ(2, sender_db->get_bin_bundle_count(bundle_idx));
            vector<vector<size_t>> after = holders_of(*sender_db, views, all);
            ASSERT_EQ(size_t(0), before[0][0]);
            ASSERT_EQ(size_t(1), after[0][0]);
            ASSERT_EQ(before[1], after[1]);
            ASSERT_EQ(before[2], after[2]);
            ASSERT_EQ(size_t(0), after[3][0]);
            ASSERT_NO_FATAL_FAILURE(check_tag_layout(*sender_db, views, all, &labels));

            // A query finds every item with its label, and nothing else. With a single hash
            // function, items at one location go into separate queries.
            for (const auto &item : all) {
                ASSERT_EQ(
                    vector<vector<Label>>{ { labels.at(item) } },
                    query_labels(sender_db, key, { item }));
            }
            ASSERT_EQ(
                vector<vector<Label>>{ {} }, query_labels(sender_db, key, { Item(0, 0x5eed) }));

            // The moved item is updated and removed where it now is
            sender_db->insert_or_assign(vector<pair<Item, Label>>{ label(a), label(d) });
            ASSERT_NO_FATAL_FAILURE(check_tag_layout(*sender_db, views, all, &labels));
            sender_db->remove(a);
            ASSERT_FALSE(sender_db->has_item(a));
            ASSERT_NO_FATAL_FAILURE(check_tag_layout(*sender_db, views, { b, c, d }, &labels));

            // And the same holds after a save and a load
            stringstream ss;
            sender_db->save(ss);
            SenderDB loaded = SenderDB::Load(ss).first;
            ASSERT_NO_FATAL_FAILURE(check_tag_layout(loaded, views, { b, c, d }, &labels));
            loaded.remove(vector<Item>{ b, c, d });
            ASSERT_EQ(0, loaded.get_bin_bundle_count());
        }
    }

    TEST(SenderDBTagTests, DenseUpdatesKeepEveryItemInItsPlace)
    {
        // With 13 bits per field element and small bins, items often share field elements, bins
        // fill up, and batches move items to make room. Whatever happens, every item stays at
        // each of its locations, exactly once, with its tag and label, every bin holds distinct
        // field elements, and no more BinBundles are used than newest-first placement would use.
        // With one field element per item, the first batch goes in alone so that the next one is
        // placed newest-first and moves items, rather than being packed.
        //
        // The layout is checked at the end of each phase of updates rather than after each
        // update. An item lost, stored twice, or stored without its tag or label stays so, as
        // nothing later puts it right, so the check at the end of the phase finds it.
        oprf::OPRFKey key = fixed_oprf_key();
        size_t moved_count = 0;
        for (uint32_t felts_per_item : { 1U, 4U }) {
            PSIParams params =
                create_tag_params(felts_per_item, 4 / felts_per_item, 3, 32, 1024, 12289);
            ViewCache views(key, params);
            size_t label_byte_count = (felts_per_item == 1) ? 8 : 0;
            SenderDB sender_db(params, key, label_byte_count, 16, true);
            unordered_map<Item, Label> labels;
            unsigned char next_label = 0;

            auto store = [&](const vector<Item> &items) {
                if (!label_byte_count) {
                    sender_db.insert_or_assign(items);
                    return;
                }

                vector<pair<Item, Label>> data;
                for (const auto &item : items) {
                    labels[item] = create_label(next_label++, label_byte_count);
                    data.emplace_back(item, labels[item]);
                }
                sender_db.insert_or_assign(data);
            };

            auto check = [&](SenderDB &db, const vector<Item> &items) {
                ASSERT_EQ(items.size(), db.get_item_count());
                ASSERT_NO_FATAL_FAILURE(
                    check_tag_layout(db, views, items, label_byte_count ? &labels : nullptr));
            };

            // Insert the batches one after another
            size_t first_count = (felts_per_item == 1) ? 20000 : 6000;
            vector<vector<Item>> batches{ make_items(1, 1),
                                          make_items(2, first_count),
                                          make_items(first_count + 2, 300),
                                          make_items(first_count + 302, 3) };
            vector<Item> items;
            for (const auto &batch : batches) {
                LogCapture capture;
                store(batch);
                moved_count += capture.sum(moved_text);
                items.insert(items.end(), batch.begin(), batch.end());
                ASSERT_EQ(items.size(), sender_db.get_item_count());
            }

            ASSERT_NO_FATAL_FAILURE(check(sender_db, items));
            vector<size_t> newest = newest_first_bundle_counts(views, batches);
            for (uint32_t b = 0; b < params.bundle_idx_count(); b++) {
                ASSERT_LE(sender_db.get_bin_bundle_count(b), newest[b]);
            }

            // Remove a fifth of the items and insert as many new ones, twice
            for (uint64_t round = 0; round < 2; round++) {
                vector<Item> removed;
                vector<Item> kept;
                for (size_t i = 0; i < items.size(); i++) {
                    ((i % 5 == round) ? removed : kept).push_back(items[i]);
                }
                sender_db.remove(removed);
                ASSERT_EQ(kept.size(), sender_db.get_item_count());

                vector<Item> added = make_items(1000000 * (round + 1), removed.size());
                LogCapture capture;
                store(added);
                moved_count += capture.sum(moved_text);
                kept.insert(kept.end(), added.begin(), added.end());
                items = kept;
            }

            ASSERT_NO_FATAL_FAILURE(check(sender_db, items));

            // Updating every label finds every item where it is
            if (label_byte_count) {
                store(items);
                ASSERT_NO_FATAL_FAILURE(check(sender_db, items));
            }

            // A save and a load keep everything, and the loaded SenderDB can be changed
            stringstream ss;
            sender_db.save(ss);
            SenderDB loaded = SenderDB::Load(ss).first;
            ASSERT_EQ(sender_db.get_bin_bundle_count(), loaded.get_bin_bundle_count());
            ASSERT_NO_FATAL_FAILURE(check(loaded, items));

            loaded.remove(items);
            ASSERT_EQ(0, loaded.get_bin_bundle_count());
        }

        // The batches moved items
        ASSERT_LT(size_t(0), moved_count);
    }

    TEST(SenderDBTagTests, QueriesFindMovedItems)
    {
        // A query finds a moved item, with its label, where it now is, also once the SenderDB is
        // stripped, saved and loaded, and finds no item that is not stored. Items of four field
        // elements share one often enough for a bulk insertion to move many of them.
        PSIParams params = create_queryable_tag_params(4, 1, 3, 32);
        oprf::OPRFKey key = fixed_oprf_key();
        ViewCache views(key, params);
        auto sender_db = make_shared<SenderDB>(params, key, 8, 16, true);

        unordered_map<Item, Label> labels;
        unsigned char next_label = 0;
        auto store = [&](const vector<Item> &items) {
            vector<pair<Item, Label>> data;
            for (const auto &item : items) {
                labels[item] = create_label(next_label++, 8);
                data.emplace_back(item, labels[item]);
            }
            sender_db->insert_or_assign(data);
        };

        // Find the items that inserting more items moves
        vector<Item> items = make_items(1, 9000);
        store(items);
        vector<vector<size_t>> before = holders_of(*sender_db, views, items);
        {
            LogCapture capture;
            vector<Item> added = make_items(9001, 3000);
            store(added);
            ASSERT_LT(size_t(0), capture.sum(moved_text));
            items.insert(items.end(), added.begin(), added.end());
        }
        vector<vector<size_t>> after = holders_of(*sender_db, views, items);
        vector<Item> moved;
        for (size_t i = 0; i < before.size(); i++) {
            if (before[i] != after[i]) {
                moved.push_back(items[i]);
            }
        }
        ASSERT_LT(size_t(0), moved.size());
        ASSERT_NO_FATAL_FAILURE(check_tag_layout(*sender_db, views, items, &labels));

        // Query the moved items, as many other stored items, and as many that are not stored
        vector<Item> queried(
            moved.begin(), moved.begin() + static_cast<ptrdiff_t>(min<size_t>(moved.size(), 60)));
        size_t moved_queried = queried.size();
        unordered_set<Item> chosen(queried.begin(), queried.end());
        for (size_t i = 0; (i < items.size()) && (queried.size() < 2 * moved_queried); i += 101) {
            if (chosen.insert(items[i]).second) {
                queried.push_back(items[i]);
            }
        }
        size_t stored_count = queried.size();
        vector<Item> absent = make_items(5000000, stored_count);
        queried.insert(queried.end(), absent.begin(), absent.end());
        auto query = [&](const shared_ptr<SenderDB> &db) {
            vector<vector<Label>> results = query_labels(db, key, queried);
            for (size_t i = 0; i < queried.size(); i++) {
                if (i < stored_count) {
                    ASSERT_EQ(vector<Label>{ labels.at(queried[i]) }, results[i]) << "item " << i;
                } else {
                    ASSERT_TRUE(results[i].empty()) << "item " << i;
                }
            }
        };
        ASSERT_NO_FATAL_FAILURE(query(sender_db));

        sender_db->strip();
        stringstream ss;
        sender_db->save(ss);
        auto loaded = make_shared<SenderDB>(SenderDB::Load(ss).first);
        ASSERT_TRUE(loaded->is_stripped());
        ASSERT_NO_FATAL_FAILURE(query(loaded));
    }

    namespace {
        /**
        Checks that every bin bundle of a SenderDB that is not stripped holds the cache it would
        generate from nothing: each bin bundle the SenderDB saves is read back, its cache is
        cleared and generated again, and it is saved again, which must give the same bytes. The
        SenderDB then saves exactly what it would save had every bin bundle generated its cache
        from nothing, holding the same items in the same places.
        */
        void check_caches_as_from_scratch(const SenderDB &sender_db)
        {
            const PSIParams &params = sender_db.get_params();
            stringstream ss;
            sender_db.save(ss);
            string bytes = ss.str();

            CryptoContext crypto_context(params);
            crypto_context.set_evaluator();
            size_t label_part_count = params.tag_part_count();
            if (sender_db.is_labeled()) {
                size_t label_bit_count =
                    (sender_db.get_nonce_byte_count() + sender_db.get_label_byte_count()) * 8;
                label_part_count +=
                    (label_bit_count + params.item_bit_count() - 1) / params.item_bit_count();
            }

            // A saved SenderDB is a size-prefixed header followed by the size-prefixed bin bundles
            size_t offset = prefixed_size_at(bytes, 0);
            string rebuilt = bytes.substr(0, offset);
            size_t bundle_count = 0;
            while (offset < bytes.size()) {
                string saved = bytes.substr(offset, prefixed_size_at(bytes, offset));
                offset += saved.size();
                BinBundle bundle(
                    crypto_context,
                    label_part_count,
                    params.table_params().max_items_per_bin,
                    params.query_params().ps_low_degree,
                    params.bins_per_bundle(),
                    sender_db.is_compressed(),
                    false,
                    params.tag_part_count());
                stringstream in(saved);
                uint32_t bundle_idx = bundle.load(in).first;
                ASSERT_FALSE(bundle.cache_invalid());

                bundle.clear_cache();
                bundle.regen_cache();

                stringstream out;
                bundle.save(out, bundle_idx);
                ASSERT_TRUE(saved == out.str())
                    << "bin bundle " << bundle_count << " at bundle index " << bundle_idx
                    << " differs from the one generated from nothing";
                rebuilt += out.str();
                bundle_count++;
            }
            ASSERT_EQ(sender_db.get_bin_bundle_count(), bundle_count);
            ASSERT_TRUE(rebuilt == bytes);
        }

        /**
        Returns how many of the BinBundles whose caches were regenerated, by the given debug
        messages, computed the polynomials of some of their bins but not of all of them.
        */
        size_t partial_regen_count(const vector<string> &messages)
        {
            const string text = "Computing the polynomials of ";
            size_t count = 0;
            for (const auto &msg : messages) {
                if (msg.rfind(text, 0) != 0) {
                    continue;
                }
                size_t computed = static_cast<size_t>(stoull(msg.substr(text.size())));
                size_t total = static_cast<size_t>(
                    stoull(msg.substr(msg.find(" of ", text.size()) + string(" of ").size())));
                count += (computed < total) ? 1 : 0;
            }
            return count;
        }

        /**
        What run_random_updates saw happen: how many bin bundles regenerated their caches
        computing the polynomials of some of their bins only, and how many items were moved
        */
        struct UpdateCounts {
            size_t partial_regens = 0;

            size_t moves = 0;
        };

        /**
        Updates a SenderDB at random, starting from initial_count items, with every kind of update:
        insertions of batches of new items, from one to batch_size_max of them, the first of them
        of batch_size_max; label updates of stored items, alone or with new items, which without
        labels change nothing; removals; removals followed by as many insertions; and saving and
        loading. After every fourth update, checks that every bin bundle holds the cache it would
        generate from nothing, and that a query finds the stored items with their labels and no
        other. Finally strips the SenderDB, saves and loads it, and queries it again.

        Checking after every fourth update rather than after each keeps the test fast, and loses
        little. A bin bundle whose cache has polynomials that do not fit its bins, as a change
        that was not marked leaves them, warns as it regenerates the cache, and any warning fails
        the test. A label polynomial that is stale but fits stays so until the next check, unless
        a later update changes its bin again.
        */
        void run_random_updates(
            const PSIParams &params,
            size_t label_byte_count,
            bool compressed,
            size_t initial_count,
            size_t batch_size_max,
            uint64_t seed,
            size_t rounds,
            UpdateCounts &counts)
        {
            oprf::OPRFKey key = fixed_oprf_key();
            auto sender_db = make_shared<SenderDB>(params, key, label_byte_count, 16, compressed);
            mt19937_64 rng(seed);
            auto uniform = [&](uint64_t bound) {
                return uniform_int_distribution<uint64_t>(0, bound - 1)(rng);
            };

            // The items stored, with their labels
            unordered_map<Item, Label> stored;
            uint64_t next_item = 1;

            auto new_items = [&](size_t count) {
                vector<Item> items;
                for (size_t i = 0; i < count; i++) {
                    items.emplace_back(next_item++, 0xd1d1);
                }
                return items;
            };

            auto stored_items = [&](size_t count) {
                vector<Item> items;
                for (const auto &item_label : stored) {
                    items.push_back(item_label.first);
                }
                sort(items.begin(), items.end(), [](const Item &a, const Item &b) {
                    return a.value() < b.value();
                });
                shuffle(items.begin(), items.end(), rng);
                items.resize(min(count, items.size()));
                return items;
            };

            auto batch_size = [&] {
                // From one item to batch_size_max, about evenly in orders of magnitude
                size_t size = 1;
                for (uint64_t steps = uniform(5); steps && (size < batch_size_max); steps--) {
                    size = min(size * 10, batch_size_max);
                }
                return size;
            };

            auto store = [&](const vector<Item> &items) {
                if (!label_byte_count) {
                    sender_db->insert_or_assign(items);
                    for (const auto &item : items) {
                        stored[item] = {};
                    }
                    return;
                }

                vector<pair<Item, Label>> data;
                for (const auto &item : items) {
                    Label label(label_byte_count);
                    for (auto &byte : label) {
                        byte = static_cast<unsigned char>(uniform(256));
                    }
                    data.emplace_back(item, std::move(label));
                }
                sender_db->insert_or_assign(data);
                for (auto &item_label : data) {
                    stored[item_label.first] = std::move(item_label.second);
                }
            };

            auto remove = [&](const vector<Item> &items) {
                if (items.empty()) {
                    return;
                }
                sender_db->remove(items);
                for (const auto &item : items) {
                    stored.erase(item);
                }
            };

            auto query = [&] {
                vector<Item> queried = stored_items(30);
                size_t stored_count = queried.size();
                vector<Item> absent = new_items(10);
                queried.insert(queried.end(), absent.begin(), absent.end());

                vector<vector<Label>> results = query_labels(sender_db, key, queried);
                for (size_t i = 0; i < queried.size(); i++) {
                    if (i < stored_count) {
                        ASSERT_EQ(vector<Label>{ stored.at(queried[i]) }, results[i])
                            << "item " << i;
                    } else {
                        ASSERT_TRUE(results[i].empty()) << "item " << i;
                    }
                }
            };

            LogCapture capture;
            store(new_items(initial_count));
            ASSERT_NO_FATAL_FAILURE(check_caches_as_from_scratch(*sender_db));
            ASSERT_NO_FATAL_FAILURE(query());

            for (size_t round = 0; round < rounds; round++) {
                bool check = (round % 4 == 3);

                // The first update inserts as many new items as a batch can have, which into a
                // full SenderDB is what makes room by moving items
                switch (round ? uniform(5) : 0) {
                case 0:
                    store(new_items(round ? batch_size() : batch_size_max));
                    break;

                case 1: {
                    vector<Item> items = stored_items(batch_size());
                    if (uniform(2)) {
                        vector<Item> fresh = new_items(batch_size());
                        items.insert(items.end(), fresh.begin(), fresh.end());
                    }
                    store(items);
                    break;
                }

                case 2:
                    remove(stored_items(batch_size()));
                    break;

                case 3: {
                    // The insertions could change again the bins the removals changed, so the
                    // removals are checked on their own
                    vector<Item> items = stored_items(batch_size());
                    remove(items);
                    if (check) {
                        ASSERT_NO_FATAL_FAILURE(check_caches_as_from_scratch(*sender_db));
                    }
                    store(new_items(items.size()));
                    break;
                }

                default: {
                    stringstream ss;
                    sender_db->save(ss);
                    sender_db = make_shared<SenderDB>(SenderDB::Load(ss).first);
                    break;
                }
                }

                ASSERT_EQ(stored.size(), sender_db->get_item_count());
                if (check) {
                    ASSERT_NO_FATAL_FAILURE(check_caches_as_from_scratch(*sender_db));
                    ASSERT_NO_FATAL_FAILURE(query());
                }
            }
            counts.partial_regens = partial_regen_count(capture.messages());
            counts.moves = capture.sum(moved_text);

            // No bin bundle found polynomials it could not keep, which would mean that a change
            // did not mark the bins it changed
            for (const auto &warning : capture.warnings()) {
                ASSERT_NE(0, warning.rfind("The cache of a BinBundle", 0)) << warning;
            }

            sender_db->strip();
            stringstream ss;
            sender_db->save(ss);
            sender_db = make_shared<SenderDB>(SenderDB::Load(ss).first);
            ASSERT_NO_FATAL_FAILURE(query());
        }
    } // namespace

    TEST(SenderDBTests, UpdatesRegenerateCachesAsFromScratch)
    {
        // Without match tags, labeled and not, compressed and not. After every fourth update,
        // every bin bundle holds the cache it would generate from nothing, and some of them
        // computed the polynomials of only the bins the updates changed.
        uint64_t seed = 1;
        for (size_t label_byte_count : { 0U, 20U }) {
            for (bool compressed : { true, false }) {
                SCOPED_TRACE(
                    "label_byte_count " + to_string(label_byte_count) + ", compressed " +
                    to_string(compressed));
                UpdateCounts counts;
                ASSERT_NO_FATAL_FAILURE(run_random_updates(
                    with_shallow_bins(*get_params1(), 3),
                    label_byte_count,
                    compressed,
                    300,
                    50,
                    seed++,
                    12,
                    counts));
                ASSERT_LT(0, counts.partial_regens);
            }
        }
    }

    TEST(SenderDBTagTests, UpdatesRegenerateCachesAsFromScratch)
    {
        // With match tags, labeled and not, with items of one field element, which a SenderDB
        // packs into as few bin bundles as possible when it is empty, and of four, where batches
        // move items between bin bundles to make room for others, as do bulk insertions. Items of
        // four field elements are moved only once the SenderDB is fairly full, so there are 9000
        // of them to begin with, and 4500 of one field element, which are packed instead.
        uint64_t seed = 100;
        for (uint32_t felts_per_item : { 1U, 4U }) {
            PSIParams params =
                create_queryable_tag_params(felts_per_item, 4 / felts_per_item, 3, 32);
            size_t initial_count = (felts_per_item == 1) ? 4500 : 9000;
            for (size_t label_byte_count : { 0U, 8U }) {
                SCOPED_TRACE(
                    "felts_per_item " + to_string(felts_per_item) + ", label_byte_count " +
                    to_string(label_byte_count));
                UpdateCounts counts;
                ASSERT_NO_FATAL_FAILURE(run_random_updates(
                    params,
                    label_byte_count,
                    label_byte_count == 0,
                    initial_count,
                    initial_count / 3,
                    seed++,
                    12,
                    counts));
                ASSERT_LT(0, counts.partial_regens);
                if (felts_per_item > 1) {
                    ASSERT_LT(0, counts.moves);
                }
            }
        }
    }

    namespace {
        /**
        Returns the bytes the SenderDB saves as.
        */
        string saved(const SenderDB &sender_db)
        {
            stringstream ss;
            sender_db.save(ss);
            return ss.str();
        }

        /**
        Returns the items, each with a label of label_byte_count bytes.
        */
        vector<pair<Item, Label>> with_labels(const vector<Item> &items, size_t label_byte_count)
        {
            vector<pair<Item, Label>> data;
            for (size_t i = 0; i < items.size(); i++) {
                data.emplace_back(
                    items[i], create_label(static_cast<unsigned char>(i), label_byte_count));
            }
            return data;
        }

        /**
        Returns the number of field elements in a match tag for the parameters.
        */
        size_t tag_felt_count(const PSIParams &params)
        {
            return params.tag_part_count() * params.item_params().felts_per_item;
        }
    } // namespace

    TEST(SenderDBTests, ClearingAStrippedSenderDBGivesItANewKey)
    {
        // strip() zeroes the OPRF key, under which every item hashes to the same value. A cleared
        // stripped SenderDB becomes as a newly constructed one, with a new key of its own.
        // set_data, like insert_or_assign and remove, refuses a stripped SenderDB and leaves it as
        // it was. With match tags and without them, labeled and not.
        oprf::OPRFKey zero_key;
        zero_key.clear();
        for (bool tags : { false, true }) {
            PSIParams params = tags ? create_tag_params() : *get_params1();
            for (size_t label_byte_count : { 0U, 8U }) {
                SCOPED_TRACE(
                    string(tags ? "with" : "without") + " match tags, label_byte_count " +
                    to_string(label_byte_count));
                SenderDB sender_db(params, label_byte_count, 16);
                vector<Item> items = make_items(1, 10);
                vector<pair<Item, Label>> data = with_labels(items, label_byte_count);
                auto set_data = [&]() {
                    if (label_byte_count) {
                        sender_db.set_data(data);
                    } else {
                        sender_db.set_data(items);
                    }
                };
                set_data();
                oprf::OPRFKey old_key = sender_db.strip();
                string before = saved(sender_db);

                ASSERT_THROW(set_data(), logic_error);
                ASSERT_THROW(static_cast<void>(sender_db.strip()), logic_error);
                ASSERT_TRUE(sender_db.is_stripped());
                ASSERT_THROW(static_cast<void>(sender_db.get_oprf_key()), logic_error);
                ASSERT_TRUE(before == saved(sender_db));

                sender_db.clear();
                ASSERT_FALSE(sender_db.is_stripped());
                ASSERT_EQ(size_t(0), sender_db.get_item_count());
                oprf::OPRFKey new_key = sender_db.get_oprf_key();
                ASSERT_TRUE(new_key != zero_key);
                ASSERT_TRUE(new_key != old_key);

                set_data();
                ASSERT_EQ(items.size(), sender_db.get_item_count());
                ASSERT_EQ(items.size(), sender_db.get_hashed_items().size());
                for (const auto &item : items) {
                    ASSERT_TRUE(sender_db.has_item(item));
                }
                ASSERT_FALSE(sender_db.has_item(Item(999, 999)));
                ASSERT_EQ(
                    size_t(1),
                    sender_db.get_hashed_items().count(
                        oprf::OPRFSender::ComputeHashes(vector<Item>{ items[0] }, new_key)[0]));
            }
        }
    }

    TEST(SenderDBTests, AZeroOPRFKeyIsRefused)
    {
        // Under a zero OPRF key every item hashes to the same value. A SenderDB is not created
        // with one, and one that is not stripped but holds one, as APSI 1.1.0 could save, is not
        // loaded. A stripped SenderDB holds the zeros that strip() left, and loads.
        auto params = get_params1();
        oprf::OPRFKey zero_key;
        zero_key.clear();
        ASSERT_THROW(SenderDB(*params, zero_key, 0), invalid_argument);
        ASSERT_THROW(SenderDB(*params, zero_key, 8, 16), invalid_argument);

        SenderDB sender_db(*params, fixed_oprf_key(), 0);
        sender_db.set_data(make_items(1, 10));
        string bytes = saved(sender_db);
        {
            stringstream ss(bytes);
            ASSERT_NO_THROW(SenderDB::Load(ss));
        }
        const auto *sdb = fbs::GetSizePrefixedSenderDB(bytes.data());
        auto key_offset = reinterpret_cast<const char *>(sdb->oprf_key()->data()) - bytes.data();
        fill_n(bytes.begin() + key_offset, oprf::oprf_key_size, '\0');
        stringstream zeroed(bytes);
        ASSERT_THROW(SenderDB::Load(zeroed), runtime_error);

        sender_db.strip();
        stringstream stripped(saved(sender_db));
        SenderDB loaded = SenderDB::Load(stripped).first;
        ASSERT_TRUE(loaded.is_stripped());
        ASSERT_THROW(static_cast<void>(loaded.strip()), logic_error);
    }

    TEST(SenderDBTests, SetDataLeavesTheDatabaseAsItWasWhenItRefusesTheBatch)
    {
        // set_data checks the SenderDB and the batch, as insert_or_assign does, before it clears
        // anything
        auto params = get_params1();
        vector<Item> items = make_items(1, 10);
        vector<pair<Item, Label>> data = with_labels(items, 8);

        SenderDB labeled(*params, 8, 16);
        labeled.set_data(data);
        string labeled_before = saved(labeled);
        vector<pair<Item, Label>> duplicated{ { Item(7, 7), create_label(1, 8) },
                                              { Item(7, 7), create_label(2, 8) } };
        ASSERT_THROW(labeled.set_data(duplicated), invalid_argument);
        vector<pair<Item, Label>> too_long{ { Item(3, 3), create_label(3, 9) } };
        ASSERT_THROW(labeled.set_data(too_long), invalid_argument);
        ASSERT_THROW(labeled.set_data(items), logic_error);
        ASSERT_TRUE(labeled_before == saved(labeled));
        ASSERT_EQ(data.size(), labeled.get_item_count());

        SenderDB unlabeled(*params, 0);
        unlabeled.set_data(items);
        string unlabeled_before = saved(unlabeled);
        ASSERT_THROW(unlabeled.set_data(data), logic_error);
        ASSERT_TRUE(unlabeled_before == saved(unlabeled));

        // A batch that is taken replaces everything
        labeled.set_data(vector<pair<Item, Label>>{ { Item(100, 100), create_label(1, 8) } });
        ASSERT_EQ(size_t(1), labeled.get_item_count());
        ASSERT_TRUE(labeled.has_item(Item(100, 100)));
        ASSERT_FALSE(labeled.has_item(items[0]));
    }

    TEST(SenderDBTests, HashedItemsMakeTheSameSenderDB)
    {
        // Items hashed with OPRFSender::ComputeHashes, with their labels encrypted there, make the
        // same SenderDB, byte for byte, as the items themselves do, when they are inserted, their
        // labels replaced, and removed. The labels are encrypted without a nonce, as a nonce is
        // drawn at random.
        auto params = get_params1();
        oprf::OPRFKey key = fixed_oprf_key();
        vector<Item> items = make_items(1, 300);
        vector<Item> removed(items.begin(), items.begin() + 100);

        SenderDB unlabeled(*params, key, 0);
        SenderDB unlabeled_hashed(*params, key, 0);
        unlabeled.set_data(items);
        unlabeled_hashed.set_data_hashed(oprf::OPRFSender::ComputeHashes(items, key));
        ASSERT_TRUE(saved(unlabeled) == saved(unlabeled_hashed));

        // Items already there, and an item given twice, are inserted once
        vector<Item> more = make_items(1000, 20);
        more.insert(more.end(), items.begin(), items.begin() + 10);
        more.push_back(more.front());
        unlabeled.insert_or_assign(more);
        unlabeled_hashed.insert_or_assign_hashed(oprf::OPRFSender::ComputeHashes(more, key));
        ASSERT_EQ(size_t(320), unlabeled_hashed.get_item_count());
        ASSERT_TRUE(saved(unlabeled) == saved(unlabeled_hashed));

        unlabeled.remove(removed);
        unlabeled_hashed.remove_hashed(oprf::OPRFSender::ComputeHashes(removed, key));
        ASSERT_EQ(size_t(220), unlabeled_hashed.get_item_count());
        ASSERT_TRUE(saved(unlabeled) == saved(unlabeled_hashed));

        vector<pair<Item, Label>> data = with_labels(items, 16);
        SenderDB labeled(*params, key, 16, 0);
        SenderDB labeled_hashed(*params, key, 16, 0);
        labeled.set_data(data);
        labeled_hashed.set_data_hashed(oprf::OPRFSender::ComputeHashes(data, key, 16, 0));
        ASSERT_TRUE(saved(labeled) == saved(labeled_hashed));

        // New labels for items already there, and new items, one with a short label, which is
        // padded where it is encrypted
        vector<pair<Item, Label>> update;
        for (size_t i = 0; i < 50; i++) {
            update.emplace_back(
                items[2 * i], create_label(static_cast<unsigned char>(i + 100), 16));
        }
        update.emplace_back(Item(5000, 5000), Label{ 1, 2, 3 });
        labeled.insert_or_assign(update);
        labeled_hashed.insert_or_assign_hashed(oprf::OPRFSender::ComputeHashes(update, key, 16, 0));
        ASSERT_TRUE(saved(labeled) == saved(labeled_hashed));
        Label padded(16);
        copy_n(update.back().second.begin(), 3, padded.begin());
        ASSERT_EQ(padded, labeled_hashed.get_label(Item(5000, 5000)));
        ASSERT_EQ(update.front().second, labeled_hashed.get_label(items[0]));

        labeled.remove(removed);
        labeled_hashed.remove_hashed(oprf::OPRFSender::ComputeHashes(removed, key));
        ASSERT_TRUE(saved(labeled) == saved(labeled_hashed));

        // With a nonce the bytes differ, but the labels decrypt alike
        SenderDB nonced(*params, key, 16, 16);
        nonced.set_data_hashed(oprf::OPRFSender::ComputeHashes(data, key, 16, 16));
        for (const auto &[item, label] : data) {
            ASSERT_EQ(label, nonced.get_label(item));
        }
    }

    TEST(SenderDBTagTests, HashedItemsMakeTheSameSenderDB)
    {
        // As without match tags, with the tags computed by OPRFSender::ComputeHashesAndMatchTags
        // where the items are hashed
        PSIParams params = create_tag_params();
        oprf::OPRFKey key = fixed_oprf_key();
        size_t felt_count = tag_felt_count(params);
        uint32_t bits_per_felt = params.item_bit_count_per_felt();
        vector<Item> items = make_items(1, 300);
        vector<Item> removed(items.begin(), items.begin() + 100);

        SenderDB unlabeled(params, key, 0);
        SenderDB unlabeled_hashed(params, key, 0);
        unlabeled.set_data(items);
        unlabeled_hashed.set_data_hashed(
            oprf::OPRFSender::ComputeHashesAndMatchTags(items, key, felt_count, bits_per_felt));
        ASSERT_TRUE(saved(unlabeled) == saved(unlabeled_hashed));

        // Items already there, and an item given twice with its tag, are inserted once
        vector<Item> more = make_items(1000, 20);
        more.insert(more.end(), items.begin(), items.begin() + 10);
        more.push_back(more.front());
        unlabeled.insert_or_assign(more);
        unlabeled_hashed.insert_or_assign_hashed(
            oprf::OPRFSender::ComputeHashesAndMatchTags(more, key, felt_count, bits_per_felt));
        ASSERT_EQ(size_t(320), unlabeled_hashed.get_item_count());
        ASSERT_TRUE(saved(unlabeled) == saved(unlabeled_hashed));

        unlabeled.remove(removed);
        unlabeled_hashed.remove_hashed(oprf::OPRFSender::ComputeHashes(removed, key));
        ASSERT_TRUE(saved(unlabeled) == saved(unlabeled_hashed));

        vector<pair<Item, Label>> data = with_labels(items, 20);
        SenderDB labeled(params, key, 20, 0);
        SenderDB labeled_hashed(params, key, 20, 0);
        labeled.set_data(data);
        labeled_hashed.set_data_hashed(
            oprf::OPRFSender::ComputeHashesAndMatchTags(
                data, key, 20, 0, felt_count, bits_per_felt));
        ASSERT_TRUE(saved(labeled) == saved(labeled_hashed));

        vector<pair<Item, Label>> update;
        for (size_t i = 0; i < 50; i++) {
            update.emplace_back(
                items[2 * i], create_label(static_cast<unsigned char>(i + 100), 20));
        }
        update.emplace_back(Item(5000, 5000), create_label(7, 20));
        labeled.insert_or_assign(update);
        labeled_hashed.insert_or_assign_hashed(
            oprf::OPRFSender::ComputeHashesAndMatchTags(
                update, key, 20, 0, felt_count, bits_per_felt));
        ASSERT_TRUE(saved(labeled) == saved(labeled_hashed));

        labeled.remove(removed);
        labeled_hashed.remove_hashed(oprf::OPRFSender::ComputeHashes(removed, key));
        ASSERT_TRUE(saved(labeled) == saved(labeled_hashed));
    }

    TEST(SenderDBTests, HashedItemsThatDoNotFitAreRefused)
    {
        auto params = get_params1();
        oprf::OPRFKey key = fixed_oprf_key();
        vector<Item> items = make_items(1, 10);
        vector<pair<Item, Label>> data = with_labels(items, 8);
        vector<pair<HashedItem, vector<apsi::util::felt_t>>> tagged{
            { HashedItem(1, 1), vector<apsi::util::felt_t>(8) }
        };
        vector<tuple<HashedItem, EncryptedLabel, vector<apsi::util::felt_t>>> tagged_labeled{
            { HashedItem(1, 1), EncryptedLabel(12), vector<apsi::util::felt_t>(8) }
        };

        // Data for the other kind of SenderDB, or with match tags, which the parameters do not use
        SenderDB unlabeled(*params, key, 0);
        SenderDB labeled(*params, key, 8, 4);
        ASSERT_THROW(
            unlabeled.insert_or_assign_hashed(oprf::OPRFSender::ComputeHashes(data, key, 8, 4)),
            logic_error);
        ASSERT_THROW(unlabeled.insert_or_assign_hashed(tagged), logic_error);
        ASSERT_THROW(unlabeled.insert_or_assign_hashed(tagged_labeled), logic_error);
        ASSERT_THROW(
            labeled.insert_or_assign_hashed(oprf::OPRFSender::ComputeHashes(items, key)),
            logic_error);
        ASSERT_THROW(labeled.insert_or_assign_hashed(tagged), logic_error);
        ASSERT_THROW(labeled.insert_or_assign_hashed(tagged_labeled), logic_error);
        ASSERT_EQ(size_t(0), unlabeled.get_item_count());
        ASSERT_EQ(size_t(0), labeled.get_item_count());

        // An encrypted label of the wrong size, an item given twice, or an item to remove that is
        // not there, is refused with its whole batch
        unlabeled.set_data(items);
        labeled.set_data(data);
        string unlabeled_before = saved(unlabeled);
        string labeled_before = saved(labeled);
        auto hashed =
            oprf::OPRFSender::ComputeHashes(with_labels(make_items(100, 5), 8), key, 8, 4);
        size_t encrypted_label_byte_count = hashed.back().second.size();
        for (size_t size : { encrypted_label_byte_count - 1, encrypted_label_byte_count + 1 }) {
            auto resized = hashed;
            resized.back().second.resize(size);
            ASSERT_THROW(labeled.insert_or_assign_hashed(resized), invalid_argument);
        }
        ASSERT_THROW(
            labeled.insert_or_assign_hashed(
                oprf::OPRFSender::ComputeHashes(with_labels(make_items(100, 5), 8), key, 8, 0)),
            invalid_argument);
        auto twice = hashed;
        twice.push_back(hashed.front());
        ASSERT_THROW(labeled.insert_or_assign_hashed(twice), invalid_argument);
        ASSERT_THROW(labeled.set_data_hashed(twice), invalid_argument);
        ASSERT_THROW(
            labeled.set_data_hashed(oprf::OPRFSender::ComputeHashes(items, key)), logic_error);
        vector<Item> partly_missing{ items[0], Item(9999, 9999) };
        ASSERT_THROW(
            labeled.remove_hashed(oprf::OPRFSender::ComputeHashes(partly_missing, key)),
            logic_error);
        ASSERT_THROW(
            unlabeled.remove_hashed(oprf::OPRFSender::ComputeHashes(partly_missing, key)),
            logic_error);
        ASSERT_TRUE(labeled_before == saved(labeled));
        ASSERT_TRUE(unlabeled_before == saved(unlabeled));

        // A label longer than the SenderDB holds is refused where it is encrypted, as
        // insert_or_assign refuses it, rather than truncated
        ASSERT_THROW(
            oprf::OPRFSender::ComputeHashes(with_labels(make_items(100, 5), 9), key, 8, 4),
            invalid_argument);

        // A stripped SenderDB takes nothing, and stays stripped
        labeled.strip();
        unlabeled.strip();
        ASSERT_THROW(labeled.insert_or_assign_hashed(hashed), logic_error);
        ASSERT_THROW(labeled.set_data_hashed(hashed), logic_error);
        ASSERT_THROW(
            labeled.remove_hashed(oprf::OPRFSender::ComputeHashes(items, key)), logic_error);
        ASSERT_THROW(
            unlabeled.insert_or_assign_hashed(oprf::OPRFSender::ComputeHashes(items, key)),
            logic_error);
        ASSERT_THROW(
            unlabeled.set_data_hashed(oprf::OPRFSender::ComputeHashes(items, key)), logic_error);
        ASSERT_THROW(
            unlabeled.remove_hashed(oprf::OPRFSender::ComputeHashes(items, key)), logic_error);
        ASSERT_TRUE(labeled.is_stripped());
        ASSERT_TRUE(unlabeled.is_stripped());
    }

    TEST(SenderDBTagTests, HashedItemsThatDoNotFitAreRefused)
    {
        PSIParams params = create_tag_params();
        oprf::OPRFKey key = fixed_oprf_key();
        size_t felt_count = tag_felt_count(params);
        uint32_t bits_per_felt = params.item_bit_count_per_felt();
        vector<Item> items = make_items(1, 10);
        vector<pair<Item, Label>> data = with_labels(items, 10);

        // Data without match tags, or for the other kind of SenderDB
        SenderDB unlabeled(params, key, 0);
        SenderDB labeled(params, key, 10, 16);
        ASSERT_THROW(
            unlabeled.insert_or_assign_hashed(oprf::OPRFSender::ComputeHashes(items, key)),
            logic_error);
        ASSERT_THROW(
            labeled.insert_or_assign_hashed(oprf::OPRFSender::ComputeHashes(data, key, 10, 16)),
            logic_error);
        ASSERT_THROW(
            unlabeled.insert_or_assign_hashed(
                oprf::OPRFSender::ComputeHashesAndMatchTags(
                    data, key, 10, 16, felt_count, bits_per_felt)),
            logic_error);
        ASSERT_THROW(
            labeled.insert_or_assign_hashed(
                oprf::OPRFSender::ComputeHashesAndMatchTags(items, key, felt_count, bits_per_felt)),
            logic_error);
        ASSERT_EQ(size_t(0), unlabeled.get_item_count());
        ASSERT_EQ(size_t(0), labeled.get_item_count());

        // A tag of the wrong length or with a field element out of range, or an item given twice
        // with different tags, is refused with its whole batch
        unlabeled.set_data(items);
        string unlabeled_before = saved(unlabeled);
        auto tagged = oprf::OPRFSender::ComputeHashesAndMatchTags(
            make_items(100, 5), key, felt_count, bits_per_felt);
        auto shorter = tagged;
        shorter.back().second.pop_back();
        ASSERT_THROW(unlabeled.insert_or_assign_hashed(shorter), invalid_argument);
        auto longer = tagged;
        longer.back().second.push_back(0);
        ASSERT_THROW(unlabeled.insert_or_assign_hashed(longer), invalid_argument);
        auto out_of_range = tagged;
        out_of_range.back().second.back() = uint64_t(1) << bits_per_felt;
        ASSERT_THROW(unlabeled.insert_or_assign_hashed(out_of_range), invalid_argument);
        auto conflicting = tagged;
        conflicting.push_back(tagged.front());
        conflicting.back().second.front() ^= 1;
        ASSERT_THROW(unlabeled.insert_or_assign_hashed(conflicting), invalid_argument);
        ASSERT_TRUE(unlabeled_before == saved(unlabeled));

        // The same tag given twice is inserted once
        auto repeated = tagged;
        repeated.push_back(tagged.front());
        unlabeled.insert_or_assign_hashed(repeated);
        ASSERT_EQ(size_t(15), unlabeled.get_item_count());

        // The same checks, and that of the encrypted labels, in a labeled SenderDB
        labeled.set_data(data);
        string labeled_before = saved(labeled);
        auto tagged_labeled = oprf::OPRFSender::ComputeHashesAndMatchTags(
            with_labels(make_items(100, 5), 10), key, 10, 16, felt_count, bits_per_felt);
        auto short_label = tagged_labeled;
        get<1>(short_label.back()).pop_back();
        ASSERT_THROW(labeled.insert_or_assign_hashed(short_label), invalid_argument);
        auto short_tag = tagged_labeled;
        get<2>(short_tag.back()).pop_back();
        ASSERT_THROW(labeled.insert_or_assign_hashed(short_tag), invalid_argument);
        auto tag_out_of_range = tagged_labeled;
        get<2>(tag_out_of_range.back()).front() = uint64_t(1) << bits_per_felt;
        ASSERT_THROW(labeled.insert_or_assign_hashed(tag_out_of_range), invalid_argument);
        auto twice = tagged_labeled;
        twice.push_back(tagged_labeled.front());
        ASSERT_THROW(labeled.insert_or_assign_hashed(twice), invalid_argument);
        ASSERT_THROW(labeled.set_data_hashed(twice), invalid_argument);
        ASSERT_TRUE(labeled_before == saved(labeled));

        // A label longer than the SenderDB holds is refused where it is encrypted
        ASSERT_THROW(
            oprf::OPRFSender::ComputeHashesAndMatchTags(
                with_labels(make_items(100, 5), 11), key, 10, 16, felt_count, bits_per_felt),
            invalid_argument);
    }

    TEST(SenderDBTagTests, ReplacingTheLabelOfAHashedItemReplacesItsTag)
    {
        // The tag given with a new label for an item replaces the tag stored with the item. Tags
        // computed with the right key are the same each time, but a different one makes the item
        // invisible to receivers, which derive the tag from their own label keys.
        PSIParams params = create_queryable_tag_params(4, 1, 3, 32);
        oprf::OPRFKey key = fixed_oprf_key();
        size_t felt_count = tag_felt_count(params);
        uint32_t bits_per_felt = params.item_bit_count_per_felt();
        auto sender_db = make_shared<SenderDB>(params, key, 8, 16);
        vector<pair<Item, Label>> data = with_labels(make_items(1, 10), 8);
        sender_db->set_data_hashed(
            oprf::OPRFSender::ComputeHashesAndMatchTags(
                data, key, 8, 16, felt_count, bits_per_felt));
        ASSERT_EQ(
            (vector<vector<Label>>{ { data[0].second } }),
            query_labels(sender_db, key, { data[0].first }));

        auto replacement = oprf::OPRFSender::ComputeHashesAndMatchTags(
            vector<pair<Item, Label>>{ data[0] }, key, 8, 16, felt_count, bits_per_felt);
        get<2>(replacement[0])[0] ^= 1;
        sender_db->insert_or_assign_hashed(replacement);
        ASSERT_EQ(data.size(), sender_db->get_item_count());
        ASSERT_EQ((vector<vector<Label>>{ {} }), query_labels(sender_db, key, { data[0].first }));
        ASSERT_EQ(
            (vector<vector<Label>>{ { data[1].second } }),
            query_labels(sender_db, key, { data[1].first }));
    }

    TEST(SenderDBTests, SenderDBBuiltFromHashedItemsAnswersUnderTheirKey)
    {
        // A SenderDB built from items hashed elsewhere, with a key of its own, answers queries for
        // the key the items were hashed with, and not for its own, which is the one has_item and
        // get_label hash with. Without match tags and with them, labeled and not.
        oprf::OPRFKey key = fixed_oprf_key();
        for (bool tags : { false, true }) {
            PSIParams params = tags ? create_queryable_tag_params(4, 1, 3, 32) : *get_params1();
            size_t felt_count = tag_felt_count(params);
            uint32_t bits_per_felt = params.item_bit_count_per_felt();
            vector<Item> items = make_items(1, 100);
            vector<pair<Item, Label>> data = with_labels(items, 8);
            vector<Item> queried{ items[0], items[50], Item(5000, 5000) };

            for (bool labeled : { false, true }) {
                SCOPED_TRACE(
                    string(tags ? "with" : "without") + " match tags, " +
                    (labeled ? "labeled" : "unlabeled"));
                auto sender_db = make_shared<SenderDB>(params, labeled ? 8 : 0, 16);
                if (tags && labeled) {
                    sender_db->set_data_hashed(
                        oprf::OPRFSender::ComputeHashesAndMatchTags(
                            data, key, 8, 16, felt_count, bits_per_felt));
                } else if (tags) {
                    sender_db->set_data_hashed(
                        oprf::OPRFSender::ComputeHashesAndMatchTags(
                            items, key, felt_count, bits_per_felt));
                } else if (labeled) {
                    sender_db->set_data_hashed(oprf::OPRFSender::ComputeHashes(data, key, 8, 16));
                } else {
                    sender_db->set_data_hashed(oprf::OPRFSender::ComputeHashes(items, key));
                }

                Label label0 = labeled ? data[0].second : Label();
                Label label50 = labeled ? data[50].second : Label();
                ASSERT_EQ(
                    (vector<vector<Label>>{ { label0 }, { label50 }, {} }),
                    query_labels(sender_db, key, queried));

                ASSERT_EQ(
                    (vector<vector<Label>>{ {}, {}, {} }),
                    query_labels(sender_db, sender_db->get_oprf_key(), queried));
                ASSERT_FALSE(sender_db->has_item(items[0]));
                ASSERT_EQ(
                    size_t(1),
                    sender_db->get_hashed_items().count(
                        oprf::OPRFSender::ComputeHashes(vector<Item>{ items[0] }, key)[0]));
            }
        }
    }
} // namespace APSITests
