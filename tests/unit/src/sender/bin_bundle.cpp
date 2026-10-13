// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <numeric>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// APSI
#include "apsi/bin_bundle.h"
#include "apsi/bin_bundle_generated.h"
#include "apsi/log.h"
#include "apsi/util/db_encoding.h"

// SEAL
#include "seal/keygenerator.h"
#include "seal/util/uintarithsmallmod.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::sender;
using namespace apsi::util;
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
                table_params.max_items_per_bin = 16;
                table_params.table_size = 1024;

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
            // These parameters have a non-power-of-two felts_per_item

            static shared_ptr<PSIParams> params = nullptr;
            if (!params) {
                PSIParams::ItemParams item_params;
                item_params.felts_per_item = 7;

                PSIParams::TableParams table_params;
                table_params.hash_func_count = 3;
                table_params.max_items_per_bin = 16;
                table_params.table_size = 1170;

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

        bool find_in_bin(const vector<felt_t> &bin, felt_t element)
        {
            return find(bin.begin(), bin.end(), element) != bin.end();
        }

        vector<felt_t> create_label(size_t label_size, felt_t start)
        {
            vector<felt_t> ret(label_size);
            iota(ret.begin(), ret.end(), start);
            return ret;
        }

        vector<felt_t> zipper_merge(const vector<felt_t> &first, const vector<felt_t> &second)
        {
            if (first.size() != second.size()) {
                throw runtime_error("invalid sizes for zipper_merge");
            }

            vector<felt_t> ret;
            for (size_t i = 0; i < first.size(); i++) {
                ret.push_back(first[i]);
                ret.push_back(second[i]);
            }

            return ret;
        }

        vector<felt_t> zipper_merge(
            const vector<felt_t> &first, const vector<felt_t> &second, const vector<felt_t> &third)
        {
            if (first.size() != second.size() || first.size() != third.size()) {
                throw runtime_error("invalid sizes for zipper_merge");
            }

            vector<felt_t> ret;
            for (size_t i = 0; i < first.size(); i++) {
                ret.push_back(first[i]);
                ret.push_back(second[i]);
                ret.push_back(third[i]);
            }

            return ret;
        }
    } // namespace

    TEST(BinBundleTests, BatchedPlaintextPolynCreate)
    {
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
            CryptoContext context(*params);
            context.set_evaluator();

            BatchedPlaintextPolyn bpp(context);
            ASSERT_FALSE(bpp);

            vector<FEltPolyn> polyns;
            bpp = BatchedPlaintextPolyn(polyns, context, 0, true);
            ASSERT_TRUE(bpp);

            polyns.push_back({ 1, 2, 3 });
            polyns.push_back({ 1, 2 });
            polyns.push_back({ 3 });
            polyns.push_back({ 1, 2, 3, 4, 5 });
            bpp = BatchedPlaintextPolyn(polyns, context, 0, true);
            ASSERT_TRUE(bpp);
        };

        // Power-of-two felts_per_item
        test_fun(get_params1());

        // Non-power-of-two felts_per_item
        test_fun(get_params2());
    }

    TEST(BinBundleTests, BatchedPlaintextPolynEval)
    {
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
            CryptoContext context(*params);
            context.set_evaluator();

            vector<FEltPolyn> polyns;
            polyns.push_back({ 1, 2, 3 });
            polyns.push_back({ 1, 2 });
            polyns.push_back({ 3 });
            polyns.push_back({ 1, 2, 3, 4, 5 });
            BatchedPlaintextPolyn bpp(polyns, context, 0, true);
            ASSERT_TRUE(bpp);

            KeyGenerator keygen(*context.seal_context());
            const auto &sk = keygen.secret_key();
            context.set_secret(sk);

            Ciphertext zeros_ct;
            context.encryptor()->encrypt_zero_symmetric(zeros_ct);
            context.evaluator()->transform_to_ntt_inplace(zeros_ct);

            Plaintext ones_pt(1);
            ones_pt[0] = 1;
            Ciphertext ones_ct;
            context.encryptor()->encrypt_symmetric(ones_pt, ones_ct);
            context.evaluator()->transform_to_ntt_inplace(ones_ct);

            MemoryPoolHandle pool = MemoryManager::GetPool();
            vector<Ciphertext> ct_zeros_vec(5, zeros_ct);
            Ciphertext ct_eval = bpp.eval(ct_zeros_vec, pool);
            Plaintext zeros_pt2;
            context.decryptor()->decrypt(ct_eval, zeros_pt2);
            vector<uint64_t> result;
            context.encoder()->decode(zeros_pt2, result);
            ASSERT_EQ(1, result[0]);
            ASSERT_EQ(1, result[1]);
            ASSERT_EQ(3, result[2]);
            ASSERT_EQ(1, result[3]);
            ASSERT_TRUE(all_of(result.begin() + 4, result.end(), [](auto a) { return a == 0; }));

            vector<Ciphertext> ct_ones_vec(5, ones_ct);
            ct_eval = bpp.eval(ct_ones_vec, pool);
            Plaintext ones_pt2;
            context.decryptor()->decrypt(ct_eval, ones_pt2);
            context.encoder()->decode(ones_pt2, result);
            ASSERT_EQ(6, result[0]);
            ASSERT_EQ(3, result[1]);
            ASSERT_EQ(3, result[2]);
            ASSERT_EQ(15, result[3]);
            ASSERT_TRUE(all_of(result.begin() + 4, result.end(), [](auto a) { return a == 0; }));
        };

        // Power-of-two felts_per_item
        test_fun(get_params1());

        // Non-power-of-two felts_per_item
        test_fun(get_params2());
    }

    TEST(BinBundleTests, BinBundleUnlabeledCreate)
    {
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
            CryptoContext context(*params);

            // No evaluator set in context
            ASSERT_THROW(
                BinBundle bb(context, 0, 50, 0, params->bins_per_bundle(), true, false),
                invalid_argument);

            context.set_evaluator();
            BinBundle bb(context, 0, 50, 0, params->bins_per_bundle(), true, false);

            ASSERT_TRUE(bb.cache_invalid());
            bb.clear_cache();
            ASSERT_TRUE(bb.cache_invalid());

            // The cache is stale; cannot get it
            ASSERT_THROW(static_cast<void>(bb.get_cache()), logic_error);

            bb.regen_cache();
            const auto &cache = bb.get_cache();

            // The matching polynomial is set to a single constant zero polynomial since we haven't
            // inserted anything
            ASSERT_EQ(params->bins_per_bundle(), cache.felt_matching_polyns.size());
            ASSERT_TRUE(cache.felt_interp_polyns.empty());
            ASSERT_TRUE(cache.batched_matching_polyn);
            ASSERT_TRUE(cache.batched_interp_polyns.empty());
        };

        // Power-of-two felts_per_item
        test_fun(get_params1());

        // Non-power-of-two felts_per_item
        test_fun(get_params2());
    }

    TEST(BinBundleTests, BinBundleLabeledCreate)
    {
        auto test_fun = [&](const shared_ptr<PSIParams> &params, size_t label_size) {
            CryptoContext context(*params);

            // No evaluator set in context
            ASSERT_THROW(
                BinBundle bb(context, label_size, 50, 0, params->bins_per_bundle(), true, false),
                invalid_argument);

            context.set_evaluator();
            BinBundle bb(context, label_size, 50, 0, params->bins_per_bundle(), true, false);

            ASSERT_TRUE(bb.cache_invalid());
            bb.clear_cache();
            ASSERT_TRUE(bb.cache_invalid());

            // The cache is stale; cannot get it
            ASSERT_THROW(static_cast<void>(bb.get_cache()), logic_error);

            bb.regen_cache();
            const auto &cache = bb.get_cache();

            ASSERT_TRUE(cache.batched_matching_polyn);
            ASSERT_EQ(label_size, cache.batched_interp_polyns.size());

            for (const auto &bip : cache.batched_interp_polyns) {
                // Nothing has been inserted yet; we have a constant interpolation polynomial
                ASSERT_EQ(1, bip.batched_coeffs.size());
            }

            for (const auto &fip : cache.felt_interp_polyns) {
                // We have one (empty) vector allocated per bin
                ASSERT_EQ(params->bins_per_bundle(), fip.size());
            }
        };

        test_fun(get_params1(), 1);
        test_fun(get_params1(), 2);
        test_fun(get_params1(), 3);

        test_fun(get_params2(), 1);
        test_fun(get_params2(), 2);
        test_fun(get_params2(), 3);
    }

    TEST(BinBundleTests, BinBundleUnlabeledMultiInsert)
    {
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
            CryptoContext context(*params);
            context.set_evaluator();

            BinBundle bb(context, 0, 50, 0, params->bins_per_bundle(), true, false);
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());

            AlgItem values{ 1 };
            int res = bb.multi_insert_dry_run(values, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());

            values.push_back(1);
            res = bb.multi_insert_dry_run(values, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());

            values.push_back(2);
            res = bb.multi_insert_dry_run(values, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());

            values.resize(params->bins_per_bundle(), 1);
            res = bb.multi_insert_dry_run(values, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());

            // Overflowing
            res = bb.multi_insert_dry_run(values, 1);
            ASSERT_EQ(-1 /* error code */, res);
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());

            // Clear the values vector
            values.clear();
            values.push_back(1);

            // Now insert for real
            res = bb.multi_insert_for_real(values, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);
            ASSERT_TRUE(bb.cache_invalid());
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_FALSE(bb.empty());

            // Insert at index 1 so that we don't actually increase the max size
            values.push_back(1);
            res = bb.multi_insert_for_real(values, 1);
            ASSERT_EQ(1 /* largest bin size after insert */, res);
            ASSERT_TRUE(bb.cache_invalid());
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_FALSE(bb.empty());

            // Insert at index 2; the value 1 will intersect with the current bin but that's fine
            // in the unlabeled case.
            res = bb.multi_insert_for_real(values, 2);
            ASSERT_EQ(2 /* largest bin size after insert */, res);
            ASSERT_TRUE(bb.cache_invalid());
            ASSERT_FALSE(bb.empty());

            values.clear();
            values.push_back(2);
            values.push_back(3);
            res = bb.multi_insert_for_real(values, 1);
            ASSERT_EQ(3 /* largest bin size after insert */, res);
            ASSERT_TRUE(bb.cache_invalid());
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_FALSE(bb.empty());

            values.resize(params->bins_per_bundle(), 4);
            res = bb.multi_insert_for_real(values, 0);
            ASSERT_EQ(4 /* largest bin size after insert */, res);
            ASSERT_TRUE(bb.cache_invalid());
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_FALSE(bb.empty());

            // Overflowing
            res = bb.multi_insert_for_real(values, 1);
            ASSERT_EQ(-1 /* error code */, res);
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_FALSE(bb.empty());

            bb.clear();
            ASSERT_TRUE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());
        };

        // Power-of-two felts_per_item
        test_fun(get_params1());

        // Non-power-of-two felts_per_item
        test_fun(get_params2());
    }

    TEST(BinBundleTests, BinBundleLabeledMultiInsert)
    {
        auto test_fun = [&](const shared_ptr<PSIParams> &params, size_t label_size) {
            CryptoContext context(*params);
            context.set_evaluator();

            BinBundle bb(context, label_size, 50, 0, params->bins_per_bundle(), true, false);
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());

            AlgItemLabel values{ make_pair(1, create_label(label_size, 1)) };
            int res = bb.multi_insert_dry_run(values, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());

            // Nothing was inserted in the dry-run; verify that
            vector<felt_t> labels;
            bool bres = bb.try_get_multi_label({ 1 }, 0, labels);
            ASSERT_FALSE(bres);
            ASSERT_TRUE(labels.empty());

            // Attempt to insert with no label
            values.emplace_back(1, vector<felt_t>{});
            ASSERT_THROW(res = bb.multi_insert_dry_run(values, 0), invalid_argument);
            values.pop_back();

            // Attempt to insert wrong size label
            values.emplace_back(1, create_label(label_size + 1, 1));
            ASSERT_THROW(res = bb.multi_insert_dry_run(values, 0), invalid_argument);
            values.pop_back();

            values.emplace_back(1, create_label(label_size, 1));
            res = bb.multi_insert_dry_run(values, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());

            values.emplace_back(2, create_label(label_size, 2));
            res = bb.multi_insert_dry_run(values, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());

            values.resize(params->bins_per_bundle(), make_pair(1, create_label(label_size, 1)));
            res = bb.multi_insert_dry_run(values, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());

            // Overflowing
            res = bb.multi_insert_dry_run(values, 1);
            ASSERT_EQ(-1 /* error code */, res);
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());

            // Clear the values vector
            values.clear();
            values.emplace_back(1, create_label(label_size, 1));

            // Now insert for real
            res = bb.multi_insert_for_real(values, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);
            ASSERT_TRUE(bb.cache_invalid());
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_FALSE(bb.empty());

            // Get the label
            bres = bb.try_get_multi_label({ 1 }, 0, labels);
            ASSERT_TRUE(bres);
            ASSERT_EQ(label_size, labels.size());
            auto expected_label = create_label(label_size, 1);
            ASSERT_TRUE(equal(expected_label.begin(), expected_label.end(), labels.begin()));

            // Try getting a label for wrong value
            bres = bb.try_get_multi_label({ 2 }, 0, labels);
            ASSERT_FALSE(bres);
            ASSERT_EQ(0, labels.size());

            // Insert at index 1 so that we don't actually increase the max size
            values.emplace_back(1, create_label(label_size, 1));
            res = bb.multi_insert_for_real(values, 1);
            ASSERT_EQ(1 /* largest bin size after insert */, res);
            ASSERT_TRUE(bb.cache_invalid());
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_FALSE(bb.empty());

            // Get the label
            bres = bb.try_get_multi_label({ 1, 1 }, 0, labels);
            ASSERT_TRUE(bres);
            expected_label = zipper_merge(create_label(label_size, 1), create_label(label_size, 1));
            ASSERT_EQ(expected_label.size(), labels.size());
            ASSERT_TRUE(equal(expected_label.begin(), expected_label.end(), labels.begin()));

            // Try getting a label for wrong value
            bres = bb.try_get_multi_label({ 0, 1 }, 0, labels);
            ASSERT_FALSE(bres);
            ASSERT_EQ(0, labels.size());
            ASSERT_FALSE(bb.empty());

            // Insert at index 2; the value 1 will intersect with the current bin so will fail
            res = bb.multi_insert_for_real(values, 2);
            ASSERT_EQ(-1 /* largest bin size after insert */, res);
            ASSERT_FALSE(bb.cache_invalid());

            values.clear();

            // Use a repeating label; there is no problem since the item value is different
            values.emplace_back(2, create_label(label_size, 7));
            values.emplace_back(3, create_label(label_size, 8));
            res = bb.multi_insert_for_real(values, 1);
            ASSERT_EQ(2 /* largest bin size after insert */, res);
            ASSERT_TRUE(bb.cache_invalid());
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_FALSE(bb.empty());

            // Get the label
            bres = bb.try_get_multi_label({ 1, 2, 3 }, 0, labels);
            ASSERT_TRUE(bres);
            expected_label = zipper_merge(
                create_label(label_size, 1),
                create_label(label_size, 7),
                create_label(label_size, 8));
            ASSERT_EQ(expected_label.size(), labels.size());
            ASSERT_TRUE(equal(expected_label.begin(), expected_label.end(), labels.begin()));

            values.resize(params->bins_per_bundle(), make_pair(4, create_label(label_size, 4)));
            res = bb.multi_insert_for_real(values, 0);
            ASSERT_EQ(3 /* largest bin size after insert */, res);
            ASSERT_TRUE(bb.cache_invalid());
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_FALSE(bb.empty());

            // Overflowing
            res = bb.multi_insert_for_real(values, 1);
            ASSERT_EQ(-1 /* error code */, res);
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_FALSE(bb.empty());

            bb.clear();
            ASSERT_TRUE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());
        };

        test_fun(get_params1(), 1);
        test_fun(get_params1(), 2);
        test_fun(get_params1(), 3);

        test_fun(get_params2(), 1);
        test_fun(get_params2(), 2);
        test_fun(get_params2(), 3);
    }

    TEST(BinBundleTests, BinBundleTryMultiOverwrite)
    {
        auto test_fun = [&](const shared_ptr<PSIParams> &params, size_t label_size) {
            CryptoContext context(*params);
            context.set_evaluator();

            BinBundle bb(context, label_size, 50, 0, params->bins_per_bundle(), true, false);

            AlgItemLabel values{ make_pair(1, create_label(label_size, 1)) };

            // Now insert for real
            int res = bb.multi_insert_for_real(values, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);

            // Check the label
            vector<felt_t> labels;
            bool bres = bb.try_get_multi_label({ 1 }, 0, labels);
            ASSERT_TRUE(bres);
            auto expected_label = create_label(label_size, 1);
            ASSERT_EQ(expected_label.size(), labels.size());
            ASSERT_TRUE(equal(expected_label.begin(), expected_label.end(), labels.begin()));

            ASSERT_TRUE(bb.cache_invalid());
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());

            values[0].second = create_label(label_size, 2);
            bres = bb.try_multi_overwrite(values, 0);
            ASSERT_TRUE(bres);

            // Check the label
            bres = bb.try_get_multi_label({ 1 }, 0, labels);
            ASSERT_TRUE(bres);
            expected_label = create_label(label_size, 2);
            ASSERT_EQ(expected_label.size(), labels.size());
            ASSERT_TRUE(equal(expected_label.begin(), expected_label.end(), labels.begin()));

            ASSERT_TRUE(bb.cache_invalid());
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());

            // Item doesn't match so won't overwrite
            values[0].first = 2;
            values[0].second = create_label(label_size, 3);
            bres = bb.try_multi_overwrite(values, 0);
            ASSERT_FALSE(bres);

            // Check the label; no change expected
            bres = bb.try_get_multi_label({ 1 }, 0, labels);
            ASSERT_TRUE(bres);
            ASSERT_EQ(expected_label.size(), labels.size());
            ASSERT_TRUE(equal(expected_label.begin(), expected_label.end(), labels.begin()));
            ASSERT_FALSE(bb.cache_invalid());

            values.clear();
            values = {
                make_pair(1, create_label(label_size, 1)),
                make_pair(2, create_label(label_size, 2)),
                make_pair(3, create_label(label_size, 3)),
            };
            bb.clear();
            res = bb.multi_insert_for_real(values, 0);
            values = {
                make_pair(4, create_label(label_size, 4)),
                make_pair(5, create_label(label_size, 5)),
                make_pair(6, create_label(label_size, 6)),
            };
            res = bb.multi_insert_for_real(values, 0);
            ASSERT_EQ(2 /* largest bin size after insert */, res);

            // Check the label
            bres = bb.try_get_multi_label({ 1, 5, 3 }, 0, labels);
            ASSERT_TRUE(bres);
            expected_label = zipper_merge(
                create_label(label_size, 1),
                create_label(label_size, 5),
                create_label(label_size, 3));
            ASSERT_EQ(expected_label.size(), labels.size());
            ASSERT_TRUE(equal(expected_label.begin(), expected_label.end(), labels.begin()));

            ASSERT_TRUE(bb.cache_invalid());
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());

            // Item sequence doesn't match
            values = {
                make_pair(1, create_label(label_size, 1)),
                make_pair(4, create_label(label_size, 4)),
                make_pair(3, create_label(label_size, 3)),
            };
            bres = bb.try_multi_overwrite(values, 0);
            ASSERT_FALSE(bres);

            // Overwriting labels
            values = {
                make_pair(1, create_label(label_size, 6)),
                make_pair(5, create_label(label_size, 7)),
                make_pair(3, create_label(label_size, 8)),
            };
            bres = bb.try_multi_overwrite(values, 0);
            ASSERT_TRUE(bres);

            ASSERT_TRUE(bb.cache_invalid());
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());

            // Check the label
            bres = bb.try_get_multi_label({ 1, 5, 3 }, 0, labels);
            ASSERT_TRUE(bres);
            expected_label = zipper_merge(
                create_label(label_size, 6),
                create_label(label_size, 7),
                create_label(label_size, 8));
            ASSERT_EQ(expected_label.size(), labels.size());
            ASSERT_TRUE(equal(expected_label.begin(), expected_label.end(), labels.begin()));

            bb.clear();
            values.resize(params->bins_per_bundle(), make_pair(4, create_label(label_size, 4)));
            res = bb.multi_insert_for_real(values, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);

            ASSERT_TRUE(bb.cache_invalid());
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());

            // Overflowing
            bres = bb.try_multi_overwrite(values, 1);
            ASSERT_FALSE(bres);
            ASSERT_FALSE(bb.cache_invalid());
        };

        test_fun(get_params1(), 1);
        test_fun(get_params1(), 2);
        test_fun(get_params1(), 3);

        test_fun(get_params2(), 1);
        test_fun(get_params2(), 2);
        test_fun(get_params2(), 3);
    }

    TEST(BinBundleTests, BinBundleTryMultiRemove)
    {
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
            CryptoContext context(*params);
            context.set_evaluator();

            BinBundle bb(context, 0, 50, 0, params->bins_per_bundle(), true, false);
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());

            // Now insert for real
            AlgItem values{ 1, 2, 3 };
            int res = bb.multi_insert_for_real(values, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);

            values = { 4, 5, 6, 7, 8 };
            res = bb.multi_insert_for_real(values, 0);
            ASSERT_EQ(2 /* largest bin size after insert */, res);

            ASSERT_TRUE(bb.cache_invalid());
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());

            // Try remove invalid item
            bool bres = bb.try_multi_remove({ 1, 3, 2 }, 0);
            ASSERT_FALSE(bres);
            ASSERT_FALSE(bb.cache_invalid());

            // Try remove invalid item
            bres = bb.try_multi_remove({ 1, 2, 3 }, 1);
            ASSERT_FALSE(bres);
            ASSERT_FALSE(bb.cache_invalid());

            // Remove valid item
            bres = bb.try_multi_remove({ 4, 5, 6 }, 0);
            ASSERT_TRUE(bres);
            ASSERT_FALSE(bb.empty());

            ASSERT_TRUE(bb.cache_invalid());
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());

            // Remove valid item
            bres = bb.try_multi_remove({ 1, 2, 3, 7, 8 }, 0);
            ASSERT_TRUE(bres);
            ASSERT_TRUE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());
        };

        // Power-of-two felts_per_item
        test_fun(get_params1());

        // Non-power-of-two felts_per_item
        test_fun(get_params2());
    }

    TEST(BinBundleTests, SaveLoadUnlabeled)
    {
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
            stringstream ss;

            CryptoContext context(*params);
            context.set_evaluator();

            BinBundle bb(
                context,
                0,
                params->table_params().max_items_per_bin,
                params->query_params().ps_low_degree,
                params->bins_per_bundle(),
                true,
                false);
            bb.regen_cache();
            ASSERT_TRUE(bb.empty());
            auto save_size = bb.save(ss, 1212);

            BinBundle bb2(
                context,
                0,
                params->table_params().max_items_per_bin,
                params->query_params().ps_low_degree,
                params->bins_per_bundle(),
                true,
                false);
            auto load_size = bb2.load(ss);
            ASSERT_EQ(1212, load_size.first);
            ASSERT_EQ(save_size, load_size.second);
            ASSERT_TRUE(bb2.empty());

            int res = bb.multi_insert_for_real(AlgItem{ 1 }, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);
            ASSERT_TRUE(bb.cache_invalid());
            ASSERT_FALSE(bb.empty());
            save_size = bb.save(ss, 131313);

            load_size = bb2.load(ss);
            ASSERT_EQ(131313, load_size.first);
            ASSERT_EQ(save_size, load_size.second);
            ASSERT_TRUE(bb2.cache_invalid());
            ASSERT_FALSE(bb2.empty());

            res = bb.multi_insert_for_real(AlgItem{ 2, 3 }, 0);
            ASSERT_EQ(2 /* largest bin size after insert */, res);
            ASSERT_TRUE(bb.cache_invalid());
            ASSERT_FALSE(bb.empty());
            save_size = bb.save(ss, 0);

            load_size = bb2.load(ss);
            ASSERT_EQ(0, load_size.first);
            ASSERT_EQ(save_size, load_size.second);
            ASSERT_TRUE(bb2.cache_invalid());
            ASSERT_FALSE(bb2.empty());

            // These pass for the original BinBundle
            ASSERT_TRUE(find_in_bin(bb.get_item_bins()[0], 1));
            ASSERT_TRUE(find_in_bin(bb.get_item_bins()[0], 2));
            ASSERT_TRUE(find_in_bin(bb.get_item_bins()[1], 3));

            // These should pass for the loaded BinBundle
            ASSERT_TRUE(find_in_bin(bb2.get_item_bins()[0], 1));
            ASSERT_TRUE(find_in_bin(bb2.get_item_bins()[0], 2));
            ASSERT_TRUE(find_in_bin(bb2.get_item_bins()[1], 3));

            // Try loading to labeled BinBundle
            ss.seekg(0);
            BinBundle bb3(
                context,
                1,
                params->table_params().max_items_per_bin,
                params->query_params().ps_low_degree,
                params->bins_per_bundle(),
                true,
                false);
            ASSERT_THROW(bb3.load(ss), runtime_error);
        };

        // Power-of-two felts_per_item
        test_fun(get_params1());

        // Non-power-of-two felts_per_item
        test_fun(get_params2());
    }

    TEST(BinBundleTests, SaveLoadLabeled)
    {
        auto test_fun = [&](const shared_ptr<PSIParams> &params, size_t label_size) {
            stringstream ss;

            CryptoContext context(*params);
            context.set_evaluator();

            BinBundle bb(
                context,
                label_size,
                params->table_params().max_items_per_bin,
                params->query_params().ps_low_degree,
                params->bins_per_bundle(),
                true,
                false);
            bb.regen_cache();
            ASSERT_TRUE(bb.empty());
            auto save_size = bb.save(ss, 1);

            BinBundle bb2(
                context,
                label_size,
                params->table_params().max_items_per_bin,
                params->query_params().ps_low_degree,
                params->bins_per_bundle(),
                true,
                false);
            auto load_size = bb2.load(ss);
            ASSERT_EQ(1, load_size.first);
            ASSERT_EQ(save_size, load_size.second);
            ASSERT_TRUE(bb2.empty());

            int res = bb.multi_insert_for_real(
                AlgItemLabel{ make_pair(1, create_label(label_size, 2)) }, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);
            ASSERT_TRUE(bb.cache_invalid());
            ASSERT_FALSE(bb.empty());
            save_size = bb.save(ss, 1212);

            load_size = bb2.load(ss);
            ASSERT_EQ(1212, load_size.first);
            ASSERT_EQ(save_size, load_size.second);
            ASSERT_TRUE(bb2.cache_invalid());
            ASSERT_FALSE(bb2.empty());

            res = bb.multi_insert_for_real(
                AlgItemLabel{
                    make_pair(2, create_label(label_size, 3)),
                    make_pair(3, create_label(label_size, 4)),
                },
                0);
            ASSERT_EQ(2 /* largest bin size after insert */, res);
            ASSERT_TRUE(bb.cache_invalid());
            ASSERT_FALSE(bb.empty());
            save_size = bb.save(ss, 131313);

            load_size = bb2.load(ss);
            ASSERT_EQ(131313, load_size.first);
            ASSERT_EQ(save_size, load_size.second);
            ASSERT_TRUE(bb2.cache_invalid());
            ASSERT_FALSE(bb2.empty());

            // These pass for the original BinBundle
            ASSERT_TRUE(find_in_bin(bb.get_item_bins()[0], 1));
            for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                ASSERT_TRUE(find_in_bin(bb.get_label_bins()[label_idx][0], 2 + label_idx));
            }

            ASSERT_TRUE(find_in_bin(bb.get_item_bins()[0], 2));
            for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                ASSERT_TRUE(find_in_bin(bb.get_label_bins()[label_idx][0], 3 + label_idx));
            }

            ASSERT_TRUE(find_in_bin(bb.get_item_bins()[1], 3));
            for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                ASSERT_TRUE(find_in_bin(bb.get_label_bins()[label_idx][1], 4 + label_idx));
            }

            // These should pass for the loaded BinBundle
            ASSERT_TRUE(find_in_bin(bb2.get_item_bins()[0], 1));
            for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                ASSERT_TRUE(find_in_bin(bb2.get_label_bins()[label_idx][0], 2 + label_idx));
            }

            ASSERT_TRUE(find_in_bin(bb2.get_item_bins()[0], 2));
            for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                ASSERT_TRUE(find_in_bin(bb2.get_label_bins()[label_idx][0], 3 + label_idx));
            }

            ASSERT_TRUE(find_in_bin(bb2.get_item_bins()[1], 3));
            for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                ASSERT_TRUE(find_in_bin(bb2.get_label_bins()[label_idx][1], 4 + label_idx));
            }

            // Try loading to unlabeled BinBundle
            ss.seekg(0);
            BinBundle bb3(
                context,
                0,
                params->table_params().max_items_per_bin,
                params->query_params().ps_low_degree,
                params->bins_per_bundle(),
                true,
                false);
            ASSERT_THROW(bb3.load(ss), runtime_error);
        };

        test_fun(get_params1(), 1);
        test_fun(get_params1(), 2);
        test_fun(get_params1(), 3);

        test_fun(get_params2(), 1);
        test_fun(get_params2(), 2);
        test_fun(get_params2(), 3);
    }

    TEST(BinBundleTests, SaveLoadMoreThanAMillionTables)
    {
        // A bin bundle is saved with a table for every bin of every label part, and again in its
        // cache. With 4096 bins and 150 label parts that is more than 1,000,000 tables, the
        // FlatBuffers verifier's default limit, and the bundle must still load.
        auto params = get_params1();
        size_t label_size = 150;
        ASSERT_GT(params->bins_per_bundle() * (2 * label_size + 1), size_t(1000000));

        CryptoContext context(*params);
        context.set_evaluator();
        auto make_bundle = [&] {
            return BinBundle(
                context,
                label_size,
                params->table_params().max_items_per_bin,
                params->query_params().ps_low_degree,
                params->bins_per_bundle(),
                false,
                false);
        };

        BinBundle bb = make_bundle();
        vector<pair<felt_t, vector<felt_t>>> item_label{ { 1, vector<felt_t>(label_size, 7) } };
        ASSERT_EQ(1, bb.multi_insert_for_real(item_label, 0));
        bb.regen_cache();

        stringstream ss;
        size_t save_size = bb.save(ss, 7);

        BinBundle bb2 = make_bundle();
        pair<uint32_t, size_t> load_size;
        ASSERT_NO_THROW(load_size = bb2.load(ss));
        ASSERT_EQ(7, load_size.first);
        ASSERT_EQ(save_size, load_size.second);
        ASSERT_FALSE(bb2.cache_invalid());
        ASSERT_TRUE(find_in_bin(bb2.get_item_bins()[0], 1));
        for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
            ASSERT_TRUE(find_in_bin(bb2.get_label_bins()[label_idx][0], 7));
        }
    }

    TEST(BinBundleTests, StripUnlabeled)
    {
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
            CryptoContext context(*params);
            context.set_evaluator();

            // Create a normal unlabeled BinBundle, strip, and reset
            BinBundle bb(
                context,
                0,
                params->table_params().max_items_per_bin,
                params->query_params().ps_low_degree,
                params->bins_per_bundle(),
                true,
                false);
            ASSERT_FALSE(bb.is_stripped());
            bb.strip();
            ASSERT_TRUE(bb.is_stripped());
            bb.clear();
            ASSERT_FALSE(bb.is_stripped());

            // Insert a single item and check all sizes
            AlgItem values{ 1 };
            ASSERT_EQ(1, bb.multi_insert_for_real(values, 0));
            ASSERT_FALSE(bb.empty());
            bb.regen_cache();
            ASSERT_EQ(params->bins_per_bundle(), bb.get_item_bins().size());
            ASSERT_EQ(0, bb.get_label_size());
            ASSERT_EQ(0, bb.get_label_bins().size());
            ASSERT_EQ(params->bins_per_bundle(), bb.get_cache().felt_matching_polyns.size());
            ASSERT_EQ(2, bb.get_cache().felt_matching_polyns[0].size());
            ASSERT_EQ(0, bb.get_cache().felt_interp_polyns.size());
            ASSERT_EQ(2, bb.get_cache().batched_matching_polyn.batched_coeffs.size());
            ASSERT_EQ(0, bb.get_cache().batched_interp_polyns.size());

            // Strip and check all sizes
            bb.strip();
            ASSERT_TRUE(bb.empty());
            ASSERT_TRUE(bb.is_stripped());
            ASSERT_EQ(0, bb.get_item_bins().size());
            ASSERT_EQ(0, bb.get_label_size());
            ASSERT_EQ(0, bb.get_label_bins().size());
            ASSERT_EQ(0, bb.get_cache().felt_matching_polyns.size());
            ASSERT_EQ(0, bb.get_cache().felt_interp_polyns.size());
            ASSERT_EQ(2, bb.get_cache().batched_matching_polyn.batched_coeffs.size());
            ASSERT_EQ(0, bb.get_cache().batched_interp_polyns.size());
            ASSERT_THROW(bb.multi_insert_for_real(values, 1), logic_error);

            // Save and load to a different object and check all sizes
            stringstream ss;
            bb.save(ss, 0);
            BinBundle bb2(
                context,
                0,
                params->table_params().max_items_per_bin,
                params->query_params().ps_low_degree,
                params->bins_per_bundle(),
                true,
                false);
            bb2.load(ss);
            ASSERT_TRUE(bb2.empty());
            ASSERT_TRUE(bb2.is_stripped());
            ASSERT_EQ(0, bb2.get_item_bins().size());
            ASSERT_EQ(0, bb2.get_label_size());
            ASSERT_EQ(0, bb2.get_label_bins().size());
            ASSERT_EQ(0, bb2.get_cache().felt_matching_polyns.size());
            ASSERT_EQ(0, bb2.get_cache().felt_interp_polyns.size());
            ASSERT_EQ(2, bb2.get_cache().batched_matching_polyn.batched_coeffs.size());
            ASSERT_EQ(0, bb2.get_cache().batched_interp_polyns.size());
            ASSERT_THROW(bb2.multi_insert_for_real(values, 1), logic_error);

            // Check that data buffers match
            ASSERT_TRUE(equal(
                bb.get_cache().batched_matching_polyn.batched_coeffs[0].begin(),
                bb.get_cache().batched_matching_polyn.batched_coeffs[0].end(),
                bb2.get_cache().batched_matching_polyn.batched_coeffs[0].begin()));
            ASSERT_TRUE(equal(
                bb.get_cache().batched_matching_polyn.batched_coeffs[1].begin(),
                bb.get_cache().batched_matching_polyn.batched_coeffs[1].end(),
                bb2.get_cache().batched_matching_polyn.batched_coeffs[1].begin()));

            bb2.clear();
            ASSERT_FALSE(bb2.is_stripped());
        };

        // Power-of-two felts_per_item
        test_fun(get_params1());

        // Non-power-of-two felts_per_item
        test_fun(get_params2());
    }

    TEST(BinBundleTests, StripLabeled)
    {
        auto test_fun = [](const shared_ptr<PSIParams> &params) {
            CryptoContext context(*params);
            context.set_evaluator();

            // Create a normal labeled BinBundle, strip, and reset
            size_t label_size = 1;
            BinBundle bb(
                context,
                label_size,
                params->table_params().max_items_per_bin,
                params->query_params().ps_low_degree,
                params->bins_per_bundle(),
                true,
                false);
            ASSERT_FALSE(bb.is_stripped());
            bb.strip();
            ASSERT_TRUE(bb.is_stripped());
            bb.clear();
            ASSERT_FALSE(bb.is_stripped());

            // Insert a single item and check all sizes
            AlgItemLabel values{ make_pair(1, create_label(label_size, 1)) };
            ASSERT_EQ(1, bb.multi_insert_for_real(values, 0));
            ASSERT_FALSE(bb.empty());
            bb.regen_cache();
            ASSERT_EQ(params->bins_per_bundle(), bb.get_item_bins().size());
            ASSERT_EQ(label_size, bb.get_label_size());
            ASSERT_EQ(label_size, bb.get_label_bins().size());
            ASSERT_EQ(params->bins_per_bundle(), bb.get_cache().felt_matching_polyns.size());
            ASSERT_EQ(2, bb.get_cache().felt_matching_polyns[0].size());
            ASSERT_EQ(label_size, bb.get_cache().felt_interp_polyns.size());
            ASSERT_EQ(2, bb.get_cache().batched_matching_polyn.batched_coeffs.size());
            ASSERT_EQ(label_size, bb.get_cache().batched_interp_polyns.size());
            ASSERT_EQ(1, bb.get_cache().batched_interp_polyns[0].batched_coeffs.size());

            // Strip and check all sizes
            bb.strip();
            ASSERT_TRUE(bb.empty());
            ASSERT_TRUE(bb.is_stripped());
            ASSERT_EQ(0, bb.get_item_bins().size());
            ASSERT_EQ(label_size, bb.get_label_size());
            ASSERT_EQ(0, bb.get_label_bins().size());
            ASSERT_EQ(0, bb.get_cache().felt_matching_polyns.size());
            ASSERT_EQ(0, bb.get_cache().felt_interp_polyns.size());
            ASSERT_EQ(2, bb.get_cache().batched_matching_polyn.batched_coeffs.size());
            ASSERT_EQ(label_size, bb.get_cache().batched_interp_polyns.size());
            ASSERT_EQ(1, bb.get_cache().batched_interp_polyns[0].batched_coeffs.size());
            ASSERT_THROW(bb.multi_insert_for_real(values, 1), logic_error);

            // Save and load to a different object and check all sizes
            stringstream ss;
            bb.save(ss, 0);
            BinBundle bb2(
                context,
                label_size,
                params->table_params().max_items_per_bin,
                params->query_params().ps_low_degree,
                params->bins_per_bundle(),
                true,
                false);
            bb2.load(ss);
            ASSERT_TRUE(bb2.empty());
            ASSERT_TRUE(bb2.is_stripped());
            ASSERT_EQ(0, bb2.get_item_bins().size());
            ASSERT_EQ(label_size, bb2.get_label_size());
            ASSERT_EQ(0, bb2.get_label_bins().size());
            ASSERT_EQ(0, bb2.get_cache().felt_matching_polyns.size());
            ASSERT_EQ(0, bb2.get_cache().felt_interp_polyns.size());
            ASSERT_EQ(2, bb2.get_cache().batched_matching_polyn.batched_coeffs.size());
            ASSERT_EQ(label_size, bb2.get_cache().batched_interp_polyns.size());
            ASSERT_EQ(1, bb2.get_cache().batched_interp_polyns[0].batched_coeffs.size());
            ASSERT_THROW(bb2.multi_insert_for_real(values, 1), logic_error);

            // Check that data buffers match
            ASSERT_TRUE(equal(
                bb.get_cache().batched_matching_polyn.batched_coeffs[0].begin(),
                bb.get_cache().batched_matching_polyn.batched_coeffs[0].end(),
                bb2.get_cache().batched_matching_polyn.batched_coeffs[0].begin()));
            ASSERT_TRUE(equal(
                bb.get_cache().batched_matching_polyn.batched_coeffs[1].begin(),
                bb.get_cache().batched_matching_polyn.batched_coeffs[1].end(),
                bb2.get_cache().batched_matching_polyn.batched_coeffs[1].begin()));
            ASSERT_TRUE(equal(
                bb.get_cache().batched_interp_polyns[0].batched_coeffs[0].begin(),
                bb.get_cache().batched_interp_polyns[0].batched_coeffs[0].end(),
                bb2.get_cache().batched_interp_polyns[0].batched_coeffs[0].begin()));

            bb2.clear();
            ASSERT_FALSE(bb2.is_stripped());
        };

        // Power-of-two felts_per_item
        test_fun(get_params1());

        // Non-power-of-two felts_per_item
        test_fun(get_params2());
    }

    TEST(BinBundleTests, AnItemTheFilterRefusesIsStillFound)
    {
        // A cuckoo filter is probabilistic and can refuse an item while holding fewer than the
        // bin does, when enough of them share a fingerprint. These nine values all carry the same
        // 12-bit fingerprint, which saturates both of the buckets it can occupy plus the single
        // overflow slot, so a filter sized well above ten refuses the last of them.
        //
        // The item still belongs in the bin, so what has to hold is that it remains findable.
        // A filter that has refused an item no longer knows everything the bin holds, and a
        // lookup that took its negative as conclusive would never find that item again.
        // The first nine share a 12-bit fingerprint, which saturates both buckets that
        // fingerprint can occupy plus the single overflow slot. Once the overflow slot is taken
        // the filter refuses everything, so the tenth value is dropped even though its own
        // fingerprint is nowhere in the filter -- which is what makes it report absent rather
        // than giving a false positive that would mask the problem.
        const vector<felt_t> colliding{ 1, 252, 11389, 12874, 17547, 21064, 37127, 40541, 41546 };
        constexpr felt_t dropped_item = 100000;

        auto params = get_params1();
        CryptoContext context(*params);
        context.set_evaluator();

        constexpr size_t label_size = 1;
        BinBundle bb(context, label_size, 50, 0, params->bins_per_bundle(), true, false);

        vector<felt_t> all_items = colliding;
        all_items.push_back(dropped_item);

        // Every item goes into bin 0, so they share one filter.
        for (felt_t item : all_items) {
            vector<pair<felt_t, vector<felt_t>>> one{ { item, { item } } };
            ASSERT_LE(0, bb.multi_insert_for_real(one, 0))
                << "item " << item << " was rejected outright";
        }

        // The bin and its labels stay in step.
        ASSERT_EQ(all_items.size(), bb.get_item_bins()[0].size());
        ASSERT_EQ(all_items.size(), bb.get_label_bins()[0][0].size());

        // Every item is findable, including the one the filter refused.
        for (felt_t item : all_items) {
            vector<felt_t> labels;
            ASSERT_TRUE(bb.try_get_multi_label({ item }, 0, labels))
                << "item " << item << " is in the bin but cannot be found";
            ASSERT_EQ(size_t(1), labels.size());
            ASSERT_EQ(item, labels[0]);
        }
    }

    namespace {
        // Parameters with match tags of three parts; see make_tag_params
        constexpr size_t tag_part_count = 3;

        constexpr size_t tag_max_bin_size = 8;

        /**
        Parameters with match tags, with felts_per_item field elements of 16 bits per item.
        */
        PSIParams make_tag_params(uint32_t felts_per_item, size_t pmd = 4096)
        {
            PSIParams::ItemParams item_params;
            item_params.felts_per_item = felts_per_item;
            item_params.tag_part_count = static_cast<uint32_t>(tag_part_count);

            PSIParams::TableParams table_params;
            table_params.hash_func_count = 3;
            table_params.max_items_per_bin = static_cast<uint32_t>(tag_max_bin_size);
            table_params.table_size = static_cast<uint32_t>(pmd / felts_per_item);

            PSIParams::QueryParams query_params;
            query_params.query_powers = { 1, 3, 5 };

            PSIParams::SEALParams seal_params;
            seal_params.set_poly_modulus_degree(pmd);
            seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
            seal_params.set_plain_modulus(65537);

            return PSIParams(item_params, table_params, query_params, seal_params);
        }

        BinBundle make_tag_bundle(
            const CryptoContext &context, const PSIParams &params, size_t label_size)
        {
            return BinBundle(
                context,
                label_size,
                tag_max_bin_size,
                0,
                params.bins_per_bundle(),
                true,
                false,
                tag_part_count);
        }

        /**
        An item with the given field elements, with HashedItem (id, ~id), and with label_size
        label parts: part p of its field element s is label_start + 10 * p + s. In a BinBundle
        with match tags, the first tag_part_count of them stand in for its tag.
        */
        TaggedAlgItemLabel make_tagged_item(
            uint64_t id, const vector<felt_t> &felts, size_t label_size, felt_t label_start)
        {
            TaggedAlgItemLabel item;
            item.item = HashedItem(id, ~id);
            for (size_t s = 0; s < felts.size(); s++) {
                vector<felt_t> parts(label_size);
                for (size_t p = 0; p < label_size; p++) {
                    parts[p] = label_start + (10 * p) + s;
                }
                item.alg_item_label.emplace_back(felts[s], std::move(parts));
            }
            return item;
        }

        /**
        While it exists, makes the user's log handler throw on every debug message that reports
        that a cuckoo filter refused an item, and counts those messages.
        */
        class RefusalLogThrows {
        public:
            RefusalLogThrows() : saved_level_(GetLogLevel())
            {
                array<Logger::log_handler_t, Logger::level_count> log_handlers{};
                log_handlers[static_cast<size_t>(LogLevel::debug)] = [this](const string &msg) {
                    if (msg.find("refused an item") != string::npos) {
                        refusal_count_++;
                        throw runtime_error("the log handler failed");
                    }
                };
                SetLogger(Logger::Create(std::move(log_handlers), {}, {}));
                SetLogLevel(LogLevel::debug);
            }

            ~RefusalLogThrows()
            {
                CloseLogger();
                SetLogLevel(saved_level_);
            }

            RefusalLogThrows(const RefusalLogThrows &) = delete;

            RefusalLogThrows &operator=(const RefusalLogThrows &) = delete;

            size_t refusal_count() const
            {
                return refusal_count_;
            }

        private:
            LogLevel saved_level_;

            size_t refusal_count_ = 0;
        };

        /**
        The labels try_get_multi_label gives for an item: part p of its field element s at
        p * felts_per_item + s.
        */
        vector<felt_t> labels_of(const TaggedAlgItemLabel &item)
        {
            size_t felts_per_item = item.alg_item_label.size();
            size_t label_size = item.alg_item_label[0].second.size();
            vector<felt_t> labels(felts_per_item * label_size);
            for (size_t s = 0; s < felts_per_item; s++) {
                for (size_t p = 0; p < label_size; p++) {
                    labels[(p * felts_per_item) + s] = item.alg_item_label[s].second[p];
                }
            }
            return labels;
        }

        felt_t evaluate(const FEltPolyn &polyn, felt_t x, const Modulus &mod)
        {
            felt_t result = 0;
            for (size_t i = polyn.size(); i-- > 0;) {
                result = seal::util::multiply_uint_mod(result, x, mod);
                result = seal::util::add_uint_mod(result, polyn[i], mod);
            }
            return result;
        }

        string save_to_string(const BinBundle &bb)
        {
            stringstream ss;
            bb.save(ss, 0);
            return ss.str();
        }

        void load_from_string(BinBundle &bb, const string &bytes)
        {
            stringstream ss(bytes);
            bb.load(ss);
        }

        /**
        Changes for rebuild_bin_bundle to make to a saved BinBundle.
        */
        struct BinBundleChanges {
            bool drop_hashed_items = false;

            bool drop_last_hashed_item = false;

            bool add_extra_hashed_item = false;

            bool add_hashed_items = false;

            bool add_matching_polyns = false;

            bool drop_matching_polyns = false;

            bool shorten_first_matching_polyn = false;

            bool drop_last_interp_polyns = false;

            bool shorten_first_felt_interp_polyn = false;

            bool empty_first_batched_interp_polyn = false;

            bool shorten_last_batched_interp_polyn = false;

            bool empty_felt_polyns = false;

            bool empty_batched_matching_polyn = false;

            bool empty_last_batched_interp_polyn = false;
        };

        flatbuffers::Offset<fbs::FEltMatrix> copy_felt_matrix(
            flatbuffers::FlatBufferBuilder &builder,
            const fbs::FEltMatrix *matrix,
            bool shorten_first_row = false)
        {
            vector<flatbuffers::Offset<fbs::FEltArray>> rows;
            if (matrix) {
                for (const auto *row : *matrix->rows()) {
                    vector<uint64_t> felts(row->felts()->begin(), row->felts()->end());
                    if (shorten_first_row && rows.empty() && !felts.empty()) {
                        felts.pop_back();
                    }
                    rows.push_back(fbs::CreateFEltArray(builder, builder.CreateVector(felts)));
                }
            }
            return fbs::CreateFEltMatrix(builder, builder.CreateVector(rows));
        }

        /**
        Returns a matrix with as many rows as the given one, each of them empty.
        */
        flatbuffers::Offset<fbs::FEltMatrix> empty_felt_matrix(
            flatbuffers::FlatBufferBuilder &builder, const fbs::FEltMatrix *matrix)
        {
            vector<flatbuffers::Offset<fbs::FEltArray>> rows;
            if (matrix) {
                for (size_t i = 0; i < matrix->rows()->size(); i++) {
                    rows.push_back(
                        fbs::CreateFEltArray(builder, builder.CreateVector(vector<uint64_t>())));
                }
            }
            return fbs::CreateFEltMatrix(builder, builder.CreateVector(rows));
        }

        flatbuffers::Offset<fbs::BatchedPlaintextPolyn> copy_batched_polyn(
            flatbuffers::FlatBufferBuilder &builder,
            const fbs::BatchedPlaintextPolyn &polyn,
            size_t drop_count = 0)
        {
            vector<flatbuffers::Offset<fbs::Plaintext>> coeffs;
            size_t keep_count =
                polyn.coeffs()->size() - min<size_t>(drop_count, polyn.coeffs()->size());
            for (size_t i = 0; i < keep_count; i++) {
                const auto &data =
                    *polyn.coeffs()->Get(static_cast<flatbuffers::uoffset_t>(i))->data();
                coeffs.push_back(
                    fbs::CreatePlaintext(builder, builder.CreateVector(data.data(), data.size())));
            }
            return fbs::CreateBatchedPlaintextPolyn(builder, builder.CreateVector(coeffs));
        }

        /**
        Writes a saved BinBundle again, field by field, with the given changes, giving data that
        BinBundle::save never writes but that the FlatBuffers verifier accepts.
        */
        string rebuild_bin_bundle(const string &bytes, const BinBundleChanges &changes)
        {
            const auto *bb = fbs::GetSizePrefixedBinBundle(bytes.data());
            flatbuffers::FlatBufferBuilder builder(1024);

            auto item_bins = copy_felt_matrix(builder, bb->item_bins());
            vector<flatbuffers::Offset<fbs::FEltMatrix>> label_bins;
            if (bb->label_bins()) {
                for (const auto *label_bin : *bb->label_bins()) {
                    label_bins.push_back(copy_felt_matrix(builder, label_bin));
                }
            }
            auto label_bins_vec = builder.CreateVector(label_bins);

            flatbuffers::Offset<fbs::BinBundleCache> cache;
            if (bb->cache()) {
                const auto &c = *bb->cache();
                size_t interp_count = c.batched_interp_polyns()->size();
                if (changes.drop_last_interp_polyns) {
                    interp_count--;
                }

                flatbuffers::Offset<fbs::FEltMatrix> felt_matching;
                flatbuffers::Offset<fbs::BatchedPlaintextPolyn> batched_matching;
                if (c.felt_matching_polyns() && !changes.drop_matching_polyns) {
                    felt_matching = changes.empty_felt_polyns
                                        ? empty_felt_matrix(builder, c.felt_matching_polyns())
                                        : copy_felt_matrix(
                                              builder,
                                              c.felt_matching_polyns(),
                                              changes.shorten_first_matching_polyn);
                    const auto &polyn = *c.batched_matching_polyn();
                    batched_matching = copy_batched_polyn(
                        builder,
                        polyn,
                        changes.empty_batched_matching_polyn ? polyn.coeffs()->size() : 0);
                } else if (changes.add_matching_polyns) {
                    // Polynomials of the right shape: those of the first label part
                    const fbs::FEltMatrix *first = nullptr;
                    if (c.felt_interp_polyns() && c.felt_interp_polyns()->size()) {
                        first = c.felt_interp_polyns()->Get(0);
                    }
                    felt_matching = copy_felt_matrix(builder, first);
                    batched_matching =
                        copy_batched_polyn(builder, *c.batched_interp_polyns()->Get(0));
                }

                vector<flatbuffers::Offset<fbs::FEltMatrix>> felt_interp;
                size_t felt_interp_count =
                    min<size_t>(interp_count, c.felt_interp_polyns()->size());
                for (size_t i = 0; i < felt_interp_count; i++) {
                    const auto *matrix =
                        c.felt_interp_polyns()->Get(static_cast<flatbuffers::uoffset_t>(i));
                    felt_interp.push_back(
                        changes.empty_felt_polyns
                            ? empty_felt_matrix(builder, matrix)
                            : copy_felt_matrix(
                                  builder,
                                  matrix,
                                  changes.shorten_first_felt_interp_polyn && (i == 0)));
                }
                auto felt_interp_vec = builder.CreateVector(felt_interp);

                vector<flatbuffers::Offset<fbs::BatchedPlaintextPolyn>> batched_interp;
                for (size_t i = 0; i < interp_count; i++) {
                    const auto &polyn =
                        *c.batched_interp_polyns()->Get(static_cast<flatbuffers::uoffset_t>(i));
                    size_t drop_count = 0;
                    if ((changes.empty_first_batched_interp_polyn && (i == 0)) ||
                        (changes.empty_last_batched_interp_polyn && (i + 1 == interp_count))) {
                        drop_count = polyn.coeffs()->size();
                    }
                    if (changes.shorten_last_batched_interp_polyn && (i + 1 == interp_count)) {
                        drop_count = 1;
                    }
                    batched_interp.push_back(copy_batched_polyn(builder, polyn, drop_count));
                }
                auto batched_interp_vec = builder.CreateVector(batched_interp);

                fbs::BinBundleCacheBuilder cache_builder(builder);
                if (!felt_matching.IsNull()) {
                    cache_builder.add_felt_matching_polyns(felt_matching);
                    cache_builder.add_batched_matching_polyn(batched_matching);
                }
                cache_builder.add_felt_interp_polyns(felt_interp_vec);
                cache_builder.add_batched_interp_polyns(batched_interp_vec);
                cache = cache_builder.Finish();
            }

            vector<fbs::ItemHash> hashes;
            bool has_hashed_items = false;
            if (bb->hashed_items() && !changes.drop_hashed_items) {
                for (const auto *hash : *bb->hashed_items()) {
                    hashes.push_back(*hash);
                }
                if (changes.drop_last_hashed_item) {
                    hashes.pop_back();
                }
                if (changes.add_extra_hashed_item) {
                    hashes.emplace_back(1, 2);
                }
                has_hashed_items = true;
            } else if (!bb->hashed_items() && changes.add_hashed_items) {
                hashes.emplace_back(1, 2);
                has_hashed_items = true;
            }
            flatbuffers::Offset<flatbuffers::Vector<const fbs::ItemHash *>> hashed_items;
            if (has_hashed_items) {
                hashed_items = builder.CreateVectorOfStructs(hashes);
            }

            fbs::BinBundleBuilder bb_builder(builder);
            bb_builder.add_bundle_idx(bb->bundle_idx());
            bb_builder.add_mod(bb->mod());
            bb_builder.add_item_bins(item_bins);
            bb_builder.add_label_bins(label_bins_vec);
            if (!cache.IsNull()) {
                bb_builder.add_cache(cache);
            }
            bb_builder.add_stripped(bb->stripped());
            if (has_hashed_items) {
                bb_builder.add_hashed_items(hashed_items);
            }
            builder.FinishSizePrefixed(bb_builder.Finish());

            return { reinterpret_cast<const char *>(builder.GetBufferPointer()),
                     builder.GetSize() };
        }

        /**
        Returns whether loading the given saved BinBundle, with the given changes, into a new
        BinBundle with match tags fails as malformed data should.
        */
        bool tag_load_refused(
            const CryptoContext &context,
            const PSIParams &params,
            size_t label_size,
            const string &bytes,
            const BinBundleChanges &changes)
        {
            BinBundle bb = make_tag_bundle(context, params, label_size);
            try {
                load_from_string(bb, rebuild_bin_bundle(bytes, changes));
            } catch (const runtime_error &) {
                return true;
            }
            return false;
        }
    } // namespace

    TEST(BinBundleTagTests, Create)
    {
        PSIParams params = make_tag_params(1);
        CryptoContext context(params);
        context.set_evaluator();

        // The tag parts are label parts, so there must be at least that many of them
        ASSERT_THROW(make_tag_bundle(context, params, tag_part_count - 1), invalid_argument);

        BinBundle bb = make_tag_bundle(context, params, tag_part_count);
        ASSERT_TRUE(bb.uses_tags());
        ASSERT_EQ(tag_part_count, bb.get_tag_part_count());
        ASSERT_EQ(tag_part_count, bb.get_label_size());
        ASSERT_TRUE(bb.empty());
        ASSERT_FALSE(bb.is_stripped());
        ASSERT_EQ(params.bins_per_bundle(), bb.get_num_bins());
        ASSERT_EQ(params.bins_per_bundle(), bb.get_item_bins().size());
        ASSERT_EQ(params.bins_per_bundle(), bb.get_hashed_item_bins().size());

        // A BinBundle without match tags keeps no HashedItems
        BinBundle untagged(context, 2, tag_max_bin_size, 0, params.bins_per_bundle(), true, false);
        ASSERT_FALSE(untagged.uses_tags());
        ASSERT_EQ(0, untagged.get_tag_part_count());
        ASSERT_TRUE(untagged.get_hashed_item_bins().empty());

        // Neither does a stripped one, nor one cleared to be stripped
        BinBundle stripped(
            context, tag_part_count, tag_max_bin_size, 0, params.bins_per_bundle(), true, true, 1);
        ASSERT_TRUE(stripped.is_stripped());
        ASSERT_TRUE(stripped.get_hashed_item_bins().empty());
        bb.clear(true);
        ASSERT_TRUE(bb.get_hashed_item_bins().empty());
        bb.clear();
        ASSERT_EQ(params.bins_per_bundle(), bb.get_hashed_item_bins().size());
    }

    TEST(BinBundleTagTests, InsertFindOverwriteRemove)
    {
        for (uint32_t felts_per_item : { 1U, 2U, 3U }) {
            PSIParams params = make_tag_params(felts_per_item);
            CryptoContext context(params);
            context.set_evaluator();

            size_t label_size = tag_part_count + 2;
            BinBundle bb = make_tag_bundle(context, params, label_size);

            vector<felt_t> felts_a(felts_per_item, 5);
            vector<felt_t> felts_b(felts_per_item, 6);
            TaggedAlgItemLabel a = make_tagged_item(1, felts_a, label_size, 100);
            TaggedAlgItemLabel b = make_tagged_item(2, felts_b, label_size, 200);
            HashedItem stranger(3, ~uint64_t(3));

            // A dry run changes nothing
            ASSERT_EQ(1, bb.multi_insert_dry_run(a, 0));
            ASSERT_TRUE(bb.empty());
            ASSERT_FALSE(bb.multi_contains(a, 0));

            ASSERT_EQ(1, bb.multi_insert_for_real(a, 0));
            ASSERT_EQ(2, bb.multi_insert_for_real(b, 0));
            ASSERT_FALSE(bb.empty());

            // The label polynomials interpolate through the field elements, so another item with
            // the same field elements cannot go into the same bins
            ASSERT_EQ(
                -1, bb.multi_insert_dry_run(make_tagged_item(3, felts_a, label_size, 300), 0));
            ASSERT_EQ(
                -1, bb.multi_insert_for_real(make_tagged_item(3, felts_b, label_size, 300), 0));

            // Inserting where the item does not fit fails without a change
            ASSERT_EQ(-1, bb.multi_insert_for_real(a, bb.get_num_bins() - felts_per_item + 1));
            ASSERT_EQ(-1, bb.multi_insert_for_real(a, bb.get_num_bins()));

            // The HashedItems are kept in step with the field elements
            for (size_t s = 0; s < felts_per_item; s++) {
                ASSERT_EQ(felts_a[s], bb.get_item_bins()[s][0]);
                ASSERT_EQ(felts_b[s], bb.get_item_bins()[s][1]);
                ASSERT_EQ(vector<HashedItem>({ a.item, b.item }), bb.get_hashed_item_bins()[s]);
            }

            // An item is found by its HashedItem, and an item with the same field elements but
            // another HashedItem is not found
            ASSERT_TRUE(bb.multi_contains(a, 0));
            ASSERT_TRUE(bb.multi_contains(felts_b, b.item, 0));
            ASSERT_FALSE(bb.multi_contains(felts_a, stranger, 0));
            ASSERT_FALSE(bb.multi_contains(a, 1));

            vector<felt_t> labels;
            ASSERT_TRUE(bb.try_get_multi_label(felts_a, a.item, 0, labels));
            ASSERT_EQ(labels_of(a), labels);
            ASSERT_TRUE(bb.try_get_multi_label(felts_b, b.item, 0, labels));
            ASSERT_EQ(labels_of(b), labels);
            ASSERT_FALSE(bb.try_get_multi_label(felts_a, stranger, 0, labels));
            ASSERT_TRUE(labels.empty());

            // Overwriting changes the item's label parts and nothing else
            TaggedAlgItemLabel a2 = make_tagged_item(1, felts_a, label_size, 900);
            ASSERT_TRUE(bb.try_multi_overwrite(a2, 0));
            ASSERT_TRUE(bb.try_get_multi_label(felts_a, a.item, 0, labels));
            ASSERT_EQ(labels_of(a2), labels);
            ASSERT_TRUE(bb.try_get_multi_label(felts_b, b.item, 0, labels));
            ASSERT_EQ(labels_of(b), labels);
            ASSERT_FALSE(bb.try_multi_overwrite(make_tagged_item(3, felts_a, label_size, 300), 0));
            ASSERT_TRUE(bb.try_get_multi_label(felts_a, a.item, 0, labels));
            ASSERT_EQ(labels_of(a2), labels);

            // An item that is not there is not removed, and nothing changes
            ASSERT_FALSE(bb.try_multi_remove(felts_a, stranger, 0));
            ASSERT_FALSE(bb.try_multi_remove(felts_a, a.item, 1));
            ASSERT_TRUE(bb.multi_contains(a, 0));

            // Removing an item removes what is kept with it
            ASSERT_TRUE(bb.try_multi_remove(felts_a, a.item, 0));
            ASSERT_FALSE(bb.multi_contains(a, 0));
            ASSERT_TRUE(bb.try_get_multi_label(felts_b, b.item, 0, labels));
            ASSERT_EQ(labels_of(b), labels);
            for (size_t s = 0; s < felts_per_item; s++) {
                ASSERT_EQ(vector<felt_t>({ felts_b[s] }), bb.get_item_bins()[s]);
                ASSERT_EQ(vector<HashedItem>({ b.item }), bb.get_hashed_item_bins()[s]);
                for (size_t p = 0; p < label_size; p++) {
                    ASSERT_EQ(1, bb.get_label_bins()[p][s].size());
                }
            }

            // Now another item can have those field elements
            TaggedAlgItemLabel c = make_tagged_item(3, felts_a, label_size, 300);
            ASSERT_EQ(2, bb.multi_insert_for_real(c, 0));
            ASSERT_TRUE(bb.try_get_multi_label(felts_a, c.item, 0, labels));
            ASSERT_EQ(labels_of(c), labels);
            ASSERT_FALSE(bb.try_get_multi_label(felts_a, a.item, 0, labels));

            ASSERT_TRUE(bb.try_multi_remove(felts_a, c.item, 0));
            ASSERT_TRUE(bb.try_multi_remove(felts_b, b.item, 0));
            ASSERT_TRUE(bb.empty());
        }
    }

    TEST(BinBundleTagTests, ReplaceTakesTheStoredItemsPlaces)
    {
        // An item that replaces a stored one takes its places in the bins, with its HashedItem
        // and every label part, so that the bins hold as many items as before: this is how an
        // item takes the place of one moved to another BinBundle
        for (uint32_t felts_per_item : { 1U, 2U, 3U }) {
            PSIParams params = make_tag_params(felts_per_item);
            CryptoContext context(params);
            context.set_evaluator();

            size_t label_size = tag_part_count + 2;
            BinBundle bb = make_tag_bundle(context, params, label_size);

            vector<felt_t> felts_a(felts_per_item, 5);
            vector<felt_t> felts_b(felts_per_item, 6);
            vector<felt_t> felts_c(felts_per_item, 7);
            TaggedAlgItemLabel a = make_tagged_item(1, felts_a, label_size, 100);
            TaggedAlgItemLabel b = make_tagged_item(2, felts_b, label_size, 200);
            TaggedAlgItemLabel c = make_tagged_item(3, felts_c, label_size, 300);
            ASSERT_EQ(1, bb.multi_insert_for_real(a, 0));
            ASSERT_EQ(2, bb.multi_insert_for_real(b, 0));
            bb.regen_cache();
            ASSERT_FALSE(bb.cache_invalid());

            // A dry run changes nothing
            ASSERT_TRUE(bb.try_multi_replace(a.item, 0, c, 0, true));
            ASSERT_TRUE(bb.multi_contains(a, 0));
            ASSERT_FALSE(bb.multi_contains(c, 0));
            ASSERT_FALSE(bb.cache_invalid());

            // Nothing is replaced that is not stored where it is looked for, and no item takes a
            // place if another stored item has one of its field elements
            ASSERT_FALSE(bb.try_multi_replace(c.item, 0, c, 0, false));
            ASSERT_FALSE(bb.try_multi_replace(a.item, 1, c, 0, false));
            ASSERT_FALSE(bb.try_multi_replace(a.item, 2, c, 0, false));
            ASSERT_FALSE(bb.try_multi_replace(a.item, 0, c, felts_per_item, false));
            ASSERT_FALSE(bb.try_multi_replace(
                a.item, 0, make_tagged_item(4, felts_b, label_size, 400), 0, false));
            ASSERT_FALSE(bb.try_multi_replace(a.item, 0, c, bb.get_num_bins(), false));
            ASSERT_TRUE(bb.multi_contains(a, 0));
            ASSERT_FALSE(bb.cache_invalid());

            // c takes the places of a, and b is left as it was
            ASSERT_TRUE(bb.try_multi_replace(a.item, 0, c, 0, false));
            ASSERT_TRUE(bb.cache_invalid());
            ASSERT_FALSE(bb.multi_contains(a, 0));
            ASSERT_TRUE(bb.multi_contains(c, 0));
            ASSERT_TRUE(bb.multi_contains(b, 0));
            for (size_t s = 0; s < felts_per_item; s++) {
                ASSERT_EQ(vector<felt_t>({ felts_c[s], felts_b[s] }), bb.get_item_bins()[s]);
                ASSERT_EQ(vector<HashedItem>({ c.item, b.item }), bb.get_hashed_item_bins()[s]);
            }
            vector<felt_t> labels;
            ASSERT_TRUE(bb.try_get_multi_label(felts_c, c.item, 0, labels));
            ASSERT_EQ(labels_of(c), labels);
            ASSERT_TRUE(bb.try_get_multi_label(felts_b, b.item, 0, labels));
            ASSERT_EQ(labels_of(b), labels);

            // The field elements of a are free again, and those of c are taken
            ASSERT_EQ(
                -1, bb.multi_insert_dry_run(make_tagged_item(5, felts_c, label_size, 500), 0));
            ASSERT_EQ(
                3, bb.multi_insert_for_real(make_tagged_item(5, felts_a, label_size, 500), 0));

            // An item can take the places of one with the same field elements
            TaggedAlgItemLabel c2 = make_tagged_item(6, felts_c, label_size, 600);
            ASSERT_TRUE(bb.try_multi_replace(c.item, 0, c2, 0, false));
            ASSERT_FALSE(bb.multi_contains(c, 0));
            ASSERT_TRUE(bb.try_get_multi_label(felts_c, c2.item, 0, labels));
            ASSERT_EQ(labels_of(c2), labels);
            for (size_t s = 0; s < felts_per_item; s++) {
                ASSERT_EQ(3, bb.get_item_bins()[s].size());
                for (size_t p = 0; p < label_size; p++) {
                    ASSERT_EQ(3, bb.get_label_bins()[p][s].size());
                }
            }

            // The regenerated cache is that of a BinBundle that held these items from the start
            bb.regen_cache();
            BinBundle fresh = make_tag_bundle(context, params, label_size);
            ASSERT_EQ(1, fresh.multi_insert_for_real(c2, 0));
            ASSERT_EQ(2, fresh.multi_insert_for_real(b, 0));
            ASSERT_EQ(
                3, fresh.multi_insert_for_real(make_tagged_item(5, felts_a, label_size, 500), 0));
            fresh.regen_cache();
            for (size_t p = 0; p < label_size; p++) {
                ASSERT_EQ(
                    fresh.get_cache().felt_interp_polyns[p], bb.get_cache().felt_interp_polyns[p]);
                ASSERT_EQ(
                    fresh.get_cache().batched_interp_polyns[p].batched_coeffs,
                    bb.get_cache().batched_interp_polyns[p].batched_coeffs);
            }
        }
    }

    TEST(BinBundleTagTests, ItemsWithTheSameFieldElementsAreToldApart)
    {
        // With few bits per item, different items can have the same field elements in the same
        // bins. They cannot share a BinBundle, so they go into different BinBundles at the same
        // bundle index, and every lookup must find the item asked for and never another.
        PSIParams params = make_tag_params(2);
        CryptoContext context(params);
        context.set_evaluator();

        size_t label_size = tag_part_count + 1;
        vector<BinBundle> bundles;
        for (int i = 0; i < 3; i++) {
            bundles.push_back(make_tag_bundle(context, params, label_size));
        }

        vector<felt_t> felts{ 77, 88 };
        vector<TaggedAlgItemLabel> items;
        for (uint64_t i = 0; i < 3; i++) {
            items.push_back(make_tagged_item(i + 1, felts, label_size, 1000 * (i + 1)));
            if (i) {
                ASSERT_EQ(-1, bundles[0].multi_insert_dry_run(items[i], 6));
            }
            ASSERT_EQ(1, bundles[i].multi_insert_for_real(items[i], 6));
        }

        for (size_t i = 0; i < 3; i++) {
            for (size_t j = 0; j < 3; j++) {
                ASSERT_EQ(i == j, bundles[j].multi_contains(items[i], 6));
            }
        }

        // Overwrite the second one
        TaggedAlgItemLabel second = make_tagged_item(2, felts, label_size, 5000);
        ASSERT_FALSE(bundles[0].try_multi_overwrite(second, 6));
        ASSERT_TRUE(bundles[1].try_multi_overwrite(second, 6));
        ASSERT_FALSE(bundles[2].try_multi_overwrite(second, 6));

        vector<felt_t> labels;
        for (size_t j = 0; j < 3; j++) {
            for (size_t i = 0; i < 3; i++) {
                ASSERT_EQ(i == j, bundles[j].try_get_multi_label(felts, items[i].item, 6, labels));
            }
        }
        ASSERT_TRUE(bundles[0].try_get_multi_label(felts, items[0].item, 6, labels));
        ASSERT_EQ(labels_of(items[0]), labels);
        ASSERT_TRUE(bundles[1].try_get_multi_label(felts, items[1].item, 6, labels));
        ASSERT_EQ(labels_of(second), labels);
        ASSERT_TRUE(bundles[2].try_get_multi_label(felts, items[2].item, 6, labels));
        ASSERT_EQ(labels_of(items[2]), labels);

        // Remove the third one; the others stay where they are
        ASSERT_FALSE(bundles[0].try_multi_remove(felts, items[2].item, 6));
        ASSERT_FALSE(bundles[1].try_multi_remove(felts, items[2].item, 6));
        ASSERT_TRUE(bundles[2].try_multi_remove(felts, items[2].item, 6));
        ASSERT_TRUE(bundles[2].empty());
        ASSERT_TRUE(bundles[0].multi_contains(items[0], 6));
        ASSERT_TRUE(bundles[1].multi_contains(items[1], 6));
    }

    TEST(BinBundleTagTests, AnItemTheFilterRefusesIsStillFound)
    {
        // See BinBundleTests.AnItemTheFilterRefusesIsStillFound: the filter refuses the last of
        // these, and the item must still be found, here by its HashedItem
        const vector<felt_t> values{
            1, 252, 11389, 12874, 17547, 21064, 37127, 40541, 41546, 100000
        };

        PSIParams params = make_tag_params(1);
        CryptoContext context(params);
        context.set_evaluator();

        size_t label_size = tag_part_count;
        BinBundle bb(
            context, label_size, 50, 0, params.bins_per_bundle(), true, false, tag_part_count);

        vector<TaggedAlgItemLabel> items;
        for (size_t i = 0; i < values.size(); i++) {
            items.push_back(make_tagged_item(i + 1, { values[i] }, label_size, 10 * i));
            ASSERT_LE(0, bb.multi_insert_for_real(items.back(), 0));
        }

        vector<felt_t> labels;
        for (const auto &item : items) {
            ASSERT_TRUE(bb.multi_contains(item, 0));
            ASSERT_TRUE(
                bb.try_get_multi_label({ item.alg_item_label[0].first }, item.item, 0, labels));
            ASSERT_EQ(labels_of(item), labels);
        }

        // Removing the refused item works too, and leaves the others
        ASSERT_TRUE(bb.try_multi_remove({ values.back() }, items.back().item, 0));
        ASSERT_FALSE(bb.multi_contains(items.back(), 0));
        for (size_t i = 0; i + 1 < items.size(); i++) {
            ASSERT_TRUE(bb.multi_contains(items[i], 0));
        }
    }

    TEST(BinBundleTagTests, AMoveCompletesWhenLoggingThrows)
    {
        // A SenderDB moves an item to another BinBundle by inserting it there and then putting a
        // new item in its place, and relies on neither step throwing once it has begun to change
        // a BinBundle: an exception could only be met by undoing a change, which can fail in
        // turn, and the item would be lost or stored twice. Each step logs, once its change is
        // made, that cuckoo filters refused an item, and logging can throw, as it allocates and
        // calls the user's handler; here the handler throws. The values of
        // BinBundleTests.AnItemTheFilterRefusesIsStillFound fill the filters of the bins in both
        // BinBundles, so that the filters refuse the moved item in one and the new item in the
        // other.
        const vector<felt_t> colliding{ 1, 252, 11389, 12874, 17547, 21064, 37127, 40541, 41546 };

        for (uint32_t felts_per_item : { 1U, 2U }) {
            PSIParams params = make_tag_params(felts_per_item);
            CryptoContext context(params);
            context.set_evaluator();

            size_t label_size = tag_part_count + 1;
            auto make_bundle = [&] {
                return BinBundle(
                    context,
                    label_size,
                    50,
                    0,
                    params.bins_per_bundle(),
                    true,
                    false,
                    tag_part_count);
            };
            BinBundle source = make_bundle();
            BinBundle destination = make_bundle();

            uint64_t id = 1;
            for (felt_t value : colliding) {
                vector<felt_t> felts(felts_per_item, value);
                ASSERT_LT(
                    0,
                    source.multi_insert_for_real(
                        make_tagged_item(id++, felts, label_size, 100), 0));
                ASSERT_LT(
                    0,
                    destination.multi_insert_for_real(
                        make_tagged_item(id++, felts, label_size, 200), 0));
            }
            vector<felt_t> moved_felts(felts_per_item, 7);
            vector<felt_t> new_felts(felts_per_item, 9);
            TaggedAlgItemLabel moved = make_tagged_item(id++, moved_felts, label_size, 300);
            TaggedAlgItemLabel new_item = make_tagged_item(id++, new_felts, label_size, 400);
            size_t pos = colliding.size();
            auto bin_size = static_cast<int32_t>(pos + 1);
            ASSERT_EQ(bin_size, source.multi_insert_for_real(moved, 0));

            RefusalLogThrows log;

            // The move as SenderDB makes it: both steps are checked first, then taken
            ASSERT_EQ(bin_size, destination.multi_insert_dry_run(moved, 0));
            ASSERT_TRUE(source.try_multi_replace(moved.item, pos, new_item, 0, true));
            ASSERT_EQ(0, log.refusal_count());
            int32_t inserted = -1;
            ASSERT_NO_THROW(inserted = destination.multi_insert_for_real(moved, 0));
            ASSERT_EQ(bin_size, inserted);
            ASSERT_EQ(1, log.refusal_count());
            bool replaced = false;
            ASSERT_NO_THROW(
                replaced = source.try_multi_replace(moved.item, pos, new_item, 0, false));
            ASSERT_TRUE(replaced);
            ASSERT_EQ(2, log.refusal_count());

            // The moved item is stored once, in the destination, and the new item has taken its
            // place in the source, with every label part
            for (size_t s = 0; s < felts_per_item; s++) {
                const vector<HashedItem> &in_source = source.get_hashed_item_bins()[s];
                const vector<HashedItem> &in_destination = destination.get_hashed_item_bins()[s];
                ASSERT_EQ(0, count(in_source.begin(), in_source.end(), moved.item));
                ASSERT_EQ(1, count(in_destination.begin(), in_destination.end(), moved.item));
                ASSERT_EQ(1, count(in_source.begin(), in_source.end(), new_item.item));
                ASSERT_EQ(pos + 1, source.get_item_bins()[s].size());
                ASSERT_EQ(pos + 1, destination.get_item_bins()[s].size());
                for (size_t p = 0; p < label_size; p++) {
                    ASSERT_EQ(pos + 1, source.get_label_bins()[p][s].size());
                    ASSERT_EQ(pos + 1, destination.get_label_bins()[p][s].size());
                }
            }
            vector<felt_t> labels;
            ASSERT_TRUE(destination.try_get_multi_label(moved_felts, moved.item, 0, labels));
            ASSERT_EQ(labels_of(moved), labels);
            ASSERT_TRUE(source.try_get_multi_label(new_felts, new_item.item, 0, labels));
            ASSERT_EQ(labels_of(new_item), labels);
            ASSERT_FALSE(source.multi_contains(moved, 0));
            ASSERT_TRUE(source.cache_invalid());
            ASSERT_TRUE(destination.cache_invalid());
        }
    }

    TEST(BinBundleTests, AnInsertionCompletesWhenLoggingThrows)
    {
        // Without match tags, an insertion also logs that a cuckoo filter refused the item only
        // once the item is stored, with its label parts if it has any, so that a log handler that
        // throws cannot leave the item partly stored. The values of
        // AnItemTheFilterRefusesIsStillFound make the filter refuse the last of them.
        const vector<felt_t> values{
            1, 252, 11389, 12874, 17547, 21064, 37127, 40541, 41546, 100000
        };

        auto params = get_params1();
        CryptoContext context(*params);
        context.set_evaluator();

        // Labeled
        {
            BinBundle bb(context, 1, 50, 0, params->bins_per_bundle(), true, false);

            RefusalLogThrows log;
            for (felt_t value : values) {
                vector<pair<felt_t, vector<felt_t>>> one{ { value, { value } } };
                int32_t inserted = -1;
                ASSERT_NO_THROW(inserted = bb.multi_insert_for_real(one, 0));
                ASSERT_LT(0, inserted);
            }
            ASSERT_EQ(1, log.refusal_count());

            ASSERT_EQ(values.size(), bb.get_item_bins()[0].size());
            ASSERT_EQ(values.size(), bb.get_label_bins()[0][0].size());
            for (felt_t value : values) {
                vector<felt_t> labels;
                ASSERT_TRUE(bb.try_get_multi_label({ value }, 0, labels));
                ASSERT_EQ(vector<felt_t>{ value }, labels);
            }
        }

        // Unlabeled
        {
            BinBundle bb(context, 0, 50, 0, params->bins_per_bundle(), true, false);

            RefusalLogThrows log;
            for (felt_t value : values) {
                int32_t inserted = -1;
                ASSERT_NO_THROW(inserted = bb.multi_insert_for_real(vector<felt_t>{ value }, 0));
                ASSERT_LT(0, inserted);
            }
            ASSERT_EQ(1, log.refusal_count());

            ASSERT_EQ(values.size(), bb.get_item_bins()[0].size());
            for (felt_t value : values) {
                ASSERT_TRUE(bb.multi_contains(vector<felt_t>{ value }, 0));
            }
        }
    }

    TEST(BinBundleTagTests, OperationsOfTheOtherKindAreRefused)
    {
        PSIParams params = make_tag_params(1);
        CryptoContext context(params);
        context.set_evaluator();

        size_t label_size = tag_part_count + 1;
        BinBundle tagged = make_tag_bundle(context, params, label_size);
        BinBundle untagged(
            context, label_size, tag_max_bin_size, 0, params.bins_per_bundle(), true, false);
        BinBundle unlabeled(context, 0, tag_max_bin_size, 0, params.bins_per_bundle(), true, false);

        TaggedAlgItemLabel item = make_tagged_item(1, { 5 }, label_size, 100);
        vector<felt_t> felts{ 5 };
        vector<felt_t> labels;

        // A BinBundle with match tags must know the HashedItem of every item
        ASSERT_THROW(tagged.multi_insert_for_real(item.alg_item_label, 0), logic_error);
        ASSERT_THROW(tagged.multi_insert_for_real(felts, 0), logic_error);
        ASSERT_THROW(tagged.try_multi_overwrite(item.alg_item_label, 0), logic_error);
        ASSERT_THROW(tagged.try_multi_overwrite(felts, 0), logic_error);
        ASSERT_THROW(static_cast<void>(tagged.multi_contains(felts, 0)), logic_error);
        ASSERT_THROW(static_cast<void>(tagged.multi_contains(item.alg_item_label, 0)), logic_error);
        ASSERT_THROW(tagged.try_multi_remove(felts, 0), logic_error);
        ASSERT_THROW(static_cast<void>(tagged.try_get_multi_label(felts, 0, labels)), logic_error);
        ASSERT_TRUE(tagged.empty());

        // A BinBundle without match tags keeps no HashedItems
        for (BinBundle *bb : { &untagged, &unlabeled }) {
            ASSERT_THROW(bb->multi_insert_for_real(item, 0), logic_error);
            ASSERT_THROW(bb->multi_insert_dry_run(item, 0), logic_error);
            ASSERT_THROW(bb->try_multi_overwrite(item, 0), logic_error);
            ASSERT_THROW(static_cast<void>(bb->multi_contains(item, 0)), logic_error);
            ASSERT_THROW(static_cast<void>(bb->multi_contains(felts, item.item, 0)), logic_error);
            ASSERT_THROW(bb->try_multi_remove(felts, item.item, 0), logic_error);
            ASSERT_THROW(bb->try_multi_replace(item.item, 0, item, 0, true), logic_error);
            ASSERT_THROW(
                static_cast<void>(bb->try_get_multi_label(felts, item.item, 0, labels)),
                logic_error);
            ASSERT_TRUE(bb->empty());
        }

        // An item must have exactly as many label parts as the BinBundle
        ASSERT_THROW(
            tagged.multi_insert_for_real(make_tagged_item(1, { 5 }, label_size - 1, 100), 0),
            invalid_argument);
        ASSERT_THROW(
            tagged.multi_insert_for_real(make_tagged_item(1, { 5 }, label_size + 1, 100), 0),
            invalid_argument);
        ASSERT_TRUE(tagged.empty());
        ASSERT_LT(0, tagged.multi_insert_for_real(item, 0));
        ASSERT_THROW(
            tagged.try_multi_replace(
                item.item, 0, make_tagged_item(2, { 6 }, label_size - 1, 100), 0, false),
            invalid_argument);
        ASSERT_TRUE(tagged.try_multi_remove(felts, item.item, 0));
        ASSERT_TRUE(tagged.empty());

        // Nothing changes a stripped BinBundle
        ASSERT_LT(0, tagged.multi_insert_for_real(item, 0));
        tagged.strip();
        ASSERT_THROW(tagged.multi_insert_for_real(item, 1), logic_error);
        ASSERT_THROW(tagged.try_multi_overwrite(item, 0), logic_error);
        ASSERT_THROW(static_cast<void>(tagged.multi_contains(item, 0)), logic_error);
        ASSERT_THROW(tagged.try_multi_remove(felts, item.item, 0), logic_error);
        ASSERT_THROW(tagged.try_multi_replace(item.item, 0, item, 0, true), logic_error);
        ASSERT_THROW(
            static_cast<void>(tagged.try_get_multi_label(felts, item.item, 0, labels)),
            logic_error);
    }

    TEST(BinBundleTagTests, CacheHoldsOnlyLabelPolynomials)
    {
        PSIParams params = make_tag_params(2);
        CryptoContext context(params);
        context.set_evaluator();
        const Modulus &mod = params.seal_params().plain_modulus();

        size_t label_size = tag_part_count + 2;
        BinBundle bb = make_tag_bundle(context, params, label_size);

        // Three items in bins 0 and 1, one in bins 10 and 11, and nothing elsewhere
        vector<TaggedAlgItemLabel> items{ make_tagged_item(1, { 3, 4 }, label_size, 100),
                                          make_tagged_item(2, { 5, 6 }, label_size, 200),
                                          make_tagged_item(3, { 7, 8 }, label_size, 300) };
        for (const auto &item : items) {
            ASSERT_LT(0, bb.multi_insert_for_real(item, 0));
        }
        TaggedAlgItemLabel lone = make_tagged_item(4, { 9, 10 }, label_size, 400);
        ASSERT_EQ(1, bb.multi_insert_for_real(lone, 10));
        bb.regen_cache();

        const BinBundleCache &cache = bb.get_cache();
        ASSERT_TRUE(cache.felt_matching_polyns.empty());
        ASSERT_FALSE(cache.batched_matching_polyn);
        ASSERT_EQ(label_size, cache.felt_interp_polyns.size());
        ASSERT_EQ(label_size, cache.batched_interp_polyns.size());

        for (size_t p = 0; p < label_size; p++) {
            ASSERT_EQ(params.bins_per_bundle(), cache.felt_interp_polyns[p].size());

            // A bin of k items has a polynomial of k coefficients, an empty bin the zero
            // polynomial, and the batched polynomial as many coefficients as the largest
            ASSERT_EQ(3, cache.felt_interp_polyns[p][0].size());
            ASSERT_EQ(3, cache.felt_interp_polyns[p][1].size());
            ASSERT_EQ(1, cache.felt_interp_polyns[p][10].size());
            ASSERT_EQ(1, cache.felt_interp_polyns[p][11].size());
            ASSERT_EQ(FEltPolyn{ 0 }, cache.felt_interp_polyns[p][5]);
            ASSERT_EQ(3, cache.batched_interp_polyns[p].batched_coeffs.size());

            // Each takes each item's label part at the item's field element
            for (const auto &item : items) {
                for (size_t s = 0; s < 2; s++) {
                    ASSERT_EQ(
                        item.alg_item_label[s].second[p],
                        evaluate(
                            cache.felt_interp_polyns[p][s], item.alg_item_label[s].first, mod));
                }
            }
            for (size_t s = 0; s < 2; s++) {
                ASSERT_EQ(
                    lone.alg_item_label[s].second[p],
                    evaluate(
                        cache.felt_interp_polyns[p][10 + s], lone.alg_item_label[s].first, mod));
            }
        }

        // A change invalidates the cache, and the new one is right again
        ASSERT_TRUE(bb.try_multi_overwrite(make_tagged_item(4, { 9, 10 }, label_size, 700), 10));
        ASSERT_TRUE(bb.cache_invalid());
        bb.regen_cache();
        ASSERT_EQ(
            700 + 10 * (label_size - 1),
            evaluate(bb.get_cache().felt_interp_polyns[label_size - 1][10], 9, mod));
    }

    TEST(BinBundleTagTests, SaveLoadAndStrip)
    {
        PSIParams params = make_tag_params(1);
        CryptoContext context(params);
        context.set_evaluator();

        size_t label_size = tag_part_count + 1;
        BinBundle bb = make_tag_bundle(context, params, label_size);
        vector<TaggedAlgItemLabel> items;
        for (uint64_t i = 0; i < 20; i++) {
            items.push_back(make_tagged_item(i + 1, { 100 + i }, label_size, 10 * i));
            ASSERT_LT(0, bb.multi_insert_for_real(items.back(), (i * 7) % 5));
        }

        // Without a cache and with one
        for (bool with_cache : { false, true }) {
            if (with_cache) {
                bb.regen_cache();
            }

            string bytes = save_to_string(bb);
            ASSERT_NE(nullptr, fbs::GetSizePrefixedBinBundle(bytes.data())->hashed_items());

            BinBundle bb2 = make_tag_bundle(context, params, label_size);
            load_from_string(bb2, bytes);
            ASSERT_EQ(with_cache, !bb2.cache_invalid());
            ASSERT_FALSE(bb2.is_stripped());
            ASSERT_EQ(bb.get_item_bins(), bb2.get_item_bins());
            ASSERT_EQ(bb.get_label_bins(), bb2.get_label_bins());
            ASSERT_EQ(bb.get_hashed_item_bins(), bb2.get_hashed_item_bins());
            vector<felt_t> labels;
            for (size_t i = 0; i < items.size(); i++) {
                ASSERT_TRUE(bb2.try_get_multi_label(
                    { items[i].alg_item_label[0].first }, items[i].item, (i * 7) % 5, labels));
                ASSERT_EQ(labels_of(items[i]), labels);
            }
            if (with_cache) {
                ASSERT_TRUE(bb2.get_cache().felt_matching_polyns.empty());
                ASSERT_FALSE(bb2.get_cache().batched_matching_polyn);
                for (size_t p = 0; p < label_size; p++) {
                    ASSERT_EQ(
                        bb.get_cache().felt_interp_polyns[p],
                        bb2.get_cache().felt_interp_polyns[p]);
                    ASSERT_EQ(
                        bb.get_cache().batched_interp_polyns[p].batched_coeffs,
                        bb2.get_cache().batched_interp_polyns[p].batched_coeffs);
                }
            }

            // Saving the loaded BinBundle gives the same bytes
            ASSERT_EQ(bytes, save_to_string(bb2));
        }

        // A stripped BinBundle keeps the batched polynomials and nothing else, not even the
        // HashedItems
        bb.strip();
        ASSERT_TRUE(bb.is_stripped());
        ASSERT_TRUE(bb.get_hashed_item_bins().empty());
        ASSERT_TRUE(bb.get_item_bins().empty());
        ASSERT_TRUE(bb.get_label_bins().empty());
        ASSERT_TRUE(bb.get_cache().felt_interp_polyns.empty());
        string stripped_bytes = save_to_string(bb);
        ASSERT_EQ(nullptr, fbs::GetSizePrefixedBinBundle(stripped_bytes.data())->hashed_items());

        BinBundle bb3 = make_tag_bundle(context, params, label_size);
        load_from_string(bb3, stripped_bytes);
        ASSERT_TRUE(bb3.is_stripped());
        ASSERT_TRUE(bb3.get_hashed_item_bins().empty());
        ASSERT_FALSE(bb3.get_cache().batched_matching_polyn);
        ASSERT_EQ(label_size, bb3.get_cache().batched_interp_polyns.size());
        for (size_t p = 0; p < label_size; p++) {
            ASSERT_EQ(4, bb3.get_cache().batched_interp_polyns[p].batched_coeffs.size());
            ASSERT_EQ(
                bb.get_cache().batched_interp_polyns[p].batched_coeffs,
                bb3.get_cache().batched_interp_polyns[p].batched_coeffs);
        }
        ASSERT_THROW(bb3.multi_insert_for_real(items[0], 0), logic_error);
        ASSERT_EQ(stripped_bytes, save_to_string(bb3));

        // Clearing makes room for items and their HashedItems again
        bb3.clear();
        ASSERT_EQ(params.bins_per_bundle(), bb3.get_hashed_item_bins().size());
        ASSERT_EQ(1, bb3.multi_insert_for_real(items[0], 0));
    }

    TEST(BinBundleTagTests, LoadRefusesTheOtherKindOfBinBundle)
    {
        PSIParams params = make_tag_params(1);
        CryptoContext context(params);
        context.set_evaluator();

        size_t label_size = tag_part_count;
        auto make_untagged = [&]() {
            return BinBundle(
                context, label_size, tag_max_bin_size, 0, params.bins_per_bundle(), true, false);
        };
        TaggedAlgItemLabel item = make_tagged_item(1, { 5 }, label_size, 100);

        // Saved without a cache, with one, and stripped
        vector<string> tagged_bytes;
        vector<string> untagged_bytes;
        {
            BinBundle tagged = make_tag_bundle(context, params, label_size);
            BinBundle untagged = make_untagged();
            ASSERT_LT(0, tagged.multi_insert_for_real(item, 0));
            ASSERT_LT(0, untagged.multi_insert_for_real(item.alg_item_label, 0));
            for (int i = 0; i < 3; i++) {
                if (i == 1) {
                    tagged.regen_cache();
                    untagged.regen_cache();
                }
                if (i == 2) {
                    tagged.strip();
                    untagged.strip();
                }
                tagged_bytes.push_back(save_to_string(tagged));
                untagged_bytes.push_back(save_to_string(untagged));
            }
        }

        for (size_t i = 0; i < 3; i++) {
            BinBundle into_tagged = make_tag_bundle(context, params, label_size);
            BinBundle into_untagged = make_untagged();
            ASSERT_THROW(load_from_string(into_tagged, untagged_bytes[i]), runtime_error);
            ASSERT_THROW(load_from_string(into_untagged, tagged_bytes[i]), runtime_error);

            // Each loads into its own kind
            ASSERT_NO_THROW(load_from_string(into_tagged, tagged_bytes[i]));
            ASSERT_NO_THROW(load_from_string(into_untagged, untagged_bytes[i]));
        }
    }

    TEST(BinBundleTagTests, LoadRefusesMalformedData)
    {
        PSIParams params = make_tag_params(1);
        CryptoContext context(params);
        context.set_evaluator();

        size_t label_size = tag_part_count + 1;
        BinBundle bb = make_tag_bundle(context, params, label_size);
        for (uint64_t i = 0; i < 6; i++) {
            ASSERT_LT(
                0,
                bb.multi_insert_for_real(
                    make_tagged_item(i + 1, { 10 + i }, label_size, i), i % 2));
        }
        string no_cache_bytes = save_to_string(bb);
        bb.regen_cache();
        string bytes = save_to_string(bb);
        bb.strip();
        string stripped_bytes = save_to_string(bb);

        // Unchanged, they load, so the failures below are the changes' doing
        for (const string &b : { no_cache_bytes, bytes, stripped_bytes }) {
            ASSERT_FALSE(tag_load_refused(context, params, label_size, b, {}));
        }

        // The HashedItems must be present exactly when the BinBundle is not stripped, and one
        // for each item
        BinBundleChanges c;
        c.drop_hashed_items = true;
        ASSERT_TRUE(tag_load_refused(context, params, label_size, no_cache_bytes, c));
        ASSERT_TRUE(tag_load_refused(context, params, label_size, bytes, c));
        c = {};
        c.drop_last_hashed_item = true;
        ASSERT_TRUE(tag_load_refused(context, params, label_size, no_cache_bytes, c));
        ASSERT_TRUE(tag_load_refused(context, params, label_size, bytes, c));
        c = {};
        c.add_extra_hashed_item = true;
        ASSERT_TRUE(tag_load_refused(context, params, label_size, no_cache_bytes, c));
        ASSERT_TRUE(tag_load_refused(context, params, label_size, bytes, c));
        c = {};
        c.add_hashed_items = true;
        ASSERT_TRUE(tag_load_refused(context, params, label_size, stripped_bytes, c));

        // There must be no matching polynomials
        c = {};
        c.add_matching_polyns = true;
        ASSERT_TRUE(tag_load_refused(context, params, label_size, bytes, c));
        ASSERT_TRUE(tag_load_refused(context, params, label_size, stripped_bytes, c));

        // There must be a label polynomial for each label part
        c = {};
        c.drop_last_interp_polyns = true;
        ASSERT_TRUE(tag_load_refused(context, params, label_size, bytes, c));
        ASSERT_TRUE(tag_load_refused(context, params, label_size, stripped_bytes, c));

        // A bin's label polynomial must have as many coefficients as the bin has items
        c = {};
        c.shorten_first_felt_interp_polyn = true;
        ASSERT_TRUE(tag_load_refused(context, params, label_size, bytes, c));

        // The batched label polynomials must have coefficients, the same number of them
        c = {};
        c.empty_first_batched_interp_polyn = true;
        ASSERT_TRUE(tag_load_refused(context, params, label_size, bytes, c));
        ASSERT_TRUE(tag_load_refused(context, params, label_size, stripped_bytes, c));
        c = {};
        c.shorten_last_batched_interp_polyn = true;
        ASSERT_TRUE(tag_load_refused(context, params, label_size, bytes, c));
        ASSERT_TRUE(tag_load_refused(context, params, label_size, stripped_bytes, c));
    }

    TEST(BinBundleTagTests, LoadWithoutTagsRequiresMatchingPolynomials)
    {
        // The schema does not require the matching polynomials, as a BinBundle with match tags
        // has none, so a BinBundle without match tags requires them itself
        auto params = get_params1();
        CryptoContext context(*params);
        context.set_evaluator();

        for (size_t label_size : { 0U, 1U }) {
            BinBundle untagged(
                context,
                label_size,
                params->table_params().max_items_per_bin,
                0,
                params->bins_per_bundle(),
                true,
                false);
            if (label_size) {
                ASSERT_LT(0, untagged.multi_insert_for_real(AlgItemLabel{ { 5, { 7 } } }, 0));
            } else {
                ASSERT_LT(0, untagged.multi_insert_for_real(vector<felt_t>{ 5 }, 0));
            }
            untagged.regen_cache();
            string bytes = save_to_string(untagged);
            untagged.strip();
            string stripped_bytes = save_to_string(untagged);

            BinBundle target(
                context,
                label_size,
                params->table_params().max_items_per_bin,
                0,
                params->bins_per_bundle(),
                true,
                false);
            ASSERT_NO_THROW(load_from_string(target, rebuild_bin_bundle(bytes, {})));
            ASSERT_NO_THROW(load_from_string(target, rebuild_bin_bundle(stripped_bytes, {})));

            BinBundleChanges c;
            c.drop_matching_polyns = true;
            ASSERT_THROW(load_from_string(target, rebuild_bin_bundle(bytes, c)), runtime_error);
            ASSERT_THROW(
                load_from_string(target, rebuild_bin_bundle(stripped_bytes, c)), runtime_error);

            c = {};
            c.add_hashed_items = true;
            ASSERT_THROW(load_from_string(target, rebuild_bin_bundle(bytes, c)), runtime_error);
        }
    }

    namespace {
        /**
        Collects the errors logged while it exists, and restores the global logger and log level
        when it is destroyed.
        */
        class ErrorCapture {
        public:
            ErrorCapture() : saved_level_(GetLogLevel())
            {
                array<Logger::log_handler_t, Logger::level_count> log_handlers{};
                log_handlers[static_cast<size_t>(LogLevel::error)] = [this](const string &msg) {
                    errors_.push_back(msg);
                };
                SetLogger(Logger::Create(std::move(log_handlers), {}, {}));
                SetLogLevel(LogLevel::error);
            }

            ~ErrorCapture()
            {
                CloseLogger();
                SetLogLevel(saved_level_);
            }

            ErrorCapture(const ErrorCapture &) = delete;

            ErrorCapture &operator=(const ErrorCapture &) = delete;

            /**
            Loads the saved BinBundle into bb, and returns the error logged as loading it failed,
            as malformed data should, or nothing if it loads.
            */
            string load_error(BinBundle &bb, const string &bytes)
            {
                errors_.clear();
                try {
                    load_from_string(bb, bytes);
                } catch (const runtime_error &) {
                    return errors_.empty() ? string("no error was logged") : errors_.back();
                }
                return {};
            }

        private:
            LogLevel saved_level_;

            vector<string> errors_;
        };
    } // namespace

    TEST(BinBundleTests, LoadRefusesEmptyPolynomials)
    {
        // A query evaluates the batched matching polynomial and every batched label polynomial of
        // a BinBundle without match tags, which cannot be done without a coefficient. Every
        // polynomial APSI makes has one: a matching polynomial has at least the constant 1, and a
        // label polynomial the zero polynomial's one. So a loaded BinBundle must hold at least one
        // coefficient for each, and is refused otherwise. In each change below the counts of
        // coefficients agree with each other, so that only their being zero can be refused.
        auto params = get_params1();
        CryptoContext context(*params);
        context.set_evaluator();

        for (size_t label_size : { 0U, 2U }) {
            SCOPED_TRACE("label_size " + to_string(label_size));
            auto new_bundle = [&] {
                return BinBundle(
                    context,
                    label_size,
                    params->table_params().max_items_per_bin,
                    0,
                    params->bins_per_bundle(),
                    true,
                    false);
            };

            BinBundle bb = new_bundle();
            for (felt_t i = 0; i < 12; i++) {
                size_t bin = static_cast<size_t>(i % 3);
                if (label_size) {
                    ASSERT_LT(
                        0, bb.multi_insert_for_real(AlgItemLabel{ { 100 + i, { i, 7 } } }, bin));
                } else {
                    ASSERT_LT(0, bb.multi_insert_for_real(vector<felt_t>{ 100 + i }, bin));
                }
            }
            bb.regen_cache();
            string bytes = save_to_string(bb);
            bb.strip();
            string stripped_bytes = save_to_string(bb);

            // Unchanged, they load, so the refusals below are the changes' doing
            ErrorCapture log;
            BinBundle target = new_bundle();
            for (const string &b : { bytes, stripped_bytes }) {
                ASSERT_EQ(string(), log.load_error(target, b));
                ASSERT_EQ(string(), log.load_error(target, rebuild_bin_bundle(b, {})));
            }

            // Not stripped, with every polynomial emptied, so that the largest number of
            // coefficients of a matching polynomial is zero
            BinBundleChanges c;
            c.empty_felt_polyns = true;
            c.empty_batched_matching_polyn = true;
            c.empty_first_batched_interp_polyn = true;
            c.empty_last_batched_interp_polyn = true;
            string error = log.load_error(target, rebuild_bin_bundle(bytes, c));
            ASSERT_NE(string::npos, error.find("matching polynomials with no coefficients"))
                << error;

            // Stripped, whose polynomials are batched only, with an empty matching polynomial
            c = {};
            c.empty_batched_matching_polyn = true;
            error = log.load_error(target, rebuild_bin_bundle(stripped_bytes, c));
            ASSERT_NE(string::npos, error.find("batched matching polynomial with no coefficients"))
                << error;

            // Either label part empty, stripped and not. Not stripped, the count of coefficients
            // is wrong as well.
            if (label_size) {
                for (bool first : { true, false }) {
                    c = {};
                    if (first) {
                        c.empty_first_batched_interp_polyn = true;
                    } else {
                        c.empty_last_batched_interp_polyn = true;
                    }

                    error = log.load_error(target, rebuild_bin_bundle(stripped_bytes, c));
                    ASSERT_NE(
                        string::npos,
                        error.find("batched interpolation polynomial with no coefficients"))
                        << error;
                    ASSERT_NE(string(), log.load_error(target, rebuild_bin_bundle(bytes, c)));
                }
            }
        }
    }

    TEST(BinBundleTests, BatchedPlaintextPolynEvalRefusesAnEmptyPolynomial)
    {
        // A polynomial without coefficients has no degree to evaluate it to. There are ciphertext
        // powers enough for a polynomial of up to five coefficients, so the polynomial being empty
        // is the only thing to refuse.
        auto params = get_params1();
        CryptoContext context(*params);
        context.set_evaluator();

        BatchedPlaintextPolyn empty(context);
        ASSERT_FALSE(empty);
        vector<Ciphertext> powers(5);
        MemoryPoolHandle pool = MemoryManager::GetPool();
        ASSERT_THROW(static_cast<void>(empty.eval(powers, pool)), invalid_argument);
        ASSERT_THROW(
            static_cast<void>(empty.eval_patstock(context, powers, 2, pool)), invalid_argument);
    }

    namespace {
        /**
        Collects what is logged while it exists about regenerating caches: for how many bins
        polynomials were computed, and the warnings that the polynomials a cache held could not be
        kept. Restores the global logger and log level when it is destroyed.
        */
        class RegenLog {
        public:
            RegenLog() : saved_level_(GetLogLevel())
            {
                array<Logger::log_handler_t, Logger::level_count> log_handlers{};
                log_handlers[static_cast<size_t>(LogLevel::debug)] = [this](const string &msg) {
                    const string text = "Computing the polynomials of ";
                    if (msg.rfind(text, 0) == 0) {
                        computed_bin_counts_.push_back(
                            static_cast<size_t>(stoull(msg.substr(text.size()))));
                    }
                };
                log_handlers[static_cast<size_t>(LogLevel::warning)] = [this](const string &msg) {
                    if (msg.rfind("The cache of a BinBundle", 0) == 0) {
                        cache_warnings_.push_back(msg);
                    }
                };
                SetLogger(Logger::Create(std::move(log_handlers), {}, {}));
                SetLogLevel(LogLevel::debug);
            }

            ~RegenLog()
            {
                CloseLogger();
                SetLogLevel(saved_level_);
            }

            RegenLog(const RegenLog &) = delete;

            RegenLog &operator=(const RegenLog &) = delete;

            /**
            Runs f, and returns, for each cache regenerated meanwhile, for how many bins
            polynomials were computed.
            */
            template <typename F>
            vector<size_t> computed_while(F &&f)
            {
                computed_bin_counts_.clear();
                f();
                return exchange(computed_bin_counts_, {});
            }

            /**
            Regenerates the cache of the BinBundle, and returns what computed_while returns.
            */
            vector<size_t> regen(BinBundle &bb)
            {
                return computed_while([&] { bb.regen_cache(); });
            }

            /**
            Returns the warnings that the polynomials a cache held could not be kept.
            */
            [[nodiscard]] const vector<string> &cache_warnings() const
            {
                return cache_warnings_;
            }

        private:
            LogLevel saved_level_;

            vector<size_t> computed_bin_counts_;

            vector<string> cache_warnings_;
        };

        /**
        What a BinBundle is made with, so that another like it can be made.
        */
        struct BundleShape {
            size_t label_size;

            size_t tag_part_count;

            size_t felts_per_item;

            size_t max_bin_size;

            size_t ps_low_degree;

            size_t num_bins;

            bool compressed;
        };

        BinBundle make_bundle(const CryptoContext &context, const BundleShape &shape)
        {
            return BinBundle(
                context,
                shape.label_size,
                shape.max_bin_size,
                shape.ps_low_degree,
                shape.num_bins,
                shape.compressed,
                false,
                shape.tag_part_count);
        }

        vector<size_t> dirty_bins_of(const BinBundle &bb)
        {
            vector<size_t> dirty;
            for (size_t bin = 0; bin < bb.get_dirty_bins().size(); bin++) {
                if (bb.get_dirty_bins()[bin]) {
                    dirty.push_back(bin);
                }
            }
            return dirty;
        }

        vector<size_t> bin_range(size_t first, size_t count)
        {
            vector<size_t> bins(count);
            iota(bins.begin(), bins.end(), first);
            return bins;
        }

        /**
        Checks that the cache of a BinBundle, generated after any changes to it, is the cache that
        a BinBundle holding the same items generates from nothing: the same polynomials for every
        bin, and the same plaintexts byte for byte, so that the two save the same bytes. Also
        checks that the label polynomials take the label parts of the items at their field
        elements and, without match tags, that the matching polynomials vanish there.
        */
        void check_cache_as_from_scratch(
            const BinBundle &bb, const CryptoContext &context, const BundleShape &shape)
        {
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_TRUE(dirty_bins_of(bb).empty());
            string bytes = save_to_string(bb);

            BinBundle scratch = make_bundle(context, shape);
            load_from_string(scratch, bytes);
            scratch.clear_cache();
            scratch.regen_cache();

            const BinBundleCache &cache = bb.get_cache();
            const BinBundleCache &expected = scratch.get_cache();
            ASSERT_EQ(expected.felt_matching_polyns, cache.felt_matching_polyns);
            ASSERT_EQ(expected.felt_interp_polyns, cache.felt_interp_polyns);
            ASSERT_EQ(
                expected.batched_matching_polyn.batched_coeffs,
                cache.batched_matching_polyn.batched_coeffs);
            ASSERT_EQ(expected.batched_interp_polyns.size(), cache.batched_interp_polyns.size());
            for (size_t p = 0; p < expected.batched_interp_polyns.size(); p++) {
                ASSERT_EQ(
                    expected.batched_interp_polyns[p].batched_coeffs,
                    cache.batched_interp_polyns[p].batched_coeffs)
                    << "label part " << p;
            }
            ASSERT_TRUE(save_to_string(scratch) == bytes) << "the saved BinBundles differ";

            const Modulus &mod =
                context.seal_context()->first_context_data()->parms().plain_modulus();
            const auto &item_bins = bb.get_item_bins();
            for (size_t bin = 0; bin < item_bins.size(); bin++) {
                for (size_t i = 0; i < item_bins[bin].size(); i++) {
                    felt_t x = item_bins[bin][i];
                    if (!bb.uses_tags()) {
                        ASSERT_EQ(0, evaluate(cache.felt_matching_polyns[bin], x, mod));
                    }
                    for (size_t p = 0; p < shape.label_size; p++) {
                        ASSERT_EQ(
                            bb.get_label_bins()[p][bin][i],
                            evaluate(cache.felt_interp_polyns[p][bin], x, mod));
                    }
                }
            }
        }

        /**
        What a BinBundle holds, bin by bin, and which of its bins are dirty
        */
        struct BundleState {
            vector<vector<felt_t>> item_bins;

            vector<vector<vector<felt_t>>> label_bins;

            vector<vector<HashedItem>> hashed_item_bins;

            vector<bool> dirty_bins;

            bool cache_invalid;

            explicit BundleState(const BinBundle &bb)
                : item_bins(bb.get_item_bins()), label_bins(bb.get_label_bins()),
                  hashed_item_bins(bb.get_hashed_item_bins()), dirty_bins(bb.get_dirty_bins()),
                  cache_invalid(bb.cache_invalid())
            {}

            [[nodiscard]] bool same_bin(const BundleState &other, size_t bin) const
            {
                if (item_bins[bin] != other.item_bins[bin]) {
                    return false;
                }
                for (size_t p = 0; p < label_bins.size(); p++) {
                    if (label_bins[p][bin] != other.label_bins[p][bin]) {
                        return false;
                    }
                }
                return hashed_item_bins.empty() ||
                       (hashed_item_bins[bin] == other.hashed_item_bins[bin]);
            }
        };

        /**
        Checks what an operation did to a BinBundle that was in the given state before it. One
        that failed, or was a dry run, changed nothing and marked nothing. One that succeeded
        changed no bin outside the bin_count bins beginning at first_bin, marked exactly those
        dirty, and invalidated the cache.
        */
        void check_marked(
            const BundleState &before,
            const BinBundle &bb,
            bool succeeded,
            size_t first_bin,
            size_t bin_count)
        {
            BundleState after(bb);
            ASSERT_EQ(before.item_bins.size(), after.item_bins.size());
            for (size_t bin = 0; bin < before.item_bins.size(); bin++) {
                bool marked = succeeded && (bin >= first_bin) && (bin - first_bin < bin_count);
                if (!marked) {
                    ASSERT_TRUE(before.same_bin(after, bin)) << "bin " << bin;
                }
                ASSERT_EQ(before.dirty_bins[bin] || marked, after.dirty_bins[bin]) << "bin " << bin;
            }
            ASSERT_EQ(before.cache_invalid || succeeded, after.cache_invalid);
        }

        /**
        Changes a BinBundle at random, with match tags if shape has tag parts and otherwise
        without, labeled if it has label parts, and checks after every change that exactly the
        bins it changed were marked dirty, and after about a third of them that regenerating the
        cache computes the polynomials of the dirty bins only, and gives what generating it from
        nothing gives. Most changes go to a few locations, so that their bins fill up to
        max_bin_size and empty again, and the field elements are few, so that insertions and
        replacements often fail; the sequence alternates between phases that favor insertions,
        changes and removals. The BinBundle is saved and loaded, with and without its cache, its
        cache is cleared now and then, and in the end it is changed and stripped.
        */
        void run_random_changes(
            const CryptoContext &context, const BundleShape &shape, uint64_t seed, size_t steps)
        {
            const bool tagged = shape.tag_part_count > 0;
            const bool labeled = shape.label_size > 0;
            const size_t f = shape.felts_per_item;
            const size_t num_bins = shape.num_bins;
            const size_t location_count = num_bins / f;
            const uint64_t mod =
                context.seal_context()->first_context_data()->parms().plain_modulus().value();
            const felt_t felt_range = 2 * shape.max_bin_size;
            const vector<size_t> hot_locations{ 0, 1, 2, location_count - 1 };

            // As in a SenderDB, a bin holds max_bin_size items with match tags, and fewer without
            const size_t bin_capacity = tagged ? shape.max_bin_size : shape.max_bin_size - 1;

            mt19937_64 rng(seed);
            auto uniform = [&](uint64_t bound) {
                return uniform_int_distribution<uint64_t>(0, bound - 1)(rng);
            };

            auto new_felts = [&] {
                vector<felt_t> felts(f);
                for (auto &felt : felts) {
                    felt = 1 + uniform(felt_range);
                }
                return felts;
            };

            auto new_parts = [&] {
                vector<felt_t> parts(shape.label_size);
                for (auto &part : parts) {
                    part = (uniform(4) == 0) ? 0 : 1 + uniform(mod - 1);
                }
                return parts;
            };

            uint64_t next_id = 1;
            auto tagged_item = [&](const vector<felt_t> &felts, HashedItem id) {
                TaggedAlgItemLabel item;
                item.item = id;
                for (felt_t felt : felts) {
                    item.alg_item_label.emplace_back(felt, new_parts());
                }
                return item;
            };

            auto labeled_item = [&](const vector<felt_t> &felts) {
                AlgItemLabel item;
                for (felt_t felt : felts) {
                    item.emplace_back(felt, new_parts());
                }
                return item;
            };

            BinBundle bb = make_bundle(context, shape);
            RegenLog log;

            // The locations that have held items, and the stored item at a given place
            set<size_t> used_locations(hot_locations.begin(), hot_locations.end());

            auto stored_felts = [&](size_t start, size_t pos) {
                vector<felt_t> felts;
                for (size_t s = 0; s < f; s++) {
                    felts.push_back(bb.get_item_bins()[start + s][pos]);
                }
                return felts;
            };

            auto pick_stored = [&](size_t &start, size_t &pos) {
                vector<size_t> starts;
                for (size_t location : used_locations) {
                    if (!bb.get_item_bins()[location * f].empty()) {
                        starts.push_back(location * f);
                    }
                }
                if (starts.empty()) {
                    return false;
                }
                start = starts[uniform(starts.size())];
                pos = uniform(bb.get_item_bins()[start].size());
                return true;
            };

            auto pick_start = [&] {
                size_t location = (uniform(100) < 85) ? hot_locations[uniform(hot_locations.size())]
                                                      : uniform(location_count);
                used_locations.insert(location);
                return location * f;
            };

            // What the sequence has covered, counted where the cache is regenerated
            size_t incremental_count = 0;
            size_t full_count = 0;
            size_t grew_count = 0;
            size_t shrank_count = 0;
            size_t filled_count = 0;
            size_t emptied_count = 0;
            size_t last_max_size = 0;
            vector<bool> last_nonempty(num_bins, false);

            auto regen_and_check = [&] {
                // The cache is invalid exactly when some bin is dirty, and regenerating it
                // computes the polynomials of the dirty bins and of no other
                bool invalid = bb.cache_invalid();
                size_t dirty_count = dirty_bins_of(bb).size();
                ASSERT_EQ(invalid, dirty_count > 0);
                ASSERT_EQ(
                    invalid ? vector<size_t>{ dirty_count } : vector<size_t>{}, log.regen(bb));
                if (invalid) {
                    ((dirty_count < num_bins) ? incremental_count : full_count)++;
                }

                ASSERT_NO_FATAL_FAILURE(check_cache_as_from_scratch(bb, context, shape));

                size_t max_size = 0;
                for (size_t bin = 0; bin < num_bins; bin++) {
                    bool nonempty = !bb.get_item_bins()[bin].empty();
                    filled_count += (nonempty && !last_nonempty[bin]) ? 1 : 0;
                    emptied_count += (!nonempty && last_nonempty[bin]) ? 1 : 0;
                    last_nonempty[bin] = nonempty;
                    max_size = max(max_size, bb.get_item_bins()[bin].size());
                }
                grew_count += (max_size > last_max_size) ? 1 : 0;
                shrank_count += (max_size < last_max_size) ? 1 : 0;
                last_max_size = max_size;
            };

            // Saves and loads the BinBundle, with the cache if it is valid
            auto save_and_load = [&] {
                bool with_cache = !bb.cache_invalid();
                BinBundle loaded = make_bundle(context, shape);
                load_from_string(loaded, save_to_string(bb));
                ASSERT_EQ(with_cache, !loaded.cache_invalid());
                ASSERT_EQ(
                    with_cache ? vector<size_t>{} : bin_range(0, num_bins), dirty_bins_of(loaded));
                bb = std::move(loaded);
            };

            // Operations that fail, and dry runs, which change nothing
            auto fail = [&](const BundleState &before) {
                size_t start = pick_start();
                switch (uniform(4)) {
                case 0:
                    if (tagged) {
                        ASSERT_LE(
                            -1,
                            bb.multi_insert_dry_run(
                                tagged_item(new_felts(), HashedItem(next_id, 0)), start));
                    } else if (labeled) {
                        ASSERT_LE(-1, bb.multi_insert_dry_run(labeled_item(new_felts()), start));
                    } else {
                        ASSERT_LT(0, bb.multi_insert_dry_run(new_felts(), start));
                    }
                    break;

                case 1: {
                    // Field elements that are never inserted
                    vector<felt_t> absent(f, felt_range + 1);
                    if (tagged) {
                        ASSERT_FALSE(bb.try_multi_remove(absent, HashedItem(0, 0), start));
                        ASSERT_FALSE(
                            bb.try_multi_overwrite(tagged_item(absent, HashedItem(0, 0)), start));
                    } else {
                        ASSERT_FALSE(bb.try_multi_remove(absent, start));
                        if (labeled) {
                            ASSERT_FALSE(bb.try_multi_overwrite(labeled_item(absent), start));
                        } else {
                            ASSERT_FALSE(bb.try_multi_overwrite(absent, start));
                        }
                    }
                    break;
                }

                case 2:
                    // Where the item does not fit
                    if (tagged) {
                        ASSERT_EQ(
                            -1,
                            bb.multi_insert_for_real(
                                tagged_item(new_felts(), HashedItem(next_id, 0)),
                                num_bins - f + 1));
                    } else if (labeled) {
                        ASSERT_EQ(
                            -1,
                            bb.multi_insert_for_real(labeled_item(new_felts()), num_bins - f + 1));
                    } else {
                        ASSERT_EQ(-1, bb.multi_insert_for_real(new_felts(), num_bins - f + 1));
                    }
                    break;

                default: {
                    // An item whose field element is already in its bin, which fails with labels
                    // or match tags, or the replacement of an item that is not where it is
                    // looked for
                    size_t pos = 0;
                    if (!pick_stored(start, pos)) {
                        break;
                    }

                    vector<felt_t> felts = stored_felts(start, pos);
                    if (tagged) {
                        ASSERT_EQ(
                            -1,
                            bb.multi_insert_for_real(
                                tagged_item(felts, HashedItem(next_id, 0)), start));
                        TaggedAlgItemLabel item = tagged_item(new_felts(), HashedItem(next_id, 0));
                        ASSERT_FALSE(
                            bb.try_multi_replace(HashedItem(0, 0), pos, item, start, false));
                        ASSERT_FALSE(bb.try_multi_replace(
                            bb.get_hashed_item_bins()[start][pos],
                            bb.get_item_bins()[start].size(),
                            item,
                            start,
                            false));
                    } else if (labeled) {
                        ASSERT_EQ(-1, bb.multi_insert_for_real(labeled_item(felts), start));
                    }
                    break;
                }
                }

                ASSERT_NO_FATAL_FAILURE(check_marked(before, bb, false, 0, 0));
            };

            // Inserts a new item where it fits, as a SenderDB would, which can fail
            auto insert = [&](const BundleState &before) {
                size_t start = pick_start();
                bool inserted = false;
                if (tagged) {
                    TaggedAlgItemLabel item = tagged_item(new_felts(), HashedItem(next_id, 0));
                    int32_t size = bb.multi_insert_dry_run(item, start);
                    if ((size > 0) && (static_cast<size_t>(size) <= bin_capacity)) {
                        ASSERT_EQ(size, bb.multi_insert_for_real(item, start));
                        next_id++;
                        inserted = true;
                    }
                } else if (labeled) {
                    AlgItemLabel item = labeled_item(new_felts());
                    int32_t size = bb.multi_insert_dry_run(item, start);
                    if ((size > 0) && (static_cast<size_t>(size) <= bin_capacity)) {
                        ASSERT_EQ(size, bb.multi_insert_for_real(item, start));
                        inserted = true;
                    }
                } else {
                    vector<felt_t> item = new_felts();
                    int32_t size = bb.multi_insert_dry_run(item, start);
                    if ((size > 0) && (static_cast<size_t>(size) <= bin_capacity)) {
                        ASSERT_EQ(size, bb.multi_insert_for_real(item, start));
                        inserted = true;
                    }
                }

                ASSERT_NO_FATAL_FAILURE(check_marked(before, bb, inserted, start, f));
            };

            // Changes the stored item at the given place: its label parts, or, with match tags,
            // replaces it with another item, which can fail. Without labels, an overwrite changes
            // nothing but marks every bin.
            auto change = [&](const BundleState &before, size_t start, size_t pos) {
                vector<felt_t> felts = stored_felts(start, pos);
                if (tagged) {
                    HashedItem id = bb.get_hashed_item_bins()[start][pos];
                    if (uniform(2)) {
                        ASSERT_TRUE(bb.try_multi_overwrite(tagged_item(felts, id), start));
                        ASSERT_NO_FATAL_FAILURE(check_marked(before, bb, true, start, f));
                        return;
                    }

                    // A new item, or the same item with new label parts
                    TaggedAlgItemLabel item =
                        uniform(4) ? tagged_item(new_felts(), HashedItem(next_id++, 0))
                                   : tagged_item(felts, id);
                    bool replaceable = bb.try_multi_replace(id, pos, item, start, true);
                    ASSERT_NO_FATAL_FAILURE(check_marked(before, bb, false, 0, 0));
                    ASSERT_EQ(replaceable, bb.try_multi_replace(id, pos, item, start, false));
                    ASSERT_NO_FATAL_FAILURE(check_marked(before, bb, replaceable, start, f));
                } else if (labeled) {
                    ASSERT_TRUE(bb.try_multi_overwrite(labeled_item(felts), start));
                    ASSERT_NO_FATAL_FAILURE(check_marked(before, bb, true, start, f));
                } else if (uniform(4) == 0) {
                    ASSERT_TRUE(bb.try_multi_overwrite(felts, start));
                    ASSERT_NO_FATAL_FAILURE(check_marked(before, bb, true, 0, num_bins));
                }
            };

            // Removes the stored item at the given place
            auto remove = [&](const BundleState &before, size_t start, size_t pos) {
                vector<felt_t> felts = stored_felts(start, pos);
                if (tagged) {
                    ASSERT_TRUE(
                        bb.try_multi_remove(felts, bb.get_hashed_item_bins()[start][pos], start));
                } else {
                    ASSERT_TRUE(bb.try_multi_remove(felts, start));
                }

                ASSERT_NO_FATAL_FAILURE(check_marked(before, bb, true, start, f));
            };

            for (size_t step = 0; step < steps; step++) {
                // Out of 100: saving and loading, clearing the cache, operations that fail, and
                // by phase, insertions and changes, the rest being removals
                static const array<array<uint64_t, 2>, 3> weights{
                    { { 60, 20 }, { 35, 25 }, { 5, 15 } }
                };
                const auto &w = weights[(step / 40) % 3];
                uint64_t roll = uniform(100);
                BundleState before(bb);

                if (roll < 3) {
                    ASSERT_NO_FATAL_FAILURE(save_and_load());
                } else if (roll < 5) {
                    bb.clear_cache();
                    ASSERT_EQ(bin_range(0, num_bins), dirty_bins_of(bb));
                } else if (roll < 15) {
                    ASSERT_NO_FATAL_FAILURE(fail(before));
                } else if (roll < 15 + w[0]) {
                    ASSERT_NO_FATAL_FAILURE(insert(before));
                } else {
                    // A change or a removal, of a stored item if there is one
                    size_t start = 0;
                    size_t pos = 0;
                    if (!pick_stored(start, pos)) {
                        continue;
                    }

                    if (roll < 15 + w[0] + w[1]) {
                        ASSERT_NO_FATAL_FAILURE(change(before, start, pos));
                    } else {
                        ASSERT_NO_FATAL_FAILURE(remove(before, start, pos));
                    }
                }

                if (uniform(3) == 0) {
                    ASSERT_NO_FATAL_FAILURE(regen_and_check());
                }
            }

            ASSERT_NO_FATAL_FAILURE(regen_and_check());
            ASSERT_TRUE(log.cache_warnings().empty());

            // The sequence regenerated the cache both ways, saw bins fill and empty, and saw the
            // largest bin, which decides how many plaintexts there are, grow and shrink
            ASSERT_LT(0, incremental_count);
            ASSERT_LT(0, full_count);
            ASSERT_LT(0, filled_count);
            ASSERT_LT(0, emptied_count);
            ASSERT_LT(0, grew_count);
            ASSERT_LT(0, shrank_count);

            // A change, and then stripping, which regenerates the cache first, gives what
            // stripping a BinBundle that generated its cache from nothing gives
            size_t start = hot_locations[0] * f;
            BundleState before(bb);
            bool changed = false;
            size_t pos = 0;
            if (pick_stored(start, pos)) {
                vector<felt_t> felts = stored_felts(start, pos);
                changed =
                    tagged
                        ? bb.try_multi_remove(felts, bb.get_hashed_item_bins()[start][pos], start)
                        : bb.try_multi_remove(felts, start);
            }
            ASSERT_NO_FATAL_FAILURE(check_marked(before, bb, changed, start, f));
            BinBundle scratch = make_bundle(context, shape);
            load_from_string(scratch, save_to_string(bb));
            scratch.clear_cache();
            scratch.strip();
            bb.strip();
            ASSERT_EQ(bin_range(0, num_bins), dirty_bins_of(bb));
            ASSERT_TRUE(save_to_string(scratch) == save_to_string(bb))
                << "the saved stripped BinBundles differ";
        }
    } // namespace

    TEST(BinBundleTests, ChangesMarkTheBinsTheyChange)
    {
        // A change to a BinBundle marks the bins it changes, and regenerating the cache then
        // computes the polynomials of those bins only. A dry run, or a change that fails, marks
        // nothing. Items here have two field elements, so each takes two bins.
        PSIParams params = make_tag_params(1);
        CryptoContext context(params);
        context.set_evaluator();
        size_t num_bins = params.bins_per_bundle();
        BundleShape shape{ 2, 0, 2, tag_max_bin_size, 0, num_bins, true };
        BinBundle bb = make_bundle(context, shape);
        RegenLog log;

        // A new BinBundle holds no polynomials, so every bin is dirty
        ASSERT_EQ(bin_range(0, num_bins), dirty_bins_of(bb));
        ASSERT_EQ(vector<size_t>{ num_bins }, log.regen(bb));
        ASSERT_TRUE(dirty_bins_of(bb).empty());

        AlgItemLabel a{ { 5, { 1, 2 } }, { 6, { 3, 4 } } };
        AlgItemLabel b{ { 7, { 5, 6 } }, { 8, { 7, 8 } } };
        ASSERT_EQ(1, bb.multi_insert_dry_run(a, 4));
        ASSERT_TRUE(dirty_bins_of(bb).empty());
        ASSERT_EQ(1, bb.multi_insert_for_real(a, 4));
        ASSERT_EQ(bin_range(4, 2), dirty_bins_of(bb));
        ASSERT_EQ(1, bb.multi_insert_for_real(b, 10));
        ASSERT_EQ((vector<size_t>{ 4, 5, 10, 11 }), dirty_bins_of(bb));
        ASSERT_EQ(vector<size_t>{ 4 }, log.regen(bb));
        ASSERT_TRUE(dirty_bins_of(bb).empty());
        ASSERT_NO_FATAL_FAILURE(check_cache_as_from_scratch(bb, context, shape));

        // Changes that fail mark nothing
        ASSERT_EQ(-1, bb.multi_insert_for_real(a, 4));
        ASSERT_EQ(-1, bb.multi_insert_for_real(a, num_bins - 1));
        ASSERT_FALSE(bb.try_multi_overwrite(AlgItemLabel{ { 9, { 0, 0 } }, { 9, { 0, 0 } } }, 4));
        ASSERT_FALSE(bb.try_multi_remove({ 5, 9 }, 4));
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_TRUE(dirty_bins_of(bb).empty());

        // Overwriting and removing mark the item's bins
        ASSERT_TRUE(bb.try_multi_overwrite(AlgItemLabel{ { 7, { 9, 9 } }, { 8, { 9, 9 } } }, 10));
        ASSERT_EQ(bin_range(10, 2), dirty_bins_of(bb));
        ASSERT_EQ(vector<size_t>{ 2 }, log.regen(bb));
        ASSERT_NO_FATAL_FAILURE(check_cache_as_from_scratch(bb, context, shape));
        ASSERT_TRUE(bb.try_multi_remove({ 5, 6 }, 4));
        ASSERT_EQ(bin_range(4, 2), dirty_bins_of(bb));
        ASSERT_EQ(vector<size_t>{ 2 }, log.regen(bb));
        ASSERT_NO_FATAL_FAILURE(check_cache_as_from_scratch(bb, context, shape));

        // A BinBundle loaded with its cache keeps the polynomials of its bins; one loaded without
        // it, or whose cache is cleared, has none, and every bin is dirty
        BinBundle loaded = make_bundle(context, shape);
        load_from_string(loaded, save_to_string(bb));
        ASSERT_FALSE(loaded.cache_invalid());
        ASSERT_TRUE(dirty_bins_of(loaded).empty());
        ASSERT_EQ(1, loaded.multi_insert_for_real(a, 20));
        ASSERT_EQ(bin_range(20, 2), dirty_bins_of(loaded));
        ASSERT_EQ(vector<size_t>{ 2 }, log.regen(loaded));
        ASSERT_NO_FATAL_FAILURE(check_cache_as_from_scratch(loaded, context, shape));
        ASSERT_EQ(1, bb.multi_insert_for_real(a, 30));
        load_from_string(loaded, save_to_string(bb));
        ASSERT_TRUE(loaded.cache_invalid());
        ASSERT_EQ(bin_range(0, num_bins), dirty_bins_of(loaded));
        ASSERT_EQ(vector<size_t>{ 2 }, log.regen(bb));
        bb.clear_cache();
        ASSERT_EQ(bin_range(0, num_bins), dirty_bins_of(bb));
        ASSERT_EQ(vector<size_t>{ num_bins }, log.regen(bb));
        ASSERT_NO_FATAL_FAILURE(check_cache_as_from_scratch(bb, context, shape));

        // A stripped BinBundle holds no polynomials either
        bb.strip();
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_EQ(bin_range(0, num_bins), dirty_bins_of(bb));
        ASSERT_TRUE(log.cache_warnings().empty());

        // Without labels, an overwrite changes nothing, but marks every bin, so that the whole
        // cache is generated again, as in APSI 1.x
        BinBundle unlabeled =
            make_bundle(context, { 0, 0, 2, tag_max_bin_size, 0, num_bins, true });
        ASSERT_EQ(1, unlabeled.multi_insert_for_real(vector<felt_t>{ 5, 6 }, 4));
        ASSERT_EQ(vector<size_t>{ num_bins }, log.regen(unlabeled));
        ASSERT_FALSE(unlabeled.try_multi_overwrite(vector<felt_t>{ 5, 7 }, 4));
        ASSERT_TRUE(dirty_bins_of(unlabeled).empty());
        ASSERT_TRUE(unlabeled.try_multi_overwrite(vector<felt_t>{ 5, 6 }, 4));
        ASSERT_EQ(bin_range(0, num_bins), dirty_bins_of(unlabeled));
        ASSERT_EQ(vector<size_t>{ num_bins }, log.regen(unlabeled));
        ASSERT_NO_FATAL_FAILURE(check_cache_as_from_scratch(
            unlabeled, context, { 0, 0, 2, tag_max_bin_size, 0, num_bins, true }));
    }

    TEST(BinBundleTagTests, ChangesMarkTheBinsTheyChange)
    {
        // As without match tags, and replacing an item marks its bins as well. Items here have
        // two field elements.
        PSIParams params = make_tag_params(2);
        CryptoContext context(params);
        context.set_evaluator();
        size_t num_bins = params.bins_per_bundle();
        size_t label_size = tag_part_count + 1;
        BundleShape shape{ label_size, tag_part_count, 2, tag_max_bin_size, 0, num_bins, true };
        BinBundle bb = make_bundle(context, shape);
        RegenLog log;

        ASSERT_EQ(bin_range(0, num_bins), dirty_bins_of(bb));
        ASSERT_EQ(vector<size_t>{ num_bins }, log.regen(bb));

        TaggedAlgItemLabel a = make_tagged_item(1, { 5, 6 }, label_size, 100);
        TaggedAlgItemLabel b = make_tagged_item(2, { 7, 8 }, label_size, 200);
        TaggedAlgItemLabel c = make_tagged_item(3, { 9, 10 }, label_size, 300);
        ASSERT_EQ(1, bb.multi_insert_dry_run(a, 4));
        ASSERT_TRUE(dirty_bins_of(bb).empty());
        ASSERT_EQ(1, bb.multi_insert_for_real(a, 4));
        ASSERT_EQ(1, bb.multi_insert_for_real(b, 10));
        ASSERT_EQ((vector<size_t>{ 4, 5, 10, 11 }), dirty_bins_of(bb));
        ASSERT_EQ(vector<size_t>{ 4 }, log.regen(bb));
        ASSERT_NO_FATAL_FAILURE(check_cache_as_from_scratch(bb, context, shape));

        // Changes that fail, and dry runs, mark nothing
        HashedItem stranger(9, 9);
        ASSERT_EQ(-1, bb.multi_insert_for_real(make_tagged_item(4, { 5, 1 }, label_size, 0), 4));
        ASSERT_FALSE(bb.try_multi_overwrite(make_tagged_item(9, { 5, 6 }, label_size, 0), 4));
        ASSERT_FALSE(bb.try_multi_remove({ 5, 6 }, stranger, 4));
        ASSERT_FALSE(bb.try_multi_replace(stranger, 0, c, 4, false));
        ASSERT_FALSE(bb.try_multi_replace(a.item, 1, c, 4, false));
        ASSERT_FALSE(bb.try_multi_replace(a.item, 0, c, 10, false));
        ASSERT_TRUE(bb.try_multi_replace(a.item, 0, c, 4, true));
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_TRUE(dirty_bins_of(bb).empty());

        // Overwriting, replacing and removing mark the item's bins
        ASSERT_TRUE(bb.try_multi_overwrite(make_tagged_item(1, { 5, 6 }, label_size, 900), 4));
        ASSERT_EQ(bin_range(4, 2), dirty_bins_of(bb));
        ASSERT_EQ(vector<size_t>{ 2 }, log.regen(bb));
        ASSERT_NO_FATAL_FAILURE(check_cache_as_from_scratch(bb, context, shape));
        ASSERT_TRUE(bb.try_multi_replace(a.item, 0, c, 4, false));
        ASSERT_EQ(bin_range(4, 2), dirty_bins_of(bb));
        ASSERT_EQ(vector<size_t>{ 2 }, log.regen(bb));
        ASSERT_NO_FATAL_FAILURE(check_cache_as_from_scratch(bb, context, shape));
        ASSERT_TRUE(bb.try_multi_remove({ 7, 8 }, b.item, 10));
        ASSERT_EQ(bin_range(10, 2), dirty_bins_of(bb));
        ASSERT_EQ(vector<size_t>{ 2 }, log.regen(bb));
        ASSERT_NO_FATAL_FAILURE(check_cache_as_from_scratch(bb, context, shape));

        // Loading, clearing and stripping, as without match tags
        BinBundle loaded = make_bundle(context, shape);
        load_from_string(loaded, save_to_string(bb));
        ASSERT_TRUE(dirty_bins_of(loaded).empty());
        ASSERT_EQ(1, loaded.multi_insert_for_real(b, 20));
        ASSERT_EQ(bin_range(20, 2), dirty_bins_of(loaded));
        ASSERT_EQ(vector<size_t>{ 2 }, log.regen(loaded));
        ASSERT_NO_FATAL_FAILURE(check_cache_as_from_scratch(loaded, context, shape));
        ASSERT_EQ(1, bb.multi_insert_for_real(b, 30));
        load_from_string(loaded, save_to_string(bb));
        ASSERT_EQ(bin_range(0, num_bins), dirty_bins_of(loaded));
        bb.clear_cache();
        ASSERT_EQ(bin_range(0, num_bins), dirty_bins_of(bb));
        ASSERT_EQ(vector<size_t>{ num_bins }, log.computed_while([&] { bb.strip(); }));
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_EQ(bin_range(0, num_bins), dirty_bins_of(bb));
        ASSERT_TRUE(log.cache_warnings().empty());
    }

    TEST(BinBundleTests, PolynomialsThatDoNotFitTheirBinsAreComputedAgain)
    {
        // A loaded BinBundle keeps the polynomials it was saved with, which are trusted as the rest
        // of a saved SenderDB is. Should a bin that has not changed have a matching polynomial
        // without one more coefficient than the bin has items, regenerating the cache computes the
        // polynomials of every bin again, with a warning, rather than keep any. The data here has
        // a matching polynomial, and without match tags label polynomials, one coefficient short
        // in bin 0, which loading cannot tell from right; bin 1 holds as many items, so that the
        // number of plaintexts still fits them.
        PSIParams params = make_tag_params(1);
        CryptoContext context(params);
        context.set_evaluator();
        size_t num_bins = params.bins_per_bundle();

        for (size_t label_size : { 0U, 1U }) {
            BundleShape shape{ label_size, 0, 1, tag_max_bin_size, 0, num_bins, true };
            auto insert = [&](BinBundle &bb, felt_t x, size_t bin) {
                if (label_size) {
                    return bb.multi_insert_for_real(AlgItemLabel{ { x, { x + 10 } } }, bin);
                }
                return bb.multi_insert_for_real(vector<felt_t>{ x }, bin);
            };
            BinBundle bb = make_bundle(context, shape);
            for (felt_t x : { 5U, 6U, 7U }) {
                ASSERT_LT(0, insert(bb, x, 0));
                ASSERT_LT(0, insert(bb, x, 1));
            }
            bb.regen_cache();
            BinBundleChanges c;
            c.shorten_first_matching_polyn = true;
            c.shorten_first_felt_interp_polyn = true;
            string bytes = rebuild_bin_bundle(save_to_string(bb), c);

            RegenLog log;
            for (size_t changed_bin : { 0U, 2U }) {
                BinBundle loaded = make_bundle(context, shape);
                load_from_string(loaded, bytes);
                ASSERT_TRUE(dirty_bins_of(loaded).empty());
                ASSERT_EQ(3, loaded.get_cache().felt_matching_polyns[0].size());
                ASSERT_LT(0, insert(loaded, 8, changed_bin));

                // Once bin 0 has changed, its polynomials are computed again anyway
                if (changed_bin == 0) {
                    ASSERT_EQ(vector<size_t>{ 1 }, log.regen(loaded));
                    ASSERT_TRUE(log.cache_warnings().empty());
                } else {
                    ASSERT_EQ(vector<size_t>{ num_bins }, log.regen(loaded));
                    ASSERT_EQ(1, log.cache_warnings().size());
                }
                ASSERT_NO_FATAL_FAILURE(check_cache_as_from_scratch(loaded, context, shape));
            }
        }
    }

    TEST(BinBundleTests, RegeneratingAfterChangesGivesTheCacheFromScratch)
    {
        // Without match tags, labeled and not, with items of one and of three field elements,
        // compressed, or uncompressed and with Paterson-Stockmeyer. The BinBundles have 256 bins,
        // fewer than the plaintexts have slots, which are padded with zeros, so that they cost
        // less to generate from nothing after every few changes. For the same reason the
        // plaintexts have 2048 slots, modulo a single prime: every regeneration makes all of
        // them, and nothing else a BinBundle does depends on their size. Each sequence of
        // changes goes twice through the phases that favor insertions, changes and removals.
        PSIParams params = make_tag_params(1, 2048);
        CryptoContext context(params);
        context.set_evaluator();

        uint64_t seed = 1;
        for (size_t label_size : { 0U, 2U }) {
            for (size_t felts_per_item : { 1U, 3U }) {
                for (bool compressed : { true, false }) {
                    BundleShape shape{ label_size,           0,   felts_per_item, tag_max_bin_size,
                                       compressed ? 0U : 3U, 256, compressed };
                    SCOPED_TRACE(
                        "label_size " + to_string(label_size) + ", felts_per_item " +
                        to_string(felts_per_item) + ", compressed " + to_string(compressed));
                    ASSERT_NO_FATAL_FAILURE(run_random_changes(context, shape, seed++, 240));
                }
            }
        }
    }

    TEST(BinBundleTagTests, RegeneratingAfterChangesGivesTheCacheFromScratch)
    {
        // With match tags, labeled and not, with items of one and of two field elements,
        // compressed, or uncompressed and with Paterson-Stockmeyer, in 256 bins and with
        // plaintexts of 2048 slots, as without match tags
        PSIParams params = make_tag_params(1, 2048);
        CryptoContext context(params);
        context.set_evaluator();

        uint64_t seed = 100;
        for (size_t label_size : { tag_part_count, tag_part_count + 2 }) {
            for (size_t felts_per_item : { 1U, 2U }) {
                for (bool compressed : { true, false }) {
                    BundleShape shape{ label_size,       tag_part_count,       felts_per_item,
                                       tag_max_bin_size, compressed ? 0U : 3U, 256,
                                       compressed };
                    SCOPED_TRACE(
                        "label_size " + to_string(label_size) + ", felts_per_item " +
                        to_string(felts_per_item) + ", compressed " + to_string(compressed));
                    ASSERT_NO_FATAL_FAILURE(run_random_changes(context, shape, seed++, 240));
                }
            }
        }
    }
} // namespace APSITests
