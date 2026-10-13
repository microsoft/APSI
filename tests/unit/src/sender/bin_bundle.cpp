// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// APSI
#include "apsi/bin_bundle.h"
#include "apsi/bin_bundle_generated.h"
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

            bool drop_last_interp_polyns = false;

            bool shorten_first_felt_interp_polyn = false;

            bool empty_first_batched_interp_polyn = false;

            bool shorten_last_batched_interp_polyn = false;
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
                    felt_matching = copy_felt_matrix(builder, c.felt_matching_polyns());
                    batched_matching = copy_batched_polyn(builder, *c.batched_matching_polyn());
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
                    felt_interp.push_back(copy_felt_matrix(
                        builder,
                        c.felt_interp_polyns()->Get(static_cast<flatbuffers::uoffset_t>(i)),
                        changes.shorten_first_felt_interp_polyn && (i == 0)));
                }
                auto felt_interp_vec = builder.CreateVector(felt_interp);

                vector<flatbuffers::Offset<fbs::BatchedPlaintextPolyn>> batched_interp;
                for (size_t i = 0; i < interp_count; i++) {
                    const auto &polyn =
                        *c.batched_interp_polyns()->Get(static_cast<flatbuffers::uoffset_t>(i));
                    size_t drop_count = 0;
                    if (changes.empty_first_batched_interp_polyn && (i == 0)) {
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

        // Nothing changes a stripped BinBundle
        ASSERT_LT(0, tagged.multi_insert_for_real(item, 0));
        tagged.strip();
        ASSERT_THROW(tagged.multi_insert_for_real(item, 1), logic_error);
        ASSERT_THROW(tagged.try_multi_overwrite(item, 0), logic_error);
        ASSERT_THROW(static_cast<void>(tagged.multi_contains(item, 0)), logic_error);
        ASSERT_THROW(tagged.try_multi_remove(felts, item.item, 0), logic_error);
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
} // namespace APSITests
