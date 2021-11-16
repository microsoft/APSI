// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <memory>
#include <numeric>
#include <sstream>
#include <utility>
#include <vector>

// APSI
#include "apsi/bin_bundle.h"

// SEAL
#include "seal/keygenerator.h"

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
        auto test_fun = [](shared_ptr<PSIParams> params) {
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
        auto test_fun = [](shared_ptr<PSIParams> params) {
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
            auto sk = keygen.secret_key();
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
        auto test_fun = [](shared_ptr<PSIParams> params) {
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
            ASSERT_THROW(bb.get_cache(), logic_error);

            bb.regen_cache();
            auto &cache = bb.get_cache();

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
        auto test_fun = [&](shared_ptr<PSIParams> params, size_t label_size) {
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
            ASSERT_THROW(bb.get_cache(), logic_error);

            bb.regen_cache();
            auto &cache = bb.get_cache();

            ASSERT_TRUE(cache.batched_matching_polyn);
            ASSERT_EQ(label_size, cache.batched_interp_polyns.size());

            for (auto &bip : cache.batched_interp_polyns) {
                // Nothing has been inserted yet; we have a constant interpolation polynomial
                ASSERT_EQ(1, bip.batched_coeffs.size());
            }

            for (auto &fip : cache.felt_interp_polyns) {
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
        auto test_fun = [](shared_ptr<PSIParams> params) {
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
        auto test_fun = [&](shared_ptr<PSIParams> params, size_t label_size) {
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
            values.push_back(make_pair(1, vector<felt_t>{}));
            ASSERT_THROW(res = bb.multi_insert_dry_run(values, 0), invalid_argument);
            values.pop_back();

            // Attempt to insert wrong size label
            values.push_back(make_pair(1, create_label(label_size + 1, 1)));
            ASSERT_THROW(res = bb.multi_insert_dry_run(values, 0), invalid_argument);
            values.pop_back();

            values.push_back(make_pair(1, create_label(label_size, 1)));
            res = bb.multi_insert_dry_run(values, 0);
            ASSERT_EQ(1 /* largest bin size after insert */, res);
            ASSERT_FALSE(bb.cache_invalid());
            ASSERT_TRUE(bb.empty());

            values.push_back(make_pair(2, create_label(label_size, 2)));
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
            values.push_back(make_pair(1, create_label(label_size, 1)));

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
            values.push_back(make_pair(1, create_label(label_size, 1)));
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
            values.push_back(make_pair(2, create_label(label_size, 7)));
            values.push_back(make_pair(3, create_label(label_size, 8)));
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
        auto test_fun = [&](shared_ptr<PSIParams> params, size_t label_size) {
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
            values = { make_pair(1, create_label(label_size, 1)),
                       make_pair(2, create_label(label_size, 2)),
                       make_pair(3, create_label(label_size, 3)) };
            bb.clear();
            res = bb.multi_insert_for_real(values, 0);
            values = { make_pair(4, create_label(label_size, 4)),
                       make_pair(5, create_label(label_size, 5)),
                       make_pair(6, create_label(label_size, 6)) };
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
            values = { make_pair(1, create_label(label_size, 1)),
                       make_pair(4, create_label(label_size, 4)),
                       make_pair(3, create_label(label_size, 3)) };
            bres = bb.try_multi_overwrite(values, 0);
            ASSERT_FALSE(bres);

            // Overwriting labels
            values = { make_pair(1, create_label(label_size, 6)),
                       make_pair(5, create_label(label_size, 7)),
                       make_pair(3, create_label(label_size, 8)) };
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
        auto test_fun = [](shared_ptr<PSIParams> params) {
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
        auto test_fun = [](shared_ptr<PSIParams> params) {
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
        auto test_fun = [&](shared_ptr<PSIParams> params, size_t label_size) {
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
                AlgItemLabel{ make_pair(2, create_label(label_size, 3)),
                              make_pair(3, create_label(label_size, 4)) },
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
        auto test_fun = [](shared_ptr<PSIParams> params) {
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
        auto test_fun = [](shared_ptr<PSIParams> params) {
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
} // namespace APSITests
