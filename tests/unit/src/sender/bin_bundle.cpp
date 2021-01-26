// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <memory>
#include <sstream>
#include <utility>
#include <vector>

// APSI
#include "apsi/bin_bundle.h"

// SEAL
#include "seal/keygenerator.h"

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

        template <typename L>
        auto find_in_bin(const vector<pair<felt_t, L>> &bin, const felt_t &element)
        {
            auto result =
                std::find_if(bin.begin(), bin.end(), [&element](const pair<felt_t, L> &elem) {
                    return elem.first == element;
                });

            return result;
        }
    }

    TEST(BinBundleTests, BatchedPlaintextPolynCreate)
    {
        CryptoContext context(*get_params());
        context.set_evaluator();

        BatchedPlaintextPolyn bpp(context);
        ASSERT_FALSE(bpp);

        vector<FEltPolyn> polyns;
        bpp = BatchedPlaintextPolyn(polyns, context, true);
        ASSERT_TRUE(bpp);

        polyns.push_back({ 1, 2, 3 });
        polyns.push_back({ 1, 2 });
        polyns.push_back({ 3 });
        polyns.push_back({ 1, 2, 3, 4, 5 });
        bpp = BatchedPlaintextPolyn(polyns, context, true);
        ASSERT_TRUE(bpp);
    }

    TEST(BinBundleTests, BatchedPlaintextPolynEval)
    {
        CryptoContext context(*get_params());
        context.set_evaluator();

        vector<FEltPolyn> polyns;
        polyns.push_back({ 1, 2, 3 });
        polyns.push_back({ 1, 2 });
        polyns.push_back({ 3 });
        polyns.push_back({ 1, 2, 3, 4, 5 });
        BatchedPlaintextPolyn bpp(polyns, context, true);
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

        vector<Ciphertext> ct_zeros_vec(5, zeros_ct);
        Ciphertext ct_eval = bpp.eval(ct_zeros_vec);
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
        ct_eval = bpp.eval(ct_ones_vec);
        Plaintext ones_pt2;
        context.decryptor()->decrypt(ct_eval, ones_pt2);
        context.encoder()->decode(ones_pt2, result);
        ASSERT_EQ(6, result[0]);
        ASSERT_EQ(3, result[1]);
        ASSERT_EQ(3, result[2]);
        ASSERT_EQ(15, result[3]);
        ASSERT_TRUE(all_of(result.begin() + 4, result.end(), [](auto a) { return a == 0; }));
    }

    TEST(BinBundleTests, BinBundleUnlabeledCreate)
    {
        CryptoContext context(*get_params());

        // No evaluator set in context
        ASSERT_THROW(BinBundle<monostate> bb(context, true, 50), invalid_argument);

        context.set_evaluator();
        BinBundle<monostate> bb(context, true, 50);

        ASSERT_TRUE(bb.cache_invalid());
        bb.clear_cache();
        ASSERT_TRUE(bb.cache_invalid());

        // The cache is stale; cannot get it
        ASSERT_THROW(auto &cache = bb.get_cache(), logic_error);

        bb.regen_cache();
        auto &cache = bb.get_cache();

        // The matching polynomial is set to a single constant zero polynomial since we haven't inserted anything
        ASSERT_EQ(
            context.seal_context()->first_context_data()->parms().poly_modulus_degree(),
            cache.felt_matching_polyns.size());
        ASSERT_TRUE(cache.felt_interp_polyns.empty());
        ASSERT_TRUE(cache.batched_matching_polyn);
        ASSERT_FALSE(cache.batched_interp_polyn);
    }

    TEST(BinBundleTests, BinBundleLabeledCreate)
    {
        CryptoContext context(*get_params());

        // No evaluator set in context
        ASSERT_THROW(BinBundle<felt_t> bb(context, true, 50), invalid_argument);

        context.set_evaluator();
        BinBundle<felt_t> bb(context, true, 50);

        ASSERT_TRUE(bb.cache_invalid());
        bb.clear_cache();
        ASSERT_TRUE(bb.cache_invalid());

        // The cache is stale; cannot get it
        ASSERT_THROW(auto &cache = bb.get_cache(), logic_error);

        bb.regen_cache();
        auto &cache = bb.get_cache();

        // The matching polynomial is set to a single constant zero polynomial since we haven't inserted anything
        ASSERT_EQ(
            context.seal_context()->first_context_data()->parms().poly_modulus_degree(),
            cache.felt_matching_polyns.size());

        // The label polynomial is set to a single constant zero polynomial since we haven't inserted anything
        ASSERT_EQ(
            context.seal_context()->first_context_data()->parms().poly_modulus_degree(),
            cache.felt_interp_polyns.size());

        ASSERT_TRUE(cache.batched_matching_polyn);
        ASSERT_TRUE(cache.batched_interp_polyn);
    }

    TEST(BinBundleTests, BinBundleUnlabeledMultiInsert)
    {
        CryptoContext context(*get_params());
        context.set_evaluator();

        BinBundle<monostate> bb(context, true, 50);
        bb.regen_cache();
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_TRUE(bb.empty());

        vector<pair<felt_t, monostate>> values{ make_pair(1, monostate()) };
        int res = bb.multi_insert_dry_run(values, 0);
        ASSERT_EQ(1 /* largest bin size after insert */, res);
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_TRUE(bb.empty());

        values.push_back(make_pair(1, monostate()));
        res = bb.multi_insert_dry_run(values, 0);
        ASSERT_EQ(1 /* largest bin size after insert */, res);
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_TRUE(bb.empty());

        values.push_back(make_pair(2, monostate()));
        res = bb.multi_insert_dry_run(values, 0);
        ASSERT_EQ(1 /* largest bin size after insert */, res);
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_TRUE(bb.empty());

        values.resize(
            context.seal_context()->first_context_data()->parms().poly_modulus_degree(),
            make_pair(1, monostate()));
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
        values.push_back(make_pair(1, monostate()));

        // Now insert for real
        res = bb.multi_insert_for_real(values, 0);
        ASSERT_EQ(1 /* largest bin size after insert */, res);
        ASSERT_TRUE(bb.cache_invalid());
        bb.regen_cache();
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_FALSE(bb.empty());

        // Insert at index 1 so that we don't actually increase the max size
        values.push_back(make_pair(1, monostate()));
        res = bb.multi_insert_for_real(values, 1);
        ASSERT_EQ(1 /* largest bin size after insert */, res);
        ASSERT_TRUE(bb.cache_invalid());
        bb.regen_cache();
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_FALSE(bb.empty());

        // Insert at index 2; the value 1 will intersect with the current bin so will fail
        res = bb.multi_insert_for_real(values, 2);
        ASSERT_EQ(-1 /* largest bin size after insert */, res);
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_FALSE(bb.empty());

        values.clear();
        values.push_back(make_pair(2, monostate()));
        values.push_back(make_pair(3, monostate()));
        res = bb.multi_insert_for_real(values, 1);
        ASSERT_EQ(2 /* largest bin size after insert */, res);
        ASSERT_TRUE(bb.cache_invalid());
        bb.regen_cache();
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_FALSE(bb.empty());

        values.resize(
            context.seal_context()->first_context_data()->parms().poly_modulus_degree(),
            make_pair(4, monostate()));
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
    }

    TEST(BinBundleTests, BinBundleLabeledMultiInsert)
    {
        CryptoContext context(*get_params());
        context.set_evaluator();

        BinBundle<felt_t> bb(context, true, 50);
        bb.regen_cache();
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_TRUE(bb.empty());

        vector<pair<felt_t, felt_t>> values{ make_pair(1, 1) };
        int res = bb.multi_insert_dry_run(values, 0);
        ASSERT_EQ(1 /* largest bin size after insert */, res);
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_TRUE(bb.empty());

        // Nothing was inserted in the dry-run; verify that
        vector<felt_t> labels;
        bool bres = bb.try_get_multi_label({ 1 } , 0, labels);
        ASSERT_FALSE(bres);
        ASSERT_TRUE(labels.empty());

        values.push_back(make_pair(1, 1));
        res = bb.multi_insert_dry_run(values, 0);
        ASSERT_EQ(1 /* largest bin size after insert */, res);
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_TRUE(bb.empty());

        values.push_back(make_pair(2, 2));
        res = bb.multi_insert_dry_run(values, 0);
        ASSERT_EQ(1 /* largest bin size after insert */, res);
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_TRUE(bb.empty());

        values.resize(
            context.seal_context()->first_context_data()->parms().poly_modulus_degree(),
            make_pair(1, 1));
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
        values.push_back(make_pair(1, 1));

        // Now insert for real
        res = bb.multi_insert_for_real(values, 0);
        ASSERT_EQ(1 /* largest bin size after insert */, res);
        ASSERT_TRUE(bb.cache_invalid());
        bb.regen_cache();
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_FALSE(bb.empty());

        // Get the label
        bres = bb.try_get_multi_label({ 1 } , 0, labels);
        ASSERT_TRUE(bres);
        ASSERT_EQ(1, labels.size());
        ASSERT_EQ(1, labels[0]);

        // Try getting a label for wrong value
        bres = bb.try_get_multi_label({ 2 } , 0, labels);
        ASSERT_FALSE(bres);
        ASSERT_EQ(0, labels.size());

        // Insert at index 1 so that we don't actually increase the max size
        values.push_back(make_pair(1, 1));
        res = bb.multi_insert_for_real(values, 1);
        ASSERT_EQ(1 /* largest bin size after insert */, res);
        ASSERT_TRUE(bb.cache_invalid());
        bb.regen_cache();
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_FALSE(bb.empty());

        // Get the label
        bres = bb.try_get_multi_label({ 1, 1 } , 0, labels);
        ASSERT_TRUE(bres);
        ASSERT_EQ(2, labels.size());
        ASSERT_EQ(1, labels[0]);
        ASSERT_EQ(1, labels[1]);

        // Try getting a label for wrong value
        bres = bb.try_get_multi_label({ 0, 1 } , 0, labels);
        ASSERT_FALSE(bres);
        ASSERT_EQ(0, labels.size());
        ASSERT_FALSE(bb.empty());

        // Insert at index 2; the value 1 will intersect with the current bin so will fail
        res = bb.multi_insert_for_real(values, 2);
        ASSERT_EQ(-1 /* largest bin size after insert */, res);
        ASSERT_FALSE(bb.cache_invalid());

        values.clear();

        // Use a repeating label; there is no problem since the item value is different
        values.push_back(make_pair(2, 7));
        values.push_back(make_pair(3, 8));
        res = bb.multi_insert_for_real(values, 1);
        ASSERT_EQ(2 /* largest bin size after insert */, res);
        ASSERT_TRUE(bb.cache_invalid());
        bb.regen_cache();
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_FALSE(bb.empty());

        // Get the label
        bres = bb.try_get_multi_label({ 1, 2, 3 } , 0, labels);
        ASSERT_TRUE(bres);
        ASSERT_EQ(3, labels.size());
        ASSERT_EQ(1, labels[0]);
        ASSERT_EQ(7, labels[1]);
        ASSERT_EQ(8, labels[2]);

        values.resize(
            context.seal_context()->first_context_data()->parms().poly_modulus_degree(),
            make_pair(4, 4));
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
    }

    TEST(BinBundleTests, BinBundleTryMultiOverwrite)
    {
        CryptoContext context(*get_params());
        context.set_evaluator();

        BinBundle<felt_t> bb(context, true, 50);

        vector<pair<felt_t, felt_t>> values{ make_pair(1, 1) };

        // Now insert for real
        int res = bb.multi_insert_for_real(values, 0);
        ASSERT_EQ(1 /* largest bin size after insert */, res);

        // Check the label
        vector<felt_t> labels;
        bool bres = bb.try_get_multi_label({ 1 } , 0, labels);
        ASSERT_TRUE(bres);
        ASSERT_EQ(1, labels.size());
        ASSERT_EQ(1, labels[0]);

        ASSERT_TRUE(bb.cache_invalid());
        bb.regen_cache();
        ASSERT_FALSE(bb.cache_invalid());

        values[0].second = 2;
        bres = bb.try_multi_overwrite(values, 0);
        ASSERT_TRUE(bres);

        // Check the label
        bres = bb.try_get_multi_label({ 1 } , 0, labels);
        ASSERT_TRUE(bres);
        ASSERT_EQ(1, labels.size());
        ASSERT_EQ(2, labels[0]);

        ASSERT_TRUE(bb.cache_invalid());
        bb.regen_cache();
        ASSERT_FALSE(bb.cache_invalid());

        // Item doesn't match so won't overwrite
        values[0].first = 2;
        values[0].second = 3;
        bres = bb.try_multi_overwrite(values, 0);
        ASSERT_FALSE(bres);

        // Check the label; no change expected
        bres = bb.try_get_multi_label({ 1 } , 0, labels);
        ASSERT_TRUE(bres);
        ASSERT_EQ(1, labels.size());
        ASSERT_EQ(2, labels[0]);
        ASSERT_FALSE(bb.cache_invalid());

        values.clear();
        values = { make_pair(1, 1), make_pair(2, 2), make_pair(3, 3) };
        bb.clear();
        res = bb.multi_insert_for_real(values, 0);
        values = { make_pair(4, 4), make_pair(5, 5), make_pair(6, 6) };
        res = bb.multi_insert_for_real(values, 0);
        ASSERT_EQ(2 /* largest bin size after insert */, res);

        // Check the label
        bres = bb.try_get_multi_label({ 1, 5, 3 } , 0, labels);
        ASSERT_TRUE(bres);
        ASSERT_EQ(3, labels.size());
        ASSERT_EQ(1, labels[0]);
        ASSERT_EQ(5, labels[1]);
        ASSERT_EQ(3, labels[2]);

        ASSERT_TRUE(bb.cache_invalid());
        bb.regen_cache();
        ASSERT_FALSE(bb.cache_invalid());

        // Item sequence doesn't match
        values = { make_pair(1, 1), make_pair(4, 4), make_pair(3, 3) };
        bres = bb.try_multi_overwrite(values, 0);
        ASSERT_FALSE(bres);

        // Overwriting labels
        values = { make_pair(1, 6), make_pair(5, 7), make_pair(3, 8) };
        bres = bb.try_multi_overwrite(values, 0);
        ASSERT_TRUE(bres);

        ASSERT_TRUE(bb.cache_invalid());
        bb.regen_cache();
        ASSERT_FALSE(bb.cache_invalid());

        // Check the label
        bres = bb.try_get_multi_label({ 1, 5, 3 } , 0, labels);
        ASSERT_TRUE(bres);
        ASSERT_EQ(3, labels.size());
        ASSERT_EQ(6, labels[0]);
        ASSERT_EQ(7, labels[1]);
        ASSERT_EQ(8, labels[2]);

        bb.clear();
        values.resize(
            context.seal_context()->first_context_data()->parms().poly_modulus_degree(),
            make_pair(4, 4));
        res = bb.multi_insert_for_real(values, 0);
        ASSERT_EQ(1 /* largest bin size after insert */, res);

        ASSERT_TRUE(bb.cache_invalid());
        bb.regen_cache();
        ASSERT_FALSE(bb.cache_invalid());

        // Overflowing
        bres = bb.try_multi_overwrite(values, 1);
        ASSERT_FALSE(bres);
        ASSERT_FALSE(bb.cache_invalid());
    }

    TEST(BinBundleTests, BinBundleTryMultiRemove)
    {
        CryptoContext context(*get_params());
        context.set_evaluator();

        BinBundle<monostate> bb(context, true, 50);
        bb.regen_cache();
        ASSERT_FALSE(bb.cache_invalid());
        ASSERT_TRUE(bb.empty());

        // Now insert for real
        vector<pair<felt_t, monostate>> values{
            make_pair(1, monostate()),
            make_pair(2, monostate()),
            make_pair(3, monostate()) };
        int res = bb.multi_insert_for_real(values, 0);
        ASSERT_EQ(1 /* largest bin size after insert */, res);

        values = {
            make_pair(4, monostate()),
            make_pair(5, monostate()),
            make_pair(6, monostate()),
            make_pair(7, monostate()),
            make_pair(8, monostate()) };
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
        bres = bb.try_multi_remove({ 1, 2, 3, 7, 8  }, 0);
        ASSERT_TRUE(bres);
        ASSERT_TRUE(bb.cache_invalid());
        ASSERT_TRUE(bb.empty());
    }

    TEST(BinBundleTests, SaveLoadUnlabeled)
    {
        stringstream ss;

        CryptoContext context(*get_params());
        context.set_evaluator();

        BinBundle<monostate> bb(context, true, get_params()->table_params().max_items_per_bin);
        bb.regen_cache();
        ASSERT_TRUE(bb.empty());
        auto save_size = bb.save(ss, 1212);

        BinBundle<monostate> bb2(context, true, get_params()->table_params().max_items_per_bin);
        auto load_size = bb2.load(ss);
        ASSERT_EQ(1212, load_size.first);
        ASSERT_EQ(save_size, load_size.second);
        ASSERT_TRUE(bb2.empty());

        int res = bb.multi_insert_for_real({ make_pair(1, monostate()) }, 0);
        ASSERT_EQ(1 /* largest bin size after insert */, res);
        ASSERT_TRUE(bb.cache_invalid());
        ASSERT_FALSE(bb.empty());
        save_size = bb.save(ss, 131313);

        load_size = bb2.load(ss);
        ASSERT_EQ(131313, load_size.first);
        ASSERT_EQ(save_size, load_size.second);
        ASSERT_TRUE(bb2.cache_invalid());
        ASSERT_FALSE(bb2.empty());

        res = bb.multi_insert_for_real({ make_pair(2, monostate()), make_pair(3, monostate()) }, 0);
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
        ASSERT_NE(bb.get_bins()[0].end(), find_in_bin(bb.get_bins()[0], 1));
        ASSERT_NE(bb.get_bins()[0].end(), find_in_bin(bb.get_bins()[0], 2));
        ASSERT_NE(bb.get_bins()[1].end(), find_in_bin(bb.get_bins()[1], 3));

        // These should pass for the loaded BinBundle
        ASSERT_NE(bb2.get_bins()[0].end(), find_in_bin(bb2.get_bins()[0], 1));
        ASSERT_NE(bb2.get_bins()[0].end(), find_in_bin(bb2.get_bins()[0], 2));
        ASSERT_NE(bb2.get_bins()[1].end(), find_in_bin(bb2.get_bins()[1], 3));

        // Try loading to labeled BinBundle
        ss.seekg(0);
        BinBundle<felt_t> bb3(context, true, get_params()->table_params().max_items_per_bin);
        ASSERT_THROW(bb3.load(ss), runtime_error);
    }

    TEST(BinBundleTests, SaveLoadLabeled)
    {
        stringstream ss;

        CryptoContext context(*get_params());
        context.set_evaluator();

        BinBundle<felt_t> bb(context, true, get_params()->table_params().max_items_per_bin);
        bb.regen_cache();
        ASSERT_TRUE(bb.empty());
        auto save_size = bb.save(ss, 1);

        BinBundle<felt_t> bb2(context, true, get_params()->table_params().max_items_per_bin);
        auto load_size = bb2.load(ss);
        ASSERT_EQ(1, load_size.first);
        ASSERT_EQ(save_size, load_size.second);
        ASSERT_TRUE(bb2.empty());

        int res = bb.multi_insert_for_real({ make_pair(1, 2) }, 0);
        ASSERT_EQ(1 /* largest bin size after insert */, res);
        ASSERT_TRUE(bb.cache_invalid());
        ASSERT_FALSE(bb.empty());
        save_size = bb.save(ss, 1212);

        load_size = bb2.load(ss);
        ASSERT_EQ(1212, load_size.first);
        ASSERT_EQ(save_size, load_size.second);
        ASSERT_TRUE(bb2.cache_invalid());
        ASSERT_FALSE(bb2.empty());

        res = bb.multi_insert_for_real({ make_pair(2, 3), make_pair(3, 4) }, 0);
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
        auto find_res = find_in_bin(bb.get_bins()[0], 1);
        ASSERT_NE(bb.get_bins()[0].end(), find_res);
        ASSERT_EQ(2, find_res->second);
        find_res = find_in_bin(bb.get_bins()[0], 2);
        ASSERT_NE(bb.get_bins()[0].end(), find_res);
        ASSERT_EQ(3, find_res->second);
        find_res = find_in_bin(bb.get_bins()[1], 3);
        ASSERT_NE(bb.get_bins()[1].end(), find_res);
        ASSERT_EQ(4, find_res->second);

        // These should pass for the loaded BinBundle
        find_res = find_in_bin(bb2.get_bins()[0], 1);
        ASSERT_NE(bb2.get_bins()[0].end(), find_res);
        ASSERT_EQ(2, find_res->second);
        find_res = find_in_bin(bb2.get_bins()[0], 2);
        ASSERT_NE(bb2.get_bins()[0].end(), find_res);
        ASSERT_EQ(3, find_res->second);
        find_res = find_in_bin(bb2.get_bins()[1], 3);
        ASSERT_NE(bb2.get_bins()[1].end(), find_res);
        ASSERT_EQ(4, find_res->second);

        // Try loading to unlabeled BinBundle
        ss.seekg(0);
        BinBundle<monostate> bb3(context, true, get_params()->table_params().max_items_per_bin);
        ASSERT_THROW(bb3.load(ss), runtime_error);
    }
}
