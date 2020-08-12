// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <sstream>
#include <vector>
#include <memory>
#include <algorithm>

// APSI
#include "apsi/network/result_package.h"
#include "apsi/cryptocontext.h"
#include "apsi/psiparams.h"

// SEAL
#include "seal/context.h"

#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::network;

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
                table_params.table_size = 256;
                table_params.window_size = 1;

                size_t pmd = 1024;
                PSIParams::SEALParams seal_params(scheme_type::BFV);
                seal_params.set_poly_modulus_degree(pmd);
                seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
                seal_params.set_plain_modulus(65537);

                params = make_shared<PSIParams>(item_params, table_params, seal_params);
            }

            return params;
        }

        shared_ptr<CryptoContext> get_context()
        {
            static shared_ptr<CryptoContext> context = nullptr;
            if (!context)
            {
                context = make_shared<CryptoContext>(SEALContext::Create(get_params()->seal_params()));
                KeyGenerator keygen(context->seal_context());
                context->set_secret(keygen.secret_key());
            }

            return context;
        }
    }

    TEST(ResultPackageTest, SaveLoadResultPackage)
    {
        ResultPackage rp;
        stringstream ss;

        shared_ptr<CryptoContext> context = get_context();

        // Save with no data; this will fail due to invalid PSI result
        ASSERT_THROW(size_t out_size = rp.save(ss), logic_error);

        // Symmetric encryption
        Ciphertext ct;
        context->encryptor()->encrypt_zero_symmetric(ct);
        rp.psi_result.set(move(ct));
        size_t out_size = rp.save(ss);
        ResultPackage rp2;
        size_t in_size = rp2.load(ss, context->seal_context());
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(rp2.bundle_idx, rp.bundle_idx);
        ASSERT_TRUE(rp2.label_result.empty());
        Plaintext pt;
        context->decryptor()->decrypt(rp2.psi_result.extract_local(), pt);
        ASSERT_TRUE(pt.is_zero());

        // Symmetric encryption as Serializable; not used in practice
        auto ser_ct = context->encryptor()->encrypt_zero_symmetric();
        rp.bundle_idx = 1;
        rp.psi_result.set(ser_ct);
        out_size = rp.save(ss);
        in_size = rp2.load(ss, context->seal_context());
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(rp2.bundle_idx, rp.bundle_idx);

        // Loaded package can never be serializable
        ASSERT_FALSE(rp2.psi_result.is_serializable());
        ASSERT_TRUE(rp2.label_result.empty());

        // Add some label data as well
        rp.bundle_idx = 2;
        rp.psi_result.set(ser_ct);
        rp.label_result.push_back(ser_ct);
        rp.label_result.push_back(ser_ct);
        out_size = rp.save(ss);
        in_size = rp2.load(ss, context->seal_context());
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(rp2.bundle_idx, rp.bundle_idx);
        ASSERT_EQ(rp2.label_result.size(), rp.label_result.size());
        context->decryptor()->decrypt(rp2.label_result[0].extract_local(), pt);
        ASSERT_TRUE(pt.is_zero());
        context->decryptor()->decrypt(rp2.label_result[1].extract_local(), pt);
        ASSERT_TRUE(pt.is_zero());
    }

    TEST(ResultPackageTest, Extract)
    {
        ResultPackage rp;

        shared_ptr<CryptoContext> context = get_context();

        // No labels
        rp.bundle_idx = 123;
        Ciphertext ct;
        context->encryptor()->encrypt_zero_symmetric(ct);
        rp.psi_result.set(ct);

        PlainResultPackage prp = rp.extract(*context);

        // Data has been extracted
        ASSERT_FALSE(rp.psi_result.is_local());
        ASSERT_FALSE(rp.psi_result.is_serializable());

        // bundle_idx is unchanged by extract 
        ASSERT_EQ(rp.bundle_idx, prp.bundle_idx);
        ASSERT_TRUE(all_of(prp.psi_result.begin(), prp.psi_result.end(), [](auto a) { return !a; }));
        ASSERT_TRUE(prp.label_result.empty());

        // Add some label data as well
        rp.psi_result.set(ct);
        rp.label_result.push_back(ct);
        rp.label_result.push_back(ct);

        prp = rp.extract(*context);

        // Data has been extracted
        ASSERT_FALSE(rp.psi_result.is_local());
        ASSERT_FALSE(rp.psi_result.is_serializable());
        ASSERT_TRUE(rp.label_result.empty());

        ASSERT_EQ(rp.bundle_idx, prp.bundle_idx);
        ASSERT_TRUE(all_of(prp.psi_result.begin(), prp.psi_result.end(), [](auto a) { return !a; }));
        ASSERT_EQ(2, prp.label_result.size());
        ASSERT_TRUE(all_of(prp.label_result[0].begin(), prp.label_result[0].end(), [](auto a) { return !a; }));
        ASSERT_TRUE(all_of(prp.label_result[1].begin(), prp.label_result[1].end(), [](auto a) { return !a; }));
    }
}