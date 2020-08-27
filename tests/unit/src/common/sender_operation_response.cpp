// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <sstream>
#include <vector>

// APSI
#include "apsi/network/sender_operation_response.h"

#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::network;

namespace APSITests
{
    TEST(SenderOperationResponseTest, SaveLoadSenderOperationResponseParms)
    {
        SenderOperationResponseParms sopr;
        ASSERT_EQ(SenderOperationType::SOP_PARMS, sopr.type());
        ASSERT_FALSE(sopr.params);

        stringstream ss;

        // Cannot save if parameters are not set
        ASSERT_THROW(auto out_size = sopr.save(ss), logic_error);

        // Create valid parameters
        PSIParams::ItemParams item_params;
        item_params.felts_per_item = 8;

        PSIParams::TableParams table_params;
        table_params.hash_func_count = 3;
        table_params.max_items_per_bin = 16;
        table_params.table_size = 256;

        PSIParams::QueryParams query_params;
        query_params.query_powers_count = 3;

        size_t pmd = 1024;
        PSIParams::SEALParams seal_params(scheme_type::BFV);
        seal_params.set_poly_modulus_degree(pmd);
        seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
        seal_params.set_plain_modulus(65537);

        sopr.params = make_unique<PSIParams>(
            item_params, table_params, query_params, seal_params);
        auto out_size = sopr.save(ss);

        SenderOperationResponseParms sopr2;
        size_t in_size = sopr2.load(ss);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::SOP_PARMS, sopr2.type());

        // Check that the parameters match
        ASSERT_EQ(sopr.params->item_params().felts_per_item, sopr2.params->item_params().felts_per_item);
        ASSERT_EQ(sopr.params->table_params().hash_func_count, sopr2.params->table_params().hash_func_count);
        ASSERT_EQ(sopr.params->table_params().max_items_per_bin, sopr2.params->table_params().max_items_per_bin);
        ASSERT_EQ(sopr.params->table_params().table_size, sopr2.params->table_params().table_size);
        ASSERT_EQ(sopr.params->query_params().query_powers_count, sopr2.params->query_params().query_powers_count);
        ASSERT_EQ(sopr.params->seal_params(), sopr2.params->seal_params());
    }

    TEST(SenderOperationResponseTest, SaveLoadSenderOperationResponseOPRF)
    {
        SenderOperationResponseOPRF sopr;
        ASSERT_EQ(SenderOperationType::SOP_OPRF, sopr.type());
        ASSERT_TRUE(sopr.data.empty());

        stringstream ss;

        // Save with no data
        auto out_size = sopr.save(ss);
        SenderOperationResponseOPRF sopr2;
        size_t in_size = sopr2.load(ss);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::SOP_OPRF, sopr2.type());
        ASSERT_TRUE(sopr2.data.empty());

        sopr.data.push_back(seal_byte(0xAB));
        out_size = sopr.save(ss);
        in_size = sopr2.load(ss);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::SOP_OPRF, sopr2.type());
        ASSERT_EQ(1, sopr2.data.size());
        ASSERT_EQ(static_cast<char>(0xAB), static_cast<char>(sopr2.data[0]));

        sopr.data.push_back(seal_byte(0xCD));
        out_size = sopr.save(ss);
        in_size = sopr2.load(ss);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::SOP_OPRF, sopr2.type());
        ASSERT_EQ(2, sopr2.data.size());
        ASSERT_EQ(static_cast<char>(0xAB), static_cast<char>(sopr2.data[0]));
        ASSERT_EQ(static_cast<char>(0xCD), static_cast<char>(sopr2.data[1]));
    }

    TEST(SenderOperationResponseTest, SaveLoadSenderOperationResponseQuery)
    {
        SenderOperationResponseQuery sopr;
        ASSERT_EQ(SenderOperationType::SOP_QUERY, sopr.type());

        stringstream ss;

        sopr.package_count = 0;
        auto out_size = sopr.save(ss);
        SenderOperationResponseQuery sopr2;
        size_t in_size = sopr2.load(ss);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::SOP_QUERY, sopr2.type());
        ASSERT_EQ(sopr.package_count, sopr2.package_count);

        sopr.package_count = 1;
        out_size = sopr.save(ss);
        in_size = sopr2.load(ss);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::SOP_QUERY, sopr2.type());
        ASSERT_EQ(sopr.package_count, sopr2.package_count);

        sopr.package_count = 5;
        out_size = sopr.save(ss);
        in_size = sopr2.load(ss);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::SOP_QUERY, sopr2.type());
        ASSERT_EQ(sopr.package_count, sopr2.package_count);
    }
}
