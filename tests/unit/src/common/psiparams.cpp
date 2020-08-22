// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <sstream>

// APSI
#include "apsi/psiparams.h"

#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace seal;

namespace APSITests
{
    TEST(PSIParamsTest, Constructor)
    {
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

        // All good parameters
        ASSERT_NO_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params));

        // Too short item (4 * 16 == 64 < 80)
        item_params.felts_per_item = 4;
        ASSERT_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params), invalid_argument);

        // Too long item (16 * 16 == 256 > 128)
        item_params.felts_per_item = 16;
        ASSERT_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params), invalid_argument);

        // Too long item (16 * 16 == 256 > 128)
        item_params.felts_per_item = 16;
        ASSERT_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params), invalid_argument);

        item_params.felts_per_item = 8;
        
        // Invalid table_size (must be a power of two) and divide poly_modulus_degree
        table_params.table_size = 0;
        ASSERT_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params), invalid_argument);

        // Invalid table_size; poly_modulus_degree == 1024 with felts_per_item implies 128 items per SEAL ciphertext,
        // so this table will be too small to fill even one SEAL ciphertext.
        table_params.table_size = 64;
        ASSERT_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params), invalid_argument);

        // Size 128 is in this case the smallest table_size possible
        table_params.table_size = 128;
        ASSERT_NO_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params));

        // table_size is less than felts_per_item
        table_params.table_size = 4;
        ASSERT_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params), invalid_argument);

        // Too small query_powers_count
        table_params.table_size = 256;
        query_params.query_powers_count = 0;
        ASSERT_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params), invalid_argument);

        // Biggest possible query_powers_count
        query_params.query_powers_count = 16;
        ASSERT_NO_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params));

        // Too big query_powers_count
        query_params.query_powers_count = 17;
        ASSERT_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params), invalid_argument);
    }

    TEST(PSIParamsTest, SaveLoadPSIParams)
    {
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

        PSIParams psi_params(item_params, table_params, query_params, seal_params);
        stringstream ss;
        auto save_size = SaveParams(psi_params, ss);

        auto compare = LoadParams(ss);
        ASSERT_EQ(save_size, compare.second);
        auto load_params = compare.first;

        ASSERT_EQ(psi_params.item_params().felts_per_item, load_params.item_params().felts_per_item);
        ASSERT_EQ(psi_params.table_params().hash_func_count, load_params.table_params().hash_func_count);
        ASSERT_EQ(psi_params.table_params().max_items_per_bin, load_params.table_params().max_items_per_bin);
        ASSERT_EQ(psi_params.table_params().table_size, load_params.table_params().table_size);
        ASSERT_EQ(psi_params.query_params().query_powers_count, load_params.query_params().query_powers_count);
    }
}
