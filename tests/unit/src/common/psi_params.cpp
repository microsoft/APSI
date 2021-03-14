// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <sstream>

// APSI
#include "apsi/psi_params.h"

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
        table_params.table_size = 1024;

        PSIParams::QueryParams query_params;
        query_params.query_powers = { 1, 2, 3 };

        size_t pmd = 4096;
        PSIParams::SEALParams seal_params;
        seal_params.set_poly_modulus_degree(pmd);
        seal_params.set_coeff_modulus(CoeffModulus::Create(pmd, { 40, 40 }));
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

        // Invalid table_size; poly_modulus_degree == 4096 with felts_per_item implies 512 items per SEAL ciphertext,
        // so this table will be too small to fill even one SEAL ciphertext.
        table_params.table_size = 256;
        ASSERT_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params), invalid_argument);

        // Size 512 is in this case the smallest table_size possible
        table_params.table_size = 512;
        ASSERT_NO_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params));

        // table_size is less than felts_per_item
        table_params.table_size = 4;
        ASSERT_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params), invalid_argument);

        // query_powers must contain 1
        table_params.table_size = 512;
        query_params.query_powers = { 2 };
        ASSERT_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params), invalid_argument);

        // query_powers cannot contain 0
        query_params.query_powers = { 0, 1, 2 };
        ASSERT_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params), invalid_argument);

        // Too big query_powers
        query_params.query_powers = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 };
        ASSERT_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params), invalid_argument);
    }

    TEST(PSIParamsTest, SaveLoadPSIParams)
    {
        PSIParams::ItemParams item_params;
        item_params.felts_per_item = 8;

        PSIParams::TableParams table_params;
        table_params.hash_func_count = 3;
        table_params.max_items_per_bin = 16;
        table_params.table_size = 1024;

        PSIParams::QueryParams query_params;
        query_params.query_powers = { 1, 2, 3 };

        size_t pmd = 8192;
        PSIParams::SEALParams seal_params;
        seal_params.set_poly_modulus_degree(pmd);
        seal_params.set_coeff_modulus(CoeffModulus::Create(pmd, { 40, 50, 40 }));
        seal_params.set_plain_modulus(65537);

        PSIParams psi_params(item_params, table_params, query_params, seal_params);
        stringstream ss;
        auto save_size = psi_params.save(ss);

        auto compare = PSIParams::Load(ss);
        ASSERT_EQ(save_size, compare.second);
        auto load_params = compare.first;

        ASSERT_EQ(psi_params.item_params().felts_per_item, load_params.item_params().felts_per_item);
        ASSERT_EQ(psi_params.table_params().hash_func_count, load_params.table_params().hash_func_count);
        ASSERT_EQ(psi_params.table_params().max_items_per_bin, load_params.table_params().max_items_per_bin);
        ASSERT_EQ(psi_params.table_params().table_size, load_params.table_params().table_size);
        ASSERT_EQ(psi_params.query_params().query_powers.size(), load_params.query_params().query_powers.size());
        ASSERT_TRUE(equal(
            psi_params.query_params().query_powers.cbegin(),
            psi_params.query_params().query_powers.cend(),
            load_params.query_params().query_powers.cbegin()));
    }

    TEST(PSIParamsTest, JSONLoadPSIParams)
    {
        string json = 
"/* APSI Parameters */"
"{"
"    \"table_params\": {"
"        /* Number of hash functions to use */"
"        \"hash_func_count\": 3,"
"        /* Size of the hash table to use */"
"        \"table_size\": 512,"
"        /* Maximum number of items allowed in a bin */"
"        \"max_items_per_bin\": 92"
"    },"
"    \"item_params\": {"
"        /* Number of field elements to use per item */"
"        \"felts_per_item\": 8"
"    },"
"    \"query_params\": {"
"        /* Query powers to send in addition to 1 */"
"        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
"    },"
"    \"seal_params\": {"
"        /* Bit size for plaintext modulus prime for Microsoft SEAL encryption */"
"        /* \"plain_modulus_bits\": 16, */"
"        /* Plaintext modulus prime for Microsoft SEAL encryption */"
"        \"plain_modulus\": 40961,"
"        /* Degree of the polynomial modulus for Microsoft SEAL encryption */"
"        \"poly_modulus_degree\": 4096,"
"        /* Bit sizes for coefficient modulus primes for Microsoft SEAL encryption */"
"        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
"    }"
"}";

        PSIParams params = PSIParams::Load(json);

        ASSERT_EQ(3, params.table_params().hash_func_count);
        ASSERT_EQ(512, params.table_params().table_size);
        ASSERT_EQ(92, params.table_params().max_items_per_bin);

        ASSERT_EQ(8, params.item_params().felts_per_item);

        auto qp_end = params.query_params().query_powers.end();
        ASSERT_NE(qp_end, params.query_params().query_powers.find(3));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(4));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(5));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(8));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(14));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(20));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(26));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(32));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(38));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(41));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(42));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(43));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(45));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(46));

        ASSERT_EQ(40961, params.seal_params().plain_modulus().value());
        ASSERT_EQ(4096, params.seal_params().poly_modulus_degree());
        ASSERT_EQ(3, params.seal_params().coeff_modulus().size());
        ASSERT_EQ(49, params.seal_params().coeff_modulus()[0].value());
        ASSERT_EQ(40, params.seal_params().coeff_modulus()[1].value());
        ASSERT_EQ(20, params.seal_params().coeff_modulus()[2].value());
    }
}
