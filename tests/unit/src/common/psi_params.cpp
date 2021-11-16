// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <sstream>
#include <utility>

// APSI
#include "apsi/psi_params.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace seal;

namespace APSITests {
    TEST(PSIParamsTest, Constructor1)
    {
        PSIParams::ItemParams item_params;
        item_params.felts_per_item = 8;

        PSIParams::TableParams table_params;
        table_params.hash_func_count = 3;
        table_params.max_items_per_bin = 16;
        table_params.table_size = 1024;

        PSIParams::QueryParams query_params;
        query_params.ps_low_degree = 0;
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
        ASSERT_THROW(
            PSIParams psi_params(item_params, table_params, query_params, seal_params),
            invalid_argument);

        // Too long item (16 * 16 == 256 > 128)
        item_params.felts_per_item = 16;
        ASSERT_THROW(
            PSIParams psi_params(item_params, table_params, query_params, seal_params),
            invalid_argument);

        // Too long item (16 * 16 == 256 > 128)
        item_params.felts_per_item = 16;
        ASSERT_THROW(
            PSIParams psi_params(item_params, table_params, query_params, seal_params),
            invalid_argument);

        item_params.felts_per_item = 8;

        // Invalid table_size (must be a power of two) and divide poly_modulus_degree
        table_params.table_size = 0;
        ASSERT_THROW(
            PSIParams psi_params(item_params, table_params, query_params, seal_params),
            invalid_argument);

        // Invalid table_size; poly_modulus_degree == 4096 with felts_per_item implies 512 items per
        // SEAL ciphertext, so this table will be too small to fill even one SEAL ciphertext.
        table_params.table_size = 256;
        ASSERT_THROW(
            PSIParams psi_params(item_params, table_params, query_params, seal_params),
            invalid_argument);

        // Size 512 is in this case the smallest table_size possible
        table_params.table_size = 512;
        ASSERT_NO_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params));

        // table_size is less than felts_per_item
        table_params.table_size = 4;
        ASSERT_THROW(
            PSIParams psi_params(item_params, table_params, query_params, seal_params),
            invalid_argument);

        // ps_low_degree cannot exceed max_items_per_bin
        query_params.ps_low_degree = table_params.max_items_per_bin + 1;
        ASSERT_THROW(
            PSIParams psi_params(item_params, table_params, query_params, seal_params),
            invalid_argument);

        // query_powers must contain 1
        table_params.table_size = 512;
        query_params.query_powers = { 2 };
        ASSERT_THROW(
            PSIParams psi_params(item_params, table_params, query_params, seal_params),
            invalid_argument);

        // query_powers cannot contain 0
        query_params.query_powers = { 0, 1, 2 };
        ASSERT_THROW(
            PSIParams psi_params(item_params, table_params, query_params, seal_params),
            invalid_argument);

        // Too big query_powers
        query_params.query_powers = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 };
        ASSERT_THROW(
            PSIParams psi_params(item_params, table_params, query_params, seal_params),
            invalid_argument);
    }

    TEST(PSIParamsTest, Constructor2)
    {
        // Testing the case where felts_per_item is not a power of two

        PSIParams::ItemParams item_params;
        item_params.felts_per_item = 7;

        PSIParams::TableParams table_params;
        table_params.hash_func_count = 3;
        table_params.max_items_per_bin = 16;
        table_params.table_size = 1170;

        PSIParams::QueryParams query_params;
        query_params.ps_low_degree = 0;
        query_params.query_powers = { 1, 2, 3 };

        size_t pmd = 4096;
        PSIParams::SEALParams seal_params;
        seal_params.set_poly_modulus_degree(pmd);
        seal_params.set_coeff_modulus(CoeffModulus::Create(pmd, { 40, 40 }));
        seal_params.set_plain_modulus(65537);

        // All good parameters
        unique_ptr<PSIParams> psi_params;
        ASSERT_NO_THROW(
            psi_params =
                make_unique<PSIParams>(item_params, table_params, query_params, seal_params));

        // Check that the item count is computed correctly
        ASSERT_EQ(585, psi_params->items_per_bundle());
        ASSERT_EQ(4095, psi_params->bins_per_bundle());
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

        ASSERT_EQ(
            psi_params.item_params().felts_per_item, load_params.item_params().felts_per_item);
        ASSERT_EQ(
            psi_params.table_params().hash_func_count, load_params.table_params().hash_func_count);
        ASSERT_EQ(
            psi_params.table_params().max_items_per_bin,
            load_params.table_params().max_items_per_bin);
        ASSERT_EQ(psi_params.table_params().table_size, load_params.table_params().table_size);
        ASSERT_EQ(
            psi_params.query_params().query_powers.size(),
            load_params.query_params().query_powers.size());
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
            "        /* Paterson-Stockmeyer low degree; a value of zero disables "
            "Paterson-Stockmeyer */"
            "        \"ps_low_degree\": 0,"
            "        /* Query powers to send in addition to 1 */"
            "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
            "    },"
            "    \"seal_params\": {"
            "        /* Plaintext modulus prime for Microsoft SEAL encryption */"
            "        \"plain_modulus\": 40961,"
            "        /* Degree of the polynomial modulus for Microsoft SEAL encryption */"
            "        \"poly_modulus_degree\": 4096,"
            "        /* Bit sizes for coefficient modulus primes for Microsoft SEAL encryption */"
            "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
            "    }"
            "}";

        // Load params using plain_modulus
        PSIParams params = PSIParams::Load(json);

        ASSERT_EQ(3, params.table_params().hash_func_count);
        ASSERT_EQ(512, params.table_params().table_size);
        ASSERT_EQ(92, params.table_params().max_items_per_bin);

        ASSERT_EQ(8, params.item_params().felts_per_item);

        ASSERT_EQ(0, params.query_params().ps_low_degree);
        auto qp_end = params.query_params().query_powers.end();
        ASSERT_EQ(15, params.query_params().query_powers.size());
        ASSERT_NE(qp_end, params.query_params().query_powers.find(1));
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
        ASSERT_EQ(49, params.seal_params().coeff_modulus()[0].bit_count());
        ASSERT_EQ(40, params.seal_params().coeff_modulus()[1].bit_count());
        ASSERT_EQ(20, params.seal_params().coeff_modulus()[2].bit_count());

        json =
            "/* APSI Parameters */"
            "{"
            "    \"table_params\": {"
            "        /* Number of hash functions to use */"
            "        \"hash_func_count\": 5,"
            "        /* Size of the hash table to use */"
            "        \"table_size\": 2048,"
            "        /* Maximum number of items allowed in a bin */"
            "        \"max_items_per_bin\": 200"
            "    },"
            "    \"item_params\": {"
            "        /* Number of field elements to use per item */"
            "        \"felts_per_item\": 4"
            "    },"
            "    \"query_params\": {"
            "        /* Paterson-Stockmeyer low degree; a value of zero disables "
            "Paterson-Stockmeyer */"
            "        \"ps_low_degree\": 10,"
            "        /* Query powers to send in addition to 1 */"
            "        \"query_powers\": [ 4, 5, 8 ]"
            "    },"
            "    \"seal_params\": {"
            "        /* Bit size for plaintext modulus prime for Microsoft SEAL encryption */"
            "        \"plain_modulus_bits\": 24,"
            "        /* Degree of the polynomial modulus for Microsoft SEAL encryption */"
            "        \"poly_modulus_degree\": 8192,"
            "        /* Bit sizes for coefficient modulus primes for Microsoft SEAL encryption */"
            "        \"coeff_modulus_bits\": [ 49, 49, 40, 20 ]"
            "    }"
            "}";

        // Load params using plain_modulus_bits
        params = PSIParams::Load(json);

        ASSERT_EQ(5, params.table_params().hash_func_count);
        ASSERT_EQ(2048, params.table_params().table_size);
        ASSERT_EQ(200, params.table_params().max_items_per_bin);

        ASSERT_EQ(4, params.item_params().felts_per_item);

        ASSERT_EQ(10, params.query_params().ps_low_degree);
        qp_end = params.query_params().query_powers.end();
        ASSERT_EQ(4, params.query_params().query_powers.size());
        ASSERT_NE(qp_end, params.query_params().query_powers.find(1));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(4));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(5));
        ASSERT_NE(qp_end, params.query_params().query_powers.find(8));

        ASSERT_EQ(24, params.seal_params().plain_modulus().bit_count());
        ASSERT_EQ(8192, params.seal_params().poly_modulus_degree());
        ASSERT_EQ(4, params.seal_params().coeff_modulus().size());
        ASSERT_EQ(49, params.seal_params().coeff_modulus()[0].bit_count());
        ASSERT_EQ(49, params.seal_params().coeff_modulus()[1].bit_count());
        ASSERT_EQ(40, params.seal_params().coeff_modulus()[2].bit_count());
        ASSERT_EQ(20, params.seal_params().coeff_modulus()[3].bit_count());
    }

    TEST(PSIParamsTest, JSONLoadParamsMissingSections)
    {
        string json =
            "{"
            "    \"table_params\": {"
            "        \"hash_func_count\": 3,"
            "        \"table_size\": 512,"
            "        \"max_items_per_bin\": 92"
            "    },"
            "    \"item_params\": {"
            "        \"felts_per_item\": 8"
            "    },"
            "    \"query_params\": {"
            "        \"ps_low_degree\": 0,"
            "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
            "    },"
            "    \"seal_params\": {"
            "        \"plain_modulus\": 40961,"
            "        \"poly_modulus_degree\": 4096,"
            "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
            "    }"
            "}";

        // Correct JSON
        ASSERT_NO_THROW(PSIParams::Load(json));

        // Empty json
        json = "{}";
        ASSERT_THROW(PSIParams::Load(json), runtime_error);

        // Missing table_params
        json = "{"
               "    \"item_params\": {"
               "        \"felts_per_item\": 8"
               "    },"
               "    \"query_params\": {"
               "        \"ps_low_degree\": 0,"
               "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
               "    },"
               "    \"seal_params\": {"
               "        \"plain_modulus\": 40961,"
               "        \"poly_modulus_degree\": 4096,"
               "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
               "    }"
               "}";
        ASSERT_THROW(PSIParams::Load(json), runtime_error);

        // Missing item_params
        json = "{"
               "    \"table_params\": {"
               "        \"hash_func_count\": 3,"
               "        \"table_size\": 512,"
               "        \"max_items_per_bin\": 92"
               "    },"
               "    \"query_params\": {"
               "        \"ps_low_degree\": 0,"
               "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
               "    },"
               "    \"seal_params\": {"
               "        \"plain_modulus\": 40961,"
               "        \"poly_modulus_degree\": 4096,"
               "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
               "    }"
               "}";
        ASSERT_THROW(PSIParams::Load(json), runtime_error);

        // Missing query_params
        json = "{"
               "    \"table_params\": {"
               "        \"hash_func_count\": 3,"
               "        \"table_size\": 512,"
               "        \"max_items_per_bin\": 92"
               "    },"
               "    \"item_params\": {"
               "        \"felts_per_item\": 8"
               "    },"
               "    \"seal_params\": {"
               "        \"plain_modulus\": 40961,"
               "        \"poly_modulus_degree\": 4096,"
               "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
               "    }"
               "}";
        ASSERT_THROW(PSIParams::Load(json), runtime_error);

        // Missing seal_params
        json = "{"
               "    \"table_params\": {"
               "        \"hash_func_count\": 3,"
               "        \"table_size\": 512,"
               "        \"max_items_per_bin\": 92"
               "    },"
               "    \"item_params\": {"
               "        \"felts_per_item\": 8"
               "    },"
               "    \"query_params\": {"
               "        \"ps_low_degree\": 0,"
               "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
               "    }"
               "}";
        ASSERT_THROW(PSIParams::Load(json), runtime_error);
    }

    TEST(PSIParamsTest, JSONMissingTableParamsContent)
    {
        string json =
            "{"
            "    \"table_params\": {"
            "        \"hash_func_count\": 3,"
            "        \"table_size\": 512,"
            "        \"max_items_per_bin\": 92"
            "    },"
            "    \"item_params\": {"
            "        \"felts_per_item\": 8"
            "    },"
            "    \"query_params\": {"
            "        \"ps_low_degree\": 0,"
            "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
            "    },"
            "    \"seal_params\": {"
            "        \"plain_modulus\": 40961,"
            "        \"poly_modulus_degree\": 4096,"
            "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
            "    }"
            "}";

        // Correct JSON
        ASSERT_NO_THROW(PSIParams::Load(json));

        json = "{"
               "    \"table_params\": {"
               "        \"table_size\": 512,"
               "        \"max_items_per_bin\": 92"
               "    },"
               "    \"item_params\": {"
               "        \"felts_per_item\": 8"
               "    },"
               "    \"query_params\": {"
               "        \"ps_low_degree\": 0,"
               "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
               "    },"
               "    \"seal_params\": {"
               "        \"plain_modulus\": 40961,"
               "        \"poly_modulus_degree\": 4096,"
               "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
               "    }"
               "}";

        // Missing hash_func_count
        ASSERT_THROW(PSIParams::Load(json), runtime_error);

        json = "{"
               "    \"table_params\": {"
               "        \"hash_func_count\": 3,"
               "        \"max_items_per_bin\": 92"
               "    },"
               "    \"item_params\": {"
               "        \"felts_per_item\": 8"
               "    },"
               "    \"query_params\": {"
               "        \"ps_low_degree\": 0,"
               "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
               "    },"
               "    \"seal_params\": {"
               "        \"plain_modulus\": 40961,"
               "        \"poly_modulus_degree\": 4096,"
               "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
               "    }"
               "}";

        // Missing table_size
        ASSERT_THROW(PSIParams::Load(json), runtime_error);

        json = "{"
               "    \"table_params\": {"
               "        \"hash_func_count\": 3,"
               "        \"table_size\": 512"
               "    },"
               "    \"item_params\": {"
               "        \"felts_per_item\": 8"
               "    },"
               "    \"query_params\": {"
               "        \"ps_low_degree\": 0,"
               "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
               "    },"
               "    \"seal_params\": {"
               "        \"plain_modulus\": 40961,"
               "        \"poly_modulus_degree\": 4096,"
               "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
               "    }"
               "}";

        // Missing max_items_per_bin
        ASSERT_THROW(PSIParams::Load(json), runtime_error);
    }

    TEST(PSIParamsTest, JSONMissingItemParams)
    {
        string json =
            "{"
            "    \"table_params\": {"
            "        \"hash_func_count\": 3,"
            "        \"table_size\": 512,"
            "        \"max_items_per_bin\": 92"
            "    },"
            "    \"item_params\": {"
            "        \"felts_per_item\": 8"
            "    },"
            "    \"query_params\": {"
            "        \"ps_low_degree\": 0,"
            "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
            "    },"
            "    \"seal_params\": {"
            "        \"plain_modulus\": 40961,"
            "        \"poly_modulus_degree\": 4096,"
            "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
            "    }"
            "}";

        // Correct JSON
        ASSERT_NO_THROW(PSIParams::Load(json));

        json = "{"
               "    \"table_params\": {"
               "        \"hash_func_count\": 3,"
               "        \"table_size\": 512,"
               "        \"max_items_per_bin\": 92"
               "    },"
               "    \"item_params\": {"
               "        \"other_name\": 8"
               "    },"
               "    \"query_params\": {"
               "        \"ps_low_degree\": 0,"
               "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
               "    },"
               "    \"seal_params\": {"
               "        \"plain_modulus\": 40961,"
               "        \"poly_modulus_degree\": 4096,"
               "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
               "    }"
               "}";

        // Missing felts_per_item
        ASSERT_THROW(PSIParams::Load(json), runtime_error);
    }

    TEST(PSIParamsTest, JSONMissingQueryParams)
    {
        string json =
            "{"
            "    \"table_params\": {"
            "        \"hash_func_count\": 3,"
            "        \"table_size\": 512,"
            "        \"max_items_per_bin\": 92"
            "    },"
            "    \"item_params\": {"
            "        \"felts_per_item\": 8"
            "    },"
            "    \"query_params\": {"
            "        \"ps_low_degree\": 0,"
            "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
            "    },"
            "    \"seal_params\": {"
            "        \"plain_modulus\": 40961,"
            "        \"poly_modulus_degree\": 4096,"
            "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
            "    }"
            "}";

        // Correct JSON
        ASSERT_NO_THROW(PSIParams::Load(json));

        json = "{"
               "    \"table_params\": {"
               "        \"hash_func_count\": 3,"
               "        \"table_size\": 512,"
               "        \"max_items_per_bin\": 92"
               "    },"
               "    \"item_params\": {"
               "        \"felts_per_item\": 8"
               "    },"
               "    \"query_params\": {"
               "        \"other_name\": 0,"
               "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
               "    },"
               "    \"seal_params\": {"
               "        \"plain_modulus\": 40961,"
               "        \"poly_modulus_degree\": 4096,"
               "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
               "    }"
               "}";

        // Missing ps_low_degree
        ASSERT_THROW(PSIParams::Load(json), runtime_error);

        json = "{"
               "    \"table_params\": {"
               "        \"hash_func_count\": 3,"
               "        \"table_size\": 512,"
               "        \"max_items_per_bin\": 92"
               "    },"
               "    \"item_params\": {"
               "        \"felts_per_item\": 8"
               "    },"
               "    \"query_params\": {"
               "        \"ps_low_degree\": 0,"
               "        \"other_name\": [ 3, 4, 5 ]"
               "    },"
               "    \"seal_params\": {"
               "        \"plain_modulus\": 40961,"
               "        \"poly_modulus_degree\": 4096,"
               "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
               "    }"
               "}";

        // Missing query_powers
        ASSERT_THROW(PSIParams::Load(json), runtime_error);
    }

    TEST(PSIParamsTest, JSONMissingSEALParams)
    {
        string json =
            "{"
            "    \"table_params\": {"
            "        \"hash_func_count\": 3,"
            "        \"table_size\": 512,"
            "        \"max_items_per_bin\": 92"
            "    },"
            "    \"item_params\": {"
            "        \"felts_per_item\": 8"
            "    },"
            "    \"query_params\": {"
            "        \"ps_low_degree\": 0,"
            "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
            "    },"
            "    \"seal_params\": {"
            "        \"plain_modulus\": 40961,"
            "        \"poly_modulus_degree\": 4096,"
            "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
            "    }"
            "}";

        // Correct JSON
        ASSERT_NO_THROW(PSIParams::Load(json));

        json = "{"
               "    \"table_params\": {"
               "        \"hash_func_count\": 3,"
               "        \"table_size\": 512,"
               "        \"max_items_per_bin\": 92"
               "    },"
               "    \"item_params\": {"
               "        \"felts_per_item\": 8"
               "    },"
               "    \"query_params\": {"
               "        \"ps_low_degree\": 0,"
               "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
               "    },"
               "    \"seal_params\": {"
               "        \"poly_modulus_degree\": 4096,"
               "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
               "    }"
               "}";

        // Missing plain_modulus
        ASSERT_THROW(PSIParams::Load(json), runtime_error);

        json = "{"
               "    \"table_params\": {"
               "        \"hash_func_count\": 3,"
               "        \"table_size\": 512,"
               "        \"max_items_per_bin\": 92"
               "    },"
               "    \"item_params\": {"
               "        \"felts_per_item\": 8"
               "    },"
               "    \"query_params\": {"
               "        \"ps_low_degree\": 0,"
               "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
               "    },"
               "    \"seal_params\": {"
               "        \"plain_modulus\": 40961,"
               "        \"coeff_modulus_bits\": [ 49, 40, 20 ]"
               "    }"
               "}";

        // Missing poly_modulus_degree
        ASSERT_THROW(PSIParams::Load(json), runtime_error);

        json = "{"
               "    \"table_params\": {"
               "        \"hash_func_count\": 3,"
               "        \"table_size\": 512,"
               "        \"max_items_per_bin\": 92"
               "    },"
               "    \"item_params\": {"
               "        \"felts_per_item\": 8"
               "    },"
               "    \"query_params\": {"
               "        \"ps_low_degree\": 0,"
               "        \"query_powers\": [ 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46 ]"
               "    },"
               "    \"seal_params\": {"
               "        \"plain_modulus\": 40961,"
               "        \"poly_modulus_degree\": 4096"
               "    }"
               "}";

        // Missing coeff_modulus_bits
        ASSERT_THROW(PSIParams::Load(json), runtime_error);
    }
} // namespace APSITests
