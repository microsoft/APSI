// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cmath>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// APSI
#include "apsi/psi_params.h"
#include "apsi/psi_params_generated.h"
#include "apsi/version.h"

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

    TEST(PSIParamsTest, QuerySizeIsBounded)
    {
        // poly_modulus_degree 4096 with felts_per_item 8 gives 512 items per bundle, so a table of
        // table_size_max spans 2048 bundles. With a single query power and two 40-bit primes each
        // ciphertext is 128 KiB, keeping the query well inside query_byte_count_max.
        PSIParams::ItemParams item_params;
        item_params.felts_per_item = 8;

        PSIParams::TableParams table_params;
        table_params.hash_func_count = 3;
        table_params.max_items_per_bin = 16;
        table_params.table_size = PSIParams::TableParams::table_size_max;

        PSIParams::QueryParams query_params;
        query_params.ps_low_degree = 0;
        query_params.query_powers = { 1 };

        size_t pmd = 4096;
        PSIParams::SEALParams seal_params;
        seal_params.set_poly_modulus_degree(pmd);
        seal_params.set_coeff_modulus(CoeffModulus::Create(pmd, { 40, 40 }));
        seal_params.set_plain_modulus(65537);

        ASSERT_NO_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params));

        // One bundle beyond table_size_max is rejected; the query itself is still small enough that
        // only the table_size bound can be responsible
        table_params.table_size = PSIParams::TableParams::table_size_max + 512;
        ASSERT_THROW(
            PSIParams psi_params(item_params, table_params, query_params, seal_params),
            invalid_argument);

        table_params.table_size = PSIParams::TableParams::table_size_max;

        // 2048 bundles times two query powers is 4096 ciphertexts of 128 KiB, exactly
        // query_byte_count_max
        query_params.query_powers = { 1, 2 };
        ASSERT_NO_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params));

        // A third query power exceeds it, even though table_size is unchanged and legal
        query_params.query_powers = { 1, 2, 3 };
        ASSERT_THROW(
            PSIParams psi_params(item_params, table_params, query_params, seal_params),
            invalid_argument);

        // Enlarging the coefficient modulus is rejected for the same reason, at an unchanged
        // ciphertext count. A bound on the number of ciphertexts would not catch this.
        query_params.query_powers = { 1, 2 };
        seal_params.set_coeff_modulus(CoeffModulus::Create(pmd, { 36, 36, 36 }));
        ASSERT_THROW(
            PSIParams psi_params(item_params, table_params, query_params, seal_params),
            invalid_argument);
    }

    TEST(PSIParamsTest, MaxItemsPerBinIsBounded)
    {
        PSIParams::ItemParams item_params;
        item_params.felts_per_item = 8;

        PSIParams::TableParams table_params;
        table_params.hash_func_count = 3;
        table_params.max_items_per_bin = PSIParams::TableParams::max_items_per_bin_max;
        table_params.table_size = 512;

        PSIParams::QueryParams query_params;
        query_params.ps_low_degree = 0;
        query_params.query_powers = { 1 };

        size_t pmd = 4096;
        PSIParams::SEALParams seal_params;
        seal_params.set_poly_modulus_degree(pmd);
        seal_params.set_coeff_modulus(CoeffModulus::Create(pmd, { 40, 40 }));
        seal_params.set_plain_modulus(65537);

        ASSERT_NO_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params));

        // max_items_per_bin is the degree of the matching polynomial and drives a quadratic
        // search in PowersDag::configure. The query these parameters describe stays tiny
        // throughout, so neither of the other two bounds can be what rejects this.
        table_params.max_items_per_bin = PSIParams::TableParams::max_items_per_bin_max + 1;
        ASSERT_THROW(
            PSIParams psi_params(item_params, table_params, query_params, seal_params),
            invalid_argument);
    }

    TEST(PSIParamsTest, CoeffModulusSizeIsBounded)
    {
        PSIParams::ItemParams item_params;
        item_params.felts_per_item = 8;

        PSIParams::TableParams table_params;
        table_params.hash_func_count = 3;
        table_params.max_items_per_bin = 16;
        table_params.table_size = 2048;

        PSIParams::QueryParams query_params;
        query_params.ps_low_degree = 0;
        query_params.query_powers = { 1 };

        // A single bundle and a single query power, so the query is one ciphertext however long
        // the modulus chain is. This is the shape that escapes query_byte_count_max, and the
        // reason the chain needs a bound of its own.
        size_t pmd = 16384;
        PSIParams::SEALParams seal_params;
        seal_params.set_poly_modulus_degree(pmd);
        seal_params.set_plain_modulus(65537);

        vector<int> bits(PSIParams::coeff_modulus_size_max, 25);
        seal_params.set_coeff_modulus(CoeffModulus::Create(pmd, bits));
        ASSERT_NO_THROW(PSIParams psi_params(item_params, table_params, query_params, seal_params));

        // One prime more is rejected here rather than by Microsoft SEAL, which bounds the chain
        // by total bit width and still considers this secure at tc128
        bits.push_back(25);
        seal_params.set_coeff_modulus(CoeffModulus::Create(pmd, bits));
        ASSERT_LT(
            accumulate(bits.cbegin(), bits.cend(), 0),
            CoeffModulus::MaxBitCount(pmd, sec_level_type::tc128));
        ASSERT_THROW(
            PSIParams psi_params(item_params, table_params, query_params, seal_params),
            invalid_argument);
    }

    TEST(PSIParamsTest, MostDemandingShippedParamsAreAccepted)
    {
        // parameters/16M-11041.json builds the largest query of any parameter set in parameters/
        string json = "{"
                      "    \"table_params\": {"
                      "        \"hash_func_count\": 3,"
                      "        \"table_size\": 16380,"
                      "        \"max_items_per_bin\": 1304"
                      "    },"
                      "    \"item_params\": { \"felts_per_item\": 5 },"
                      "    \"query_params\": {"
                      "        \"ps_low_degree\": 44,"
                      "        \"query_powers\": [ 1, 3, 11, 18, 45, 225 ]"
                      "    },"
                      "    \"seal_params\": {"
                      "        \"plain_modulus_bits\": 22,"
                      "        \"poly_modulus_degree\": 8192,"
                      "        \"coeff_modulus_bits\": [ 56, 56, 56, 50 ]"
                      "    }"
                      "}";

        PSIParams params = PSIParams::Load(json);
        ASSERT_EQ(16380, params.table_params().table_size);
        ASSERT_EQ(10, params.bundle_idx_count());
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

    TEST(PSIParamsTest, LoadRejectsFlatBufferMissingRequiredTables)
    {
        // A serialized PSIParams carrying only version and seal_params. The item_params,
        // table_params and query_params tables are absent.
        //
        // Parameters arrive from the sender, so this is input the receiver does not control.
        // PSIParams::Load builds a PSIParams out of each of those tables, so a buffer that omits
        // one must be refused rather than read. The schema marks the fields required, so the
        // verifier refuses the buffer before any field is read and ahead of the serialization
        // version check, which keeps this vector valid across version bumps; PSIParams::Load
        // checks the same fields again so the guarantee does not rest on the schema alone.
        //
        // Held as bytes rather than built here on purpose: the generated builder asserts on a
        // missing required field, so the buffer this guards against cannot be constructed
        // through the API it has to be defended against.
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
        const unsigned char missing_tables[] = {
            0x38, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00,
            0x0e, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x0e, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x06, 0x00, 0x08, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        };

        stringstream ss;
        ss.write(
            reinterpret_cast<const char *>(missing_tables),
            static_cast<streamsize>(sizeof(missing_tables)));

        ASSERT_THROW(static_cast<void>(PSIParams::Load(ss)), runtime_error);
    }

    TEST(PSIParamsTest, LoadRejectsOversizedQueryPowersBeforeMaterializingThem)
    {
        // Parameters are the first thing a receiver accepts from a sender, before anything has
        // been agreed, so query_powers is attacker-chosen input. The FlatBuffers verifier bounds
        // the vector's extent but not its length, so a modest buffer can name a very large
        // number of powers; inserting them into a node-per-element container ahead of the
        // bound in initialize() is what turns that into real memory.
        //
        // The count here is one past the maximum and the values are all distinct, so the buffer
        // is rejected on count alone rather than on any of the later content checks.
        constexpr uint32_t too_many = PSIParams::TableParams::max_items_per_bin_max + 1;

        vector<uint32_t> powers(too_many);
        iota(powers.begin(), powers.end(), 1U);

        flatbuffers::FlatBufferBuilder fbs_builder(1024);

        EncryptionParameters seal_ep(scheme_type::bfv);
        seal_ep.set_poly_modulus_degree(8192);
        seal_ep.set_coeff_modulus(CoeffModulus::BFVDefault(8192));
        seal_ep.set_plain_modulus(65537);
        stringstream seal_ss;
        seal_ep.save(seal_ss);
        string seal_str = seal_ss.str();
        vector<uint8_t> seal_bytes(seal_str.cbegin(), seal_str.cend());

        auto seal_data = fbs_builder.CreateVector(seal_bytes);
        auto seal_params = fbs::CreateSEALParams(fbs_builder, seal_data);

        auto query_powers = fbs_builder.CreateVector(powers);
        auto query_params = fbs::CreateQueryParams(fbs_builder, 0, query_powers);

        fbs::ItemParams item_params(8);
        fbs::TableParams table_params(1024, 16, 3);

        fbs::PSIParamsBuilder psi_params_builder(fbs_builder);
        psi_params_builder.add_version(apsi_serialization_version);
        psi_params_builder.add_item_params(&item_params);
        psi_params_builder.add_table_params(&table_params);
        psi_params_builder.add_query_params(query_params);
        psi_params_builder.add_seal_params(seal_params);
        auto root = psi_params_builder.Finish();
        fbs_builder.FinishSizePrefixed(root);

        stringstream ss;
        ss.write(
            reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
            static_cast<streamsize>(fbs_builder.GetSize()));

        ASSERT_THROW(static_cast<void>(PSIParams::Load(ss)), runtime_error);
    }

    TEST(PSIParamsTest, LoadAcceptsAFrozenBufferFromAnEarlierVersion)
    {
        // A serialized PSIParams captured from parameters/1M-1-32.json, held here as bytes so it
        // cannot drift with the code that produced it.
        //
        // Marking fields required in psi_params.fbs changes what the verifier rejects, not what
        // the writer emits: a buffer built with and without those attributes is byte-identical,
        // because every field was always written. This vector is what pins that down. Parameters
        // are embedded in a serialized SenderDB, so a reader that stopped accepting them would
        // strand every SenderDB file an earlier version wrote.
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
        const unsigned char frozen[] = {
            0x00, 0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x22, 0x00,
            0x1c, 0x00, 0x18, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x04, 0x00, 0x0e, 0x00, 0x00, 0x00,
            0x24, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x66, 0x06, 0x00, 0x00, 0xe4, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x06, 0x00, 0x08, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x81, 0x00, 0x00, 0x00, 0x5e, 0xa1, 0x10, 0x04, 0x04, 0x00, 0x00, 0x00,
            0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5e, 0xa1, 0x10,
            0x04, 0x04, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x40, 0xfb, 0xff, 0xff, 0xff, 0xff, 0x00, 0x5e, 0xa1, 0x10, 0x04, 0x04, 0x00, 0x00,
            0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0xfd, 0xff, 0xff,
            0xff, 0x00, 0x00, 0x5e, 0xa1, 0x10, 0x04, 0x04, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x5e,
            0xa1, 0x10, 0x04, 0x04, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00,
            0x5c, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00,
        };

        stringstream ss;
        ss.write(reinterpret_cast<const char *>(frozen), static_cast<streamsize>(sizeof(frozen)));

        auto loaded = PSIParams::Load(ss);

        ASSERT_EQ(static_cast<uint32_t>(1638), loaded.first.table_params().table_size);
        ASSERT_EQ(static_cast<uint32_t>(228), loaded.first.table_params().max_items_per_bin);
        ASSERT_EQ(static_cast<uint32_t>(1), loaded.first.table_params().hash_func_count);
        ASSERT_EQ(static_cast<uint32_t>(5), loaded.first.item_params().felts_per_item);
        ASSERT_EQ(static_cast<uint32_t>(0), loaded.first.query_params().ps_low_degree);
        ASSERT_EQ(static_cast<size_t>(8), loaded.first.query_params().query_powers.size());

        // Round-tripping it must reproduce the same bytes, so a future change to the writer is
        // caught here rather than by whoever tries to read this version's output later.
        stringstream out;
        loaded.first.save(out);
        string written = out.str();
        ASSERT_EQ(sizeof(frozen), written.size());
        ASSERT_EQ(0, memcmp(frozen, written.data(), sizeof(frozen)));
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
        ASSERT_NO_THROW(static_cast<void>(PSIParams::Load(json)));

        // Empty json
        json = "{}";
        ASSERT_THROW(static_cast<void>(PSIParams::Load(json)), runtime_error);

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
        ASSERT_THROW(static_cast<void>(PSIParams::Load(json)), runtime_error);

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
        ASSERT_THROW(static_cast<void>(PSIParams::Load(json)), runtime_error);

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
        ASSERT_THROW(static_cast<void>(PSIParams::Load(json)), runtime_error);

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
        ASSERT_THROW(static_cast<void>(PSIParams::Load(json)), runtime_error);
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
        ASSERT_NO_THROW(static_cast<void>(PSIParams::Load(json)));

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
        ASSERT_THROW(static_cast<void>(PSIParams::Load(json)), runtime_error);

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
        ASSERT_THROW(static_cast<void>(PSIParams::Load(json)), runtime_error);

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
        ASSERT_THROW(static_cast<void>(PSIParams::Load(json)), runtime_error);
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
        ASSERT_NO_THROW(static_cast<void>(PSIParams::Load(json)));

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
        ASSERT_THROW(static_cast<void>(PSIParams::Load(json)), runtime_error);
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
        ASSERT_NO_THROW(static_cast<void>(PSIParams::Load(json)));

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
        ASSERT_THROW(static_cast<void>(PSIParams::Load(json)), runtime_error);

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
        ASSERT_THROW(static_cast<void>(PSIParams::Load(json)), runtime_error);
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
        ASSERT_NO_THROW(static_cast<void>(PSIParams::Load(json)));

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
        ASSERT_THROW(static_cast<void>(PSIParams::Load(json)), runtime_error);

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
        ASSERT_THROW(static_cast<void>(PSIParams::Load(json)), runtime_error);

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
        ASSERT_THROW(static_cast<void>(PSIParams::Load(json)), runtime_error);
    }
    namespace {
        // Smallest load that a bin should not exceed: the smallest k for which the chance that
        // any of the m bins holds k or more is below delta. A mean-plus-one-deviation estimate
        // is not enough here, because it describes a typical maximum rather than bounding one,
        // and under-predicts often enough to matter -- one bundle either way decides whether a
        // parameter set meets the bound.
        double load_bound(double mean, double bins)
        {
            if (mean <= 0.0) {
                return 1.0;
            }
            const double delta = 1e-3;
            double target = delta / bins;
            double log_p = -mean; // log P(X = 0)
            double tail = 1.0;    // P(X >= k)
            double k = 0.0;
            while (tail > target && k < 1e7) {
                tail -= exp(log_p);
                k += 1.0;
                log_p += log(mean) - log(k);
            }
            return k;
        }

        // How many bin bundles a bundle index may hold. Two things open a new one: a location
        // filling its bin, and -- in labeled mode only -- two items whose field elements collide,
        // since interpolation needs distinct points and BinBundle::multi_insert refuses the
        // repeat. The second dominates when max_items_per_bin approaches the square root of the
        // field element space, which is where a capacity-only estimate silently under-predicts.
        double bundle_bound(
            double sender_size,
            double hash_func_count,
            double table_size,
            double max_items_per_bin,
            double item_bit_count_per_felt,
            double label_byte_count)
        {
            double mean = hash_func_count * sender_size / table_size;
            double per_bin = load_bound(mean, table_size);
            double bundles = max(1.0, ceil(per_bin / max_items_per_bin));

            if (label_byte_count > 0.0) {
                double in_bin = min(per_bin, max_items_per_bin);
                double space = pow(2.0, item_bit_count_per_felt);
                double colliding_pairs = in_bin * in_bin / (2.0 * space);
                bundles = max(bundles, 1.0 + load_bound(colliding_pairs, table_size));
            }
            return bundles;
        }

        // Sender and receiver set sizes, and any label byte count, are encoded in the file name as
        // the README describes: <sender>-<receiver>[-<label byte count>][-com|-cmp].
        bool parse_name(const string &stem, double &sender, double &receiver, double &label_bytes)
        {
            size_t dash = stem.find('-');
            if (dash == string::npos) {
                return false;
            }
            string s = stem.substr(0, dash);
            size_t mult = 1;
            if (!s.empty() && (s.back() == 'K' || s.back() == 'M')) {
                mult = (s.back() == 'K') ? 1000 : 1000000;
                s.pop_back();
            }
            string rest = stem.substr(dash + 1);
            string r = rest;
            string tail;
            size_t dash2 = rest.find('-');
            if (dash2 != string::npos) {
                r = rest.substr(0, dash2);
                tail = rest.substr(dash2 + 1);
            }
            if (s.empty() || r.empty() || s.find_first_not_of("0123456789") != string::npos ||
                r.find_first_not_of("0123456789") != string::npos) {
                return false;
            }
            sender = static_cast<double>(stoull(s)) * static_cast<double>(mult);
            receiver = static_cast<double>(stoull(r));

            label_bytes = 0.0;
            if (!tail.empty()) {
                string first = tail.substr(0, tail.find('-'));
                if (first.find_first_not_of("0123456789") == string::npos) {
                    label_bytes = static_cast<double>(stoull(first));
                }
            }
            return true;
        }
    } // namespace

    TEST(PSIParamsTests, JSONVersionKeyIsOptionalAndGatesIncompatibleFiles)
    {
        // A file may name the serialization version it was written for, so that one written for
        // a version this build does not implement is refused while loading rather than at the
        // first exchange with a peer. The key is optional: files written before it existed, and
        // the sets in parameters/, carry no version and must still load.
        stringstream ss;
        ifstream file(string(APSI_PARAMETERS_DIR) + "/100K-1.json");
        ASSERT_TRUE(file.is_open());
        ss << file.rdbuf();
        string base = ss.str();

        ASSERT_NO_THROW(static_cast<void>(PSIParams::Load(base)));

        auto with_version = [&base](const string &value) {
            size_t brace = base.find('{');
            return base.substr(0, brace + 1) + "\n    \"version\": " + value + "," +
                   base.substr(brace + 1);
        };

        // The version this build implements is accepted.
        ASSERT_NO_THROW(
            static_cast<void>(
                PSIParams::Load(with_version(to_string(apsi_serialization_version)))));

        // Any other is refused, in both directions.
        ASSERT_THROW(
            static_cast<void>(
                PSIParams::Load(with_version(to_string(apsi_serialization_version + 1)))),
            runtime_error);
        ASSERT_THROW(static_cast<void>(PSIParams::Load(with_version("0"))), runtime_error);

        // A version that is not an unsigned integer is refused rather than ignored.
        ASSERT_THROW(static_cast<void>(PSIParams::Load(with_version("\"one\""))), runtime_error);
    }

    TEST(PSIParamsTests, MalformedJSONValuesAreRefusedWhateverTheirType)
    {
        // A value of the wrong type is reported rather than asserted on. The message names the
        // offending value by streaming it, which every Json::Value supports; reading it as a
        // string instead would hold only for a string, and jsoncpp answers the rest by throwing
        // a logic error or, when built without exceptions, by aborting.
        stringstream ss;
        ifstream file(string(APSI_PARAMETERS_DIR) + "/100K-1.json");
        ASSERT_TRUE(file.is_open());
        ss << file.rdbuf();
        string base = ss.str();

        ASSERT_NO_THROW(static_cast<void>(PSIParams::Load(base)));

        auto with_replacement = [&base](const string &from, const string &to) {
            string result = base;
            size_t at = result.find(from);
            EXPECT_NE(string::npos, at);
            return result.replace(at, from.size(), to);
        };

        // A query power at every JSON type that is not an unsigned integer.
        for (const string &value : vector<string>{ "1.5", "true", "-3", "{}", "[]", "null" }) {
            ASSERT_THROW(
                static_cast<void>(
                    PSIParams::Load(with_replacement("[ 1, 2,", "[ " + value + ", 2,"))),
                runtime_error);
        }

        // A coefficient modulus bit count at every JSON type that is not an int.
        for (const string &value : vector<string>{ "1.5", "true", "{}", "[]", "null" }) {
            ASSERT_THROW(
                static_cast<void>(PSIParams::Load(with_replacement("[ 48 ]", "[ " + value + " ]"))),
                runtime_error);
        }

        // And the optional version key, which is read the same way.
        for (const string &value : vector<string>{ "1.5", "true", "{}", "[]" }) {
            ASSERT_THROW(
                static_cast<void>(
                    PSIParams::Load(with_replacement("{", "{ \"version\": " + value + ","))),
                runtime_error);
        }
    }

    TEST(PSIParamsTests, ShippedParameterSetsHoldTheDocumentedFalsePositiveBound)
    {
        // The README promises that every shipped parameter set keeps the probability of a query
        // returning at least one false positive below 2^-40, at the set sizes its file name
        // gives. That figure is not PSIParams::log2_fpp_per_bin_bundle, which describes one
        // bin bundle: it must also count the bundles a location spills into and the items in
        // a query. Retuning a
        // parameter file without carrying both terms is what this guards against.
        //
        // The bundle count is bounded rather than estimated, so the guard errs towards reporting
        // a set as failing rather than passing.
        namespace fs = std::filesystem;
        fs::path dir(APSI_PARAMETERS_DIR);
        ASSERT_TRUE(fs::is_directory(dir)) << "cannot find " << dir;

        size_t json_files = 0;
        size_t checked = 0;
        for (const auto &entry : fs::directory_iterator(dir)) {
            if (entry.path().extension() != ".json") {
                continue;
            }
            json_files++;

            string stem = entry.path().stem().string();
            double sender = 0.0;
            double receiver = 0.0;
            double label_bytes = 0.0;
            // A name this cannot read is a parameter set nothing here is checking, which is the
            // failure this test exists to prevent.
            ASSERT_TRUE(parse_name(stem, sender, receiver, label_bytes))
                << stem << ": cannot read sender and receiver sizes from the file name, so the "
                << "false-positive bound cannot be checked for it";

            ifstream file(entry.path());
            ASSERT_TRUE(file.is_open()) << stem;
            stringstream json;
            json << file.rdbuf();

            PSIParams params = PSIParams::Load(json.str());
            double bundles = bundle_bound(
                sender,
                static_cast<double>(params.table_params().hash_func_count),
                static_cast<double>(params.table_params().table_size),
                static_cast<double>(params.table_params().max_items_per_bin),
                static_cast<double>(params.item_bit_count_per_felt()),
                label_bytes);

            double fpp = params.log2_fpp_per_bin_bundle() + log2(bundles) + log2(receiver);

            ASSERT_LT(fpp, -40.0) << stem << ": per-execution log2(fpp) is " << fpp
                                  << ", which is not below -40. "
                                  << "One bundle gives " << params.log2_fpp_per_bin_bundle()
                                  << ", a location may fill " << bundles
                                  << " bin bundles, and a query carries " << receiver << " items.";
            checked++;
        }

        ASSERT_EQ(json_files, checked) << "every parameter set must be checked";
        ASSERT_LE(size_t(30), checked) << "expected to find the shipped parameter sets";
    }
} // namespace APSITests
