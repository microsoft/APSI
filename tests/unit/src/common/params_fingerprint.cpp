// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>
#include <cstddef>
#include <cstdint>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// APSI
#include "apsi/psi_params.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/modulus.h"
#include "seal/util/blake2.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace seal;

namespace APSITests {
    namespace {
        PSIParams::Fingerprint fingerprint_from_hex(const string &hex)
        {
            PSIParams::Fingerprint fingerprint{};
            if (hex.size() != 2 * fingerprint.size()) {
                throw invalid_argument("hex has the wrong length");
            }
            for (size_t i = 0; i < fingerprint.size(); i++) {
                fingerprint[i] =
                    static_cast<unsigned char>(stoul(hex.substr(2 * i, 2), nullptr, 16));
            }
            return fingerprint;
        }

        struct ParamsValues {
            uint32_t felts_per_item = 8;
            uint32_t tag_part_count = 0;
            uint32_t table_size = 512;
            uint32_t max_items_per_bin = 16;
            uint32_t hash_func_count = 3;
            uint32_t ps_low_degree = 0;
            set<uint32_t> query_powers{ 1, 3, 5 };
            size_t poly_modulus_degree = 4096;
            uint64_t plain_modulus = 65537;

            // CoeffModulus::BFVDefault(4096), spelled out so that the known answers below do not
            // depend on how Microsoft SEAL chooses primes
            vector<uint64_t> coeff_modulus{ 0xffffee001, 0xffffc4001, 0x1ffffe0001 };
        };

        PSIParams make_params(const ParamsValues &values)
        {
            PSIParams::ItemParams item_params;
            item_params.felts_per_item = values.felts_per_item;
            item_params.tag_part_count = values.tag_part_count;

            PSIParams::TableParams table_params;
            table_params.table_size = values.table_size;
            table_params.max_items_per_bin = values.max_items_per_bin;
            table_params.hash_func_count = values.hash_func_count;

            PSIParams::QueryParams query_params;
            query_params.ps_low_degree = values.ps_low_degree;
            query_params.query_powers = values.query_powers;

            PSIParams::SEALParams seal_params;
            seal_params.set_poly_modulus_degree(values.poly_modulus_degree);
            vector<Modulus> coeff_modulus;
            coeff_modulus.reserve(values.coeff_modulus.size());
            for (uint64_t prime : values.coeff_modulus) {
                coeff_modulus.emplace_back(prime);
            }
            seal_params.set_coeff_modulus(coeff_modulus);
            seal_params.set_plain_modulus(values.plain_modulus);

            return { item_params, table_params, query_params, seal_params };
        }
    } // namespace

    TEST(PSIParamsFingerprintTest, KnownAnswer)
    {
        // The canonical encoding of the default ParamsValues, as PSIParams::fingerprint documents
        // it: "apsi.params.fingerprint.v1", then the format version 1, felts_per_item 8,
        // tag_part_count 0, table_size 512, max_items_per_bin 16, hash_func_count 3, ps_low_degree
        // 0, three query powers 1, 3, and 5, the BFV scheme 1, poly_modulus_degree 4096, plain
        // modulus 65537, and three primes 0xffffee001, 0xffffc4001, and 0x1ffffe0001. The expected
        // hashes were computed independently of APSI, with Python's
        // hashlib.blake2b(digest_size=32).
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
        const unsigned char encoding[] = {
            0x61, 0x70, 0x73, 0x69, 0x2e, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x2e, 0x66,
            0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x2e, 0x76, 0x31,
            0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
            0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x01, 0xe0, 0xfe, 0xff, 0x0f, 0x00, 0x00, 0x00, 0x01, 0x40, 0xfc, 0xff, 0x0f,
            0x00, 0x00, 0x00, 0x01, 0x00, 0xfe, 0xff, 0x1f, 0x00, 0x00, 0x00,
        };
        PSIParams::Fingerprint expected = fingerprint_from_hex(
            "a62c976dfd067d67348dae67864b292df4b6d157ae32b38efdc24c9492e21833");

        // The hash is Blake2b with a 32-byte output, which is not the same as a truncated
        // Blake2b-512
        PSIParams::Fingerprint hash{};
        ASSERT_EQ(
            0, APSI_blake2b(hash.data(), hash.size(), encoding, sizeof(encoding), nullptr, 0));
        ASSERT_EQ(expected, hash);

        ASSERT_EQ(expected, make_params(ParamsValues{}).fingerprint());

        // parameters/16M-4096.json: Paterson-Stockmeyer, four primes, and a 23-bit plain modulus
        ParamsValues values;
        values.felts_per_item = 5;
        values.table_size = 6552;
        values.max_items_per_bin = 1304;
        values.hash_func_count = 3;
        values.ps_low_degree = 44;
        values.query_powers = { 1, 3, 11, 18, 45, 225 };
        values.poly_modulus_degree = 8192;
        values.plain_modulus = 4423681;
        values.coeff_modulus = {
            0xffffffffffd8001, 0xffffffffffe8001, 0xfffffffffffc001, 0x3ff0001
        };
        ASSERT_EQ(
            fingerprint_from_hex(
                "933e44afa624b6cc83a5918dbf9591c8e17b86f9a2714ee432abcb2f217ec00c"),
            make_params(values).fingerprint());

        // With match tags the format version is 2 and the tag part count is encoded. These are the
        // parameters of the default ParamsValues with one tag part, and a set with one field
        // element per item and three tag parts: table_size 2048, max_items_per_bin 35, one hash
        // function, query powers 1 through 35, poly_modulus_degree 2048, plain modulus 65537, and
        // the 48-bit prime 2^48 - 2^14 + 1.
        values = {};
        values.tag_part_count = 1;
        ASSERT_EQ(
            fingerprint_from_hex(
                "8850757a96412d51695a0ded225cdab4b4b98106e5359d6c0904f7cd73e2d66c"),
            make_params(values).fingerprint());

        values = {};
        values.felts_per_item = 1;
        values.tag_part_count = 3;
        values.table_size = 2048;
        values.max_items_per_bin = 35;
        values.hash_func_count = 1;
        values.query_powers.clear();
        for (uint32_t power = 1; power <= 35; power++) {
            values.query_powers.insert(power);
        }
        values.poly_modulus_degree = 2048;
        values.coeff_modulus = { 0xffffffffc001 };
        ASSERT_EQ(
            fingerprint_from_hex(
                "48169e1e8706284a8fbbf85f083d2072cfa66f3f56b96c0fbca54412b730db98"),
            make_params(values).fingerprint());
    }

    TEST(PSIParamsFingerprintTest, IsDeterministic)
    {
        PSIParams params = make_params(ParamsValues{});
        PSIParams::Fingerprint fingerprint = params.fingerprint();

        ASSERT_EQ(fingerprint, params.fingerprint());
        ASSERT_EQ(fingerprint, make_params(ParamsValues{}).fingerprint());

        ASSERT_EQ(fingerprint, PSIParams(params).fingerprint());

        stringstream ss;
        params.save(ss);
        ASSERT_EQ(fingerprint, PSIParams::Load(ss).first.fingerprint());

        // CoeffModulus::Create puts the two 36-bit primes in the opposite order to
        // CoeffModulus::BFVDefault, so these parameters are not the ones above
        string json = R"({
            "table_params": { "hash_func_count": 3, "table_size": 512, "max_items_per_bin": 16 },
            "item_params": { "felts_per_item": 8 },
            "query_params": { "ps_low_degree": 0, "query_powers": [ 1, 3, 5 ] },
            "seal_params": {
                "plain_modulus": 65537,
                "poly_modulus_degree": 4096,
                "coeff_modulus_bits": [ 36, 36, 37 ]
            }
        })";
        ParamsValues values;
        values.coeff_modulus = { 0xffffc4001, 0xffffee001, 0x1ffffe0001 };
        PSIParams from_json = PSIParams::Load(json);
        ASSERT_EQ(make_params(values).fingerprint(), from_json.fingerprint());
        ASSERT_NE(fingerprint, from_json.fingerprint());
    }

    TEST(PSIParamsFingerprintTest, DistinguishesEveryParameter)
    {
        // Each pair differs in exactly one value. Some pairs need a value other than the default
        // in both members for both to be valid. The scheme is always BFV.
        vector<pair<ParamsValues, ParamsValues>> pairs;
        ParamsValues a;
        ParamsValues b;

        // tag_part_count, and with it the format version
        a = {};
        b = a;
        b.tag_part_count = 1;
        pairs.emplace_back(a, b);

        a = {};
        a.tag_part_count = 1;
        b = a;
        b.tag_part_count = 2;
        pairs.emplace_back(a, b);

        // felts_per_item; 299520 is a multiple of both 4096 / 8 = 512 and floor(4096 / 7) = 585
        a = {};
        a.table_size = 299520;
        b = a;
        b.felts_per_item = 7;
        pairs.emplace_back(a, b);

        a = {};
        b = a;
        b.table_size = 1024;
        pairs.emplace_back(a, b);

        a = {};
        b = a;
        b.max_items_per_bin = 17;
        pairs.emplace_back(a, b);

        a = {};
        b = a;
        b.hash_func_count = 2;
        pairs.emplace_back(a, b);

        a = {};
        b = a;
        b.ps_low_degree = 4;
        pairs.emplace_back(a, b);

        a = {};
        b = a;
        b.query_powers = { 1, 3, 4 };
        pairs.emplace_back(a, b);

        a = {};
        b = a;
        b.query_powers = { 1, 3, 5, 7 };
        pairs.emplace_back(a, b);

        // Two of the default primes are congruent to 1 modulo 2 * 8192 as well
        a = {};
        a.table_size = 1024;
        a.coeff_modulus = { 0xffffc4001, 0x1ffffe0001 };
        b = a;
        b.poly_modulus_degree = 8192;
        pairs.emplace_back(a, b);

        a = {};
        b = a;
        b.plain_modulus = 40961;
        pairs.emplace_back(a, b);

        a = {};
        b = a;
        b.coeff_modulus = { 0xffffc4001, 0xffffee001, 0x1ffffe0001 };
        pairs.emplace_back(a, b);

        a = {};
        b = a;
        b.coeff_modulus = { 0xffffee001, 0x1ffffe0001 };
        pairs.emplace_back(a, b);

        set<PSIParams::Fingerprint> distinct{ make_params(ParamsValues{}).fingerprint() };
        for (const auto &p : pairs) {
            PSIParams::Fingerprint first = make_params(p.first).fingerprint();
            PSIParams::Fingerprint second = make_params(p.second).fingerprint();
            ASSERT_NE(first, second);
            distinct.insert(second);
        }

        // The second members differ from each other and from the defaults, too
        ASSERT_EQ(pairs.size() + 1, distinct.size());
    }

    TEST(PSIParamsFingerprintTest, DoesNotDependOnTheSerialization)
    {
        // Microsoft SEAL 4.4 wrote its library version into the headers of the encryption
        // parameters, where later versions write the serialization format version. Parameters
        // that a SenderDB saved with one and a receiver loaded with the other must still have the
        // same fingerprint.
        PSIParams params = make_params(ParamsValues{});
        stringstream ss;
        params.save(ss);
        string saved = ss.str();

        string rewritten = saved;
        size_t seal_header_count = 0;
        for (size_t i = 0; i + 5 <= rewritten.size(); i++) {
            // Magic number 0xA15E, header size 0x10, version 4.0
            if (rewritten.compare(i, 5, string("\x5e\xa1\x10\x04\x00", 5)) == 0) {
                rewritten[i + 4] = 0x04;
                seal_header_count++;
            }
        }
        // One for the encryption parameters, one for each of the three primes, and one for the
        // plain modulus
        ASSERT_EQ(size_t(5), seal_header_count);
        ASSERT_NE(saved, rewritten);

        stringstream rewritten_ss(rewritten);
        PSIParams loaded = PSIParams::Load(rewritten_ss).first;
        ASSERT_EQ(params.fingerprint(), loaded.fingerprint());
    }
} // namespace APSITests
