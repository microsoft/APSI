// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstdint>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

// APSI
#include "apsi/network/sender_operation_response.h"
#include "apsi/network/stream_channel.h"

// SEAL
#include "seal/modulus.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::network;

namespace APSITests {
    namespace {
        /**
        Returns, in hexadecimal, what a StreamChannel writes for a parameter response holding the
        given parameters.
        */
        string sent_params_response_hex(const PSIParams &params)
        {
            stringstream ss;
            StreamChannel channel(ss);
            auto response = make_unique<SenderOperationResponseParms>();
            response->params = make_unique<PSIParams>(params);
            channel.send(std::move(response));

            ostringstream out;
            out << hex << setfill('0');
            for (char byte : ss.str()) {
                out << setw(2) << static_cast<unsigned>(static_cast<unsigned char>(byte));
            }
            return out.str();
        }
    } // namespace

    TEST(SenderOperationResponseTest, SaveLoadSenderOperationResponseParms)
    {
        SenderOperationResponseParms sopr;
        ASSERT_EQ(SenderOperationType::sop_parms, sopr.type());
        ASSERT_FALSE(sopr.params);

        stringstream ss;

        // Cannot save if parameters are not set
        ASSERT_THROW(sopr.save(ss), logic_error);

        // Create valid parameters
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
        seal_params.set_coeff_modulus(CoeffModulus::Create(pmd, { 40, 40, 40 }));
        seal_params.set_plain_modulus(65537);

        sopr.params = make_unique<PSIParams>(item_params, table_params, query_params, seal_params);
        auto out_size = sopr.save(ss);

        SenderOperationResponseParms sopr2;
        size_t in_size = sopr2.load(ss);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::sop_parms, sopr2.type());

        // Check that the parameters match
        ASSERT_EQ(
            sopr.params->item_params().felts_per_item, sopr2.params->item_params().felts_per_item);
        ASSERT_EQ(
            sopr.params->table_params().hash_func_count,
            sopr2.params->table_params().hash_func_count);
        ASSERT_EQ(
            sopr.params->table_params().max_items_per_bin,
            sopr2.params->table_params().max_items_per_bin);
        ASSERT_EQ(sopr.params->table_params().table_size, sopr2.params->table_params().table_size);
        ASSERT_EQ(
            sopr.params->query_params().query_powers.size(),
            sopr2.params->query_params().query_powers.size());
        ASSERT_TRUE(equal(
            sopr.params->query_params().query_powers.cbegin(),
            sopr.params->query_params().query_powers.cend(),
            sopr2.params->query_params().query_powers.cbegin()));
        ASSERT_EQ(sopr.params->seal_params(), sopr2.params->seal_params());
    }

    TEST(SenderOperationResponseTest, ParamsResponseWithoutMatchTagsIsAsInAPSI1x)
    {
        // For parameters without match tags, a sender sends the parameter response APSI 1.x sends,
        // so that a receiver of APSI 1.x or older that takes its parameters from the sender can
        // read them. The expected bytes are what a StreamChannel of APSI 1.1.0 writes for a
        // SenderOperationResponseParms holding each parameter set below: a SenderOperationHeader,
        // and then the response. They were recorded with APSI 1.1.0's code built with Microsoft
        // SEAL 4.6.1 and FlatBuffers 25.12.19, and are the same with Microsoft SEAL 4.7. Like
        // Microsoft SEAL 4.0, Microsoft SEAL 4.7 records the serialization format version, 4.0,
        // in each Microsoft SEAL header; built with Microsoft SEAL 4.4, APSI 1.1.0 sends the same
        // bytes, except that each such header records 4.4. A version of Microsoft SEAL or
        // FlatBuffers that serializes any of this differently calls for recording the bytes again.
        //
        // Nothing here depends on the platform: the query powers are written in increasing order,
        // and the encryption parameters are saved without compression. The primes are those
        // CoeffModulus::Create gives for the bit counts in the files, spelled out so that the
        // bytes do not depend on how Microsoft SEAL chooses primes.

        // APSI 1.x's parameters/1M-1.json: one hash function, query powers 1 to 55 without
        // Paterson-Stockmeyer, and a single prime, 2^48 - 2^14 + 1
        PSIParams::ItemParams item_params;
        item_params.felts_per_item = 5;

        PSIParams::TableParams table_params;
        table_params.hash_func_count = 1;
        table_params.max_items_per_bin = 55;
        table_params.table_size = 409;

        PSIParams::QueryParams query_params;
        for (uint32_t power = 1; power <= 55; power++) {
            query_params.query_powers.insert(power);
        }

        PSIParams::SEALParams seal_params;
        seal_params.set_poly_modulus_degree(2048);
        seal_params.set_coeff_modulus({ Modulus(0xffffffffc001) });
        seal_params.set_plain_modulus(65537);

        ASSERT_EQ(
            "180000000c00000008000c0008000400080000000100000001000000b80100000c00000008000a00"
            "09000400080000000c00000000010600080004000600000004000000900100008c01000014000000"
            "00000e0022001c0018000c00080004000e0000002400000088000000990100003700000001000000"
            "050000000100000000000600080004000600000004000000510000005ea110040000000051000000"
            "0000000001000800000000000001000000000000005ea1100400000000180000000000000001c0ff"
            "ffffff00005ea1100400000000180000000000000001000100000000000000000800080000000400"
            "08000000040000003700000001000000020000000300000004000000050000000600000007000000"
            "08000000090000000a0000000b0000000c0000000d0000000e0000000f0000001000000011000000"
            "12000000130000001400000015000000160000001700000018000000190000001a0000001b000000"
            "1c0000001d0000001e0000001f000000200000002100000022000000230000002400000025000000"
            "260000002700000028000000290000002a0000002b0000002c0000002d0000002e0000002f000000"
            "3000000031000000320000003300000034000000350000003600000037000000",
            sent_params_response_hex({ item_params, table_params, query_params, seal_params }));

        // APSI 1.x's parameters/16M-4096.json: three hash functions, Paterson-Stockmeyer, four
        // primes, and a 23-bit plain modulus
        table_params.hash_func_count = 3;
        table_params.max_items_per_bin = 1304;
        table_params.table_size = 6552;

        query_params.ps_low_degree = 44;
        query_params.query_powers = { 1, 3, 11, 18, 45, 225 };

        seal_params.set_poly_modulus_degree(8192);
        seal_params.set_coeff_modulus(
            { Modulus(0xffffffffffd8001),
              Modulus(0xffffffffffe8001),
              Modulus(0xfffffffffffc001),
              Modulus(0x3ff0001) });
        seal_params.set_plain_modulus(4423681);

        ASSERT_EQ(
            "180000000c00000008000c0008000400080000000100000001000000400100000c00000008000a00"
            "09000400080000000c00000000010600080004000600000004000000180100001401000014000000"
            "00000e0022001c0018000c00080004000e00000024000000d0000000981900001805000003000000"
            "050000000100000000000600080004000600000004000000990000005ea110040000000099000000"
            "0000000001002000000000000004000000000000005ea110040000000018000000000000000180fd"
            "ffffffff0f5ea110040000000018000000000000000180feffffffff0f5ea1100400000000180000"
            "000000000001c0ffffffffff0f5ea110040000000018000000000000000100ff03000000005ea110"
            "04000000001800000000000000018043000000000000000008000c0004000800080000002c000000"
            "040000000600000001000000030000000b000000120000002d000000e1000000",
            sent_params_response_hex({ item_params, table_params, query_params, seal_params }));
    }

    TEST(SenderOperationResponseTest, SaveLoadSenderOperationResponseOPRF)
    {
        SenderOperationResponseOPRF sopr;
        ASSERT_EQ(SenderOperationType::sop_oprf, sopr.type());
        ASSERT_TRUE(sopr.data.empty());

        stringstream ss;

        // Save with no data
        auto out_size = sopr.save(ss);
        SenderOperationResponseOPRF sopr2;
        size_t in_size = sopr2.load(ss);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::sop_oprf, sopr2.type());
        ASSERT_TRUE(sopr2.data.empty());

        sopr.data.push_back(0xAB);
        out_size = sopr.save(ss);
        in_size = sopr2.load(ss);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::sop_oprf, sopr2.type());
        ASSERT_EQ(1, sopr2.data.size());
        ASSERT_EQ(static_cast<char>(0xAB), static_cast<char>(sopr2.data[0]));

        sopr.data.push_back(0xEF);
        out_size = sopr.save(ss);
        in_size = sopr2.load(ss);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::sop_oprf, sopr2.type());
        ASSERT_EQ(2, sopr2.data.size());
        ASSERT_EQ(static_cast<char>(0xAB), static_cast<char>(sopr2.data[0]));
        ASSERT_EQ(static_cast<char>(0xEF), static_cast<char>(sopr2.data[1]));
    }

    TEST(SenderOperationResponseTest, SaveLoadSenderOperationResponseQuery)
    {
        SenderOperationResponseQuery sopr;
        ASSERT_EQ(SenderOperationType::sop_query, sopr.type());

        stringstream ss;

        sopr.package_count = 0;
        auto out_size = sopr.save(ss);
        SenderOperationResponseQuery sopr2;
        size_t in_size = sopr2.load(ss);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::sop_query, sopr2.type());
        ASSERT_EQ(sopr.package_count, sopr2.package_count);

        sopr.package_count = 1;
        out_size = sopr.save(ss);
        in_size = sopr2.load(ss);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::sop_query, sopr2.type());
        ASSERT_EQ(sopr.package_count, sopr2.package_count);

        sopr.package_count = 5;
        out_size = sopr.save(ss);
        in_size = sopr2.load(ss);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::sop_query, sopr2.type());
        ASSERT_EQ(sopr.package_count, sopr2.package_count);
    }
} // namespace APSITests
