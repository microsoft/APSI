// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <array>
#include <memory>
#include <unordered_set>
#include <vector>

// APSI
#include "apsi/oprf/oprf_receiver.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/randomgen.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::oprf;

namespace APSITests {
    TEST(OPRFTests, OPRFKeyCreate)
    {
        // Creates a random key
        OPRFKey oprf_key;

        // Set the key to zero
        oprf_key.clear();
        auto oprf_key_span = oprf_key.key_span();
        ASSERT_TRUE(
            all_of(oprf_key_span.begin(), oprf_key_span.end(), [](auto a) { return a == 0; }));

        // Create some new random keys
        oprf_key.create();
        ASSERT_FALSE(
            all_of(oprf_key_span.begin(), oprf_key_span.end(), [](auto a) { return a == 0; }));
        OPRFKey oprf_key2;
        auto oprf_key2_span = oprf_key2.key_span();
        ASSERT_FALSE(
            all_of(oprf_key2_span.begin(), oprf_key2_span.end(), [](auto a) { return a == 0; }));
        ASSERT_FALSE(equal(oprf_key_span.begin(), oprf_key_span.end(), oprf_key2_span.begin()));
    }

    TEST(OPRFTests, OPRFKeySaveLoad)
    {
        OPRFKey oprf_key;
        stringstream ss;
        oprf_key.save(ss);
        OPRFKey oprf_key2;
        oprf_key2.load(ss);

        auto oprf_key_span = oprf_key.key_span();
        auto oprf_key2_span = oprf_key2.key_span();
        ASSERT_TRUE(equal(oprf_key_span.begin(), oprf_key_span.end(), oprf_key2_span.begin()));
    }

    TEST(OPRFTests, OPRFOperation)
    {
        size_t item_count = 100;
        vector<Item> items;

        shared_ptr<UniformRandomGeneratorFactory> rng_factory(make_shared<Blake2xbPRNGFactory>());
        auto rng = rng_factory->create();
        for (size_t i = 0; i < item_count; i++) {
            Item it;
            rng->generate(sizeof(Item), it.get_as<seal_byte>().data());
            items.push_back(move(it));
        }

        // Create random key
        OPRFKey oprf_key;

        vector<HashedItem> out_items = OPRFSender::ComputeHashes(items, oprf_key);

        vector<Item> items_vec(items.begin(), items.end());
        OPRFReceiver receiver(items_vec);
        auto query = receiver.query_data();

        vector<unsigned char> responses = OPRFSender::ProcessQueries(query, oprf_key);

        vector<HashedItem> receiver_hashes(item_count);
        vector<LabelKey> label_keys(item_count);
        receiver.process_responses(responses, receiver_hashes, label_keys);

        for (auto &recv_hash : receiver_hashes) {
            bool found = out_items.end() !=
                         find_if(out_items.begin(), out_items.end(), [&](HashedItem &item) {
                             return item == recv_hash;
                         });
            ASSERT_TRUE(found);
        }
    }

    TEST(OPRFTests, Hash2Curve)
    {
        {
            std::array<unsigned char, 1> val{ 0 };
            ECPoint pt(val);
            std::array<unsigned char, ECPoint::save_size> buf;
            pt.save(buf);
            uint64_t w1 = *reinterpret_cast<uint64_t *>(buf.data());
            uint64_t w2 = *reinterpret_cast<uint64_t *>(buf.data() + 8);
            uint64_t w3 = *reinterpret_cast<uint64_t *>(buf.data() + 16);
            uint64_t w4 = *reinterpret_cast<uint64_t *>(buf.data() + 24);

            ASSERT_EQ(16185258159125907415ULL, w1);
            ASSERT_EQ(4603673558532365532ULL, w2);
            ASSERT_EQ(16070562417338412736ULL, w3);
            ASSERT_EQ(16055866365372562508ULL, w4);
        }
        {
            std::array<unsigned char, 2> val{ 0, 0 };
            ECPoint pt(val);
            std::array<unsigned char, ECPoint::save_size> buf;
            pt.save(buf);
            uint64_t w1 = *reinterpret_cast<uint64_t *>(buf.data());
            uint64_t w2 = *reinterpret_cast<uint64_t *>(buf.data() + 8);
            uint64_t w3 = *reinterpret_cast<uint64_t *>(buf.data() + 16);
            uint64_t w4 = *reinterpret_cast<uint64_t *>(buf.data() + 24);

            ASSERT_EQ(1351976583327153065ULL, w1);
            ASSERT_EQ(6824769698500631404ULL, w2);
            ASSERT_EQ(4564688725223058933ULL, w3);
            ASSERT_EQ(17703950788644595294ULL, w4);
        }
        {
            std::array<unsigned char, 16> val{ 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                                               0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0 };
            ECPoint pt(val);
            std::array<unsigned char, ECPoint::save_size> buf;
            pt.save(buf);
            uint64_t w1 = *reinterpret_cast<uint64_t *>(buf.data());
            uint64_t w2 = *reinterpret_cast<uint64_t *>(buf.data() + 8);
            uint64_t w3 = *reinterpret_cast<uint64_t *>(buf.data() + 16);
            uint64_t w4 = *reinterpret_cast<uint64_t *>(buf.data() + 24);

            ASSERT_EQ(14742796689443832496ULL, w1);
            ASSERT_EQ(2501201975610406569ULL, w2);
            ASSERT_EQ(5901317566272664835ULL, w3);
            ASSERT_EQ(15287245637096301833ULL, w4);
        }
    }
} // namespace APSITests
