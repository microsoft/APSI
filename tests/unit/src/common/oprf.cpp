// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <array>
#include <memory>

// APSI
#include "apsi/oprf/oprf_receiver.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/randomgen.h"

#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::oprf;

namespace APSITests
{
    TEST(OPRFTests, OPRFKeyCreate)
    {
        // Creates a random key
        OPRFKey oprf_key;

        // Set the key to zero
        oprf_key.clear();
        auto oprf_key_span = oprf_key.key_span();
        ASSERT_TRUE(all_of(oprf_key_span.begin(), oprf_key_span.end(), [](auto a) { return a == 0; }));

        // Create some new random keys
        oprf_key.create();
        ASSERT_FALSE(all_of(oprf_key_span.begin(), oprf_key_span.end(), [](auto a) { return a == 0; }));
        OPRFKey oprf_key2;
        auto oprf_key2_span = oprf_key2.key_span();
        ASSERT_FALSE(all_of(oprf_key2_span.begin(), oprf_key2_span.end(), [](auto a) { return a == 0; }));
        ASSERT_FALSE(equal(oprf_key_span.begin(), oprf_key_span.end(), oprf_key2_span.begin()));

        // Set up seeded PRNG
        shared_ptr<UniformRandomGeneratorFactory> rg =
            make_shared<BlakePRNGFactory>(random_seed_type{ 0, 1, 2, 3, 4, 5, 6, 7 });
        OPRFKey oprf_key3(rg);
        auto oprf_key3_span = oprf_key3.key_span();
        OPRFKey oprf_key4(rg);
        auto oprf_key4_span = oprf_key4.key_span();
        ASSERT_FALSE(all_of(oprf_key3_span.begin(), oprf_key3_span.end(), [](auto a) { return a == 0; }));
        ASSERT_FALSE(all_of(oprf_key4_span.begin(), oprf_key4_span.end(), [](auto a) { return a == 0; }));
        ASSERT_TRUE(equal(oprf_key3_span.begin(), oprf_key3_span.end(), oprf_key4_span.begin()));
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
        int item_count = 100;
        vector<Item> items;

        shared_ptr<UniformRandomGeneratorFactory> rng_factory(make_shared<BlakePRNGFactory>());
        auto rng = rng_factory->create();
        for (auto i = 0; i < item_count; i++)
        {
            Item it;
            rng->generate(sizeof(Item), reinterpret_cast<seal_byte *>(it.data()));
            items.emplace_back(move(it));
        }

        // Create random key
        OPRFKey oprf_key(rng_factory);

        vector<HashedItem> out_items(item_count);
        OPRFSender::ComputeHashes(items, oprf_key, out_items);

        vector<seal_byte> query(item_count * oprf_query_size);
        OPRFReceiver receiver(items, query);

        vector<seal_byte> responses(item_count * oprf_response_size);
        OPRFSender::ProcessQueries(query, oprf_key, responses);

        vector<HashedItem> receiver_hashes(item_count);
        receiver.process_responses(responses, receiver_hashes);

        for (auto i = 0; i < item_count; i++)
        {
            ASSERT_EQ(out_items[i][0], receiver_hashes[i][0]);
            ASSERT_EQ(out_items[i][1], receiver_hashes[i][1]);
        }
    }
} // namespace APSITests
