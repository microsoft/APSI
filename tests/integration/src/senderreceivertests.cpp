// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <cstdint>
#include <memory>
#include <random>
#include "apsi/logging/log.h"
#include "apsi/network/receiverchannel.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/receiver.h"
#include "apsi/sender.h"
#include "apsi/senderdb.h"
#include "apsi/senderdispatcher.h"
#include "apsi/util/utils.h"
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::receiver;
using namespace apsi::sender;
using namespace apsi::network;
using namespace apsi::util;
using namespace apsi::logging;
using namespace apsi::oprf;
using namespace seal;

namespace
{
    std::pair<vector<Item>, vector<size_t>> rand_subset(const vector<Item> &items, size_t size)
    {
        random_device rd;

        set<size_t> ss;
        while (ss.size() != size)
        {
            ss.emplace(static_cast<size_t>(rd() % items.size()));
        }
        auto ssIter = ss.begin();

        vector<Item> ret(size);
        for (size_t i = 0; i < size; i++)
        {
            ret[i] = items[*ssIter++];
        }
        auto iter = ss.begin();
        vector<size_t> s(size);
        for (size_t i = 0; i < static_cast<size_t>(size); ++i)
        {
            s[i] = *iter++;
        }
        return { ret, s };
    }

    void verify_intersection_results(
        vector<Item> &client_items, size_t intersection_size, pair<vector<bool>, Matrix<unsigned char>> &intersection,
        bool compare_labels, vector<size_t> &label_idx, Matrix<unsigned char> &labels)
    {
        for (size_t i = 0; i < client_items.size(); i++)
        {
            if (i < intersection_size)
            {
                // Item should be in intersection
                ASSERT_EQ(true, (bool)intersection.first[i]);

                if (compare_labels)
                {
                    size_t idx = label_idx[i];
                    int lblcmp = memcmp(intersection.second[i].data(), labels[idx].data(), labels[idx].size());

                    // Label is not the expected value
                    ASSERT_EQ(0, lblcmp);
                }
            }
            else
            {
                // Item should not be in intersection
                ASSERT_EQ(false, (bool)intersection.first[i]);
            }
        }
    }

    void RunTest(size_t senderActualSize, PSIParams &params)
    {
        // Connect the network
        ReceiverChannel recvChl;

        string conn_addr = "tcp://localhost:5550";
        recvChl.connect(conn_addr);

        uint32_t numThreads = thread::hardware_concurrency();

        unique_ptr<Receiver> receiver_ptr;

        auto f = std::async([&]() { receiver_ptr = make_unique<Receiver>(numThreads); });
        shared_ptr<Sender> sender = make_shared<Sender>(params, numThreads);
        f.get();
        Receiver &receiver = *receiver_ptr;

        auto label_bit_length = params.label_bit_count();
        size_t receiverActualSize = 20;
        size_t intersectionSize = 10;

        if (params.use_fast_membership())
        {
            // Only one match
            receiverActualSize = 1;
            intersectionSize = 1;
        }

        auto s1 = vector<Item>(senderActualSize);
        Matrix<unsigned char> labels(senderActualSize, params.label_byte_count());
        for (size_t i = 0; i < s1.size(); i++)
        {
            s1[i] = i;

            if (label_bit_length)
            {
                memset(labels[i].data(), 0, labels[i].size());

                labels[i][0] = static_cast<unsigned char>(i);
                labels[i][1] = static_cast<unsigned char>(i >> 8);
            }
        }

        auto cc1 = rand_subset(s1, intersectionSize);
        auto &c1 = cc1.first;

        c1.reserve(receiverActualSize);
        for (size_t i = 0; i < seal::util::sub_safe(receiverActualSize, intersectionSize); ++i)
            c1.emplace_back(i + s1.size());

        shared_ptr<OPRFKey> oprf_key;

        shared_ptr<UniformRandomGeneratorFactory> rng_factory(make_shared<BlakePRNGFactory>());
        oprf_key = make_shared<OPRFKey>(rng_factory);

        OPRFSender::ComputeHashes(s1, *oprf_key);

        shared_ptr<SenderDB> sender_db = make_shared<SenderDB>(params);
        sender_db->load_db(numThreads, s1, labels);

        atomic<bool> stop_sender = false;

        auto thrd = thread([&]() {
            SenderDispatcher dispatcher(sender);
            dispatcher.run(stop_sender, /* port */ 5550, oprf_key, sender_db);
        });

        receiver.handshake(recvChl);
        auto intersection = receiver.query(c1, recvChl);
        stop_sender = true;
        thrd.join();

        // Done with everything. Print the results!
        verify_intersection_results(c1, intersectionSize, intersection, label_bit_length > 0, cc1.second, labels);
    }

    PSIParams create_params(size_t sender_set_size, bool use_labels, bool fast_membership)
    {
        Log::set_log_level(Log::Level::level_error);

        PSIParams::PSIConfParams psiconf_params;
        psiconf_params.item_bit_count = 60;
        psiconf_params.sender_size = sender_set_size;
        psiconf_params.use_labels = use_labels;
        psiconf_params.use_fast_membership = fast_membership;

        // TODO: Remove sender_bin_size so this is not needed
        psiconf_params.sender_bin_size = 2 * sender_set_size / (1 << 9) + 100;

        psiconf_params.num_chunks = 1;
        psiconf_params.item_bit_length_used_after_oprf = 120;

        PSIParams::CuckooParams cuckoo_params;
        cuckoo_params.hash_func_count = 2;
        cuckoo_params.hash_func_seed = 0;
        cuckoo_params.max_probe = 100;

        PSIParams::TableParams table_params;
        table_params.binning_sec_level = 40;
        table_params.log_table_size = 9;
        table_params.split_count = 1;
        table_params.split_size = 16;
        table_params.window_size = 2;

        PSIParams::SEALParams seal_params;
        seal_params.encryption_params.set_poly_modulus_degree(4096);
        seal_params.max_supported_degree = 2;

        vector<Modulus> coeff_modulus = CoeffModulus::Create(4096, { 49, 40, 20 });
        seal_params.encryption_params.set_coeff_modulus(coeff_modulus);
        seal_params.encryption_params.set_plain_modulus(40961);

        PSIParams::FFieldParams ffield_params;
        ffield_params.characteristic = seal_params.encryption_params.plain_modulus().value();
        ffield_params.degree = 8;

        PSIParams params(psiconf_params, table_params, cuckoo_params, seal_params, ffield_params);
        return params;
    }
} // namespace

namespace APSITests
{
    TEST(SenderReceiverTests, LabelsSmallTest)
    {
        size_t senderActualSize = 100;
        PSIParams params = create_params(senderActualSize, /* use_labels */ true, /* fast_membership */ false);
        RunTest(senderActualSize, params);
    }

    TEST(SenderReceiverTests, NoLabels64KTest)
    {
        size_t senderActualSize = 65536;
        PSIParams params = create_params(senderActualSize, /* use_label */ false, /* fast_membership */ false);
        RunTest(senderActualSize, params);
    }

    TEST(SenderReceiverTests, DISABLED_LabelsTest)
    {
        size_t senderActualSize = 2000;
        PSIParams params = create_params(senderActualSize, /* use_labels */ true, /* fast_membership */ false);
        RunTest(senderActualSize, params);
    }

    TEST(SenderReceiverTests, NoLabels3KTest)
    {
        size_t senderActualSize = 3000;
        PSIParams params = create_params(senderActualSize, /* use_labels */ false, /* fast_membership */ false);
        RunTest(senderActualSize, params);
    }

    TEST(SenderReceiverTests, NoLabelsFastMembershipTest)
    {
        size_t senderActualSize = 3000;
        PSIParams params = create_params(senderActualSize, /* use_labels */ false, /* fast_membership */ true);
        RunTest(senderActualSize, params);
    }

    TEST(SenderReceiverTests, DISABLED_LabelsFastMembership)
    {
        size_t senderActualSize = 3000;
        PSIParams params = create_params(senderActualSize, /* use_labels */ true, /* fast_membership */ true);
        RunTest(senderActualSize, params);
    }
} // namespace APSITests
