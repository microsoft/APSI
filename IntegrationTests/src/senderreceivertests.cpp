#include "gtest/gtest.h"
#include <random>
#include <memory>
#include "apsi/sender.h"
#include "apsi/senderdispatcher.h"
#include "apsi/receiver.h"
#include "apsi/network/receiverchannel.h"
#include "apsi/tools/utils.h"
#include "apsi/logging/log.h"
#include "seal/defaultparams.h"


using namespace std;
using namespace apsi;
using namespace apsi::receiver;
using namespace apsi::sender;
using namespace apsi::network;
using namespace apsi::tools;
using namespace apsi::logging;
using namespace seal;


namespace
{
    std::pair<vector<Item>, vector<int>> rand_subset(const vector<Item>& items, int size)
    {
        PRNG prn(zero_block);

        set<int> ss;
        while (ss.size() != size)
        {
            ss.emplace(static_cast<int>(prn.get<unsigned int>() % items.size()));
        }
        auto ssIter = ss.begin();

        vector<Item> ret(size);
        for (int i = 0; i < size; i++)
        {
            ret[i] = items[*ssIter++];
        }
        auto iter = ss.begin();
        vector<int> s(size);
        for (u64 i = 0; i < size; ++i)
        {
            s[i] = *iter++;
        }
        return { ret, s };
    }

	void verify_intersection_results(vector<Item>& client_items, int intersection_size, pair<vector<bool>, Matrix<u8>>& intersection, bool compare_labels, vector<int>& label_idx, Matrix<u8>& labels)
	{
		bool correct = true;
		for (int i = 0; i < client_items.size(); i++)
		{

			if (i < intersection_size)
			{
				// Item should be in intersection
				ASSERT_EQ(true, (bool)intersection.first[i]);

				if (compare_labels)
				{
					auto idx = label_idx[i];
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

	void RunTest(size_t senderActualSize, PSIParams& params)
	{
		Log::set_log_level(Log::Level::level_error);

		// Connect the network
		ReceiverChannel recvChl;

		string conn_addr = "tcp://localhost:5550";
		recvChl.connect(conn_addr);

		unsigned numThreads = thread::hardware_concurrency();

		unique_ptr<Receiver> receiver_ptr;

		auto f = std::async([&]()
			{
				receiver_ptr = make_unique<Receiver>(numThreads, MemoryPoolHandle::New());
			});
		shared_ptr<Sender> sender = make_shared<Sender>(params, numThreads, numThreads, MemoryPoolHandle::New());
		f.get();
		Receiver& receiver = *receiver_ptr;

		auto label_bit_length = params.get_label_bit_count();
		auto recversActualSize = 50;
		auto intersectionSize = 25;

		auto s1 = vector<Item>(senderActualSize);
		Matrix<u8> labels(senderActualSize, params.get_label_byte_count());
		for (int i = 0; i < s1.size(); i++)
		{
			s1[i] = i;

			if (label_bit_length) {
				memset(labels[i].data(), 0, labels[i].size());

				labels[i][0] = i;
				labels[i][1] = (i >> 8);
			}
		}

		auto cc1 = rand_subset(s1, intersectionSize);
		auto& c1 = cc1.first;

		c1.reserve(recversActualSize);
		for (int i = 0; i < (recversActualSize - intersectionSize); ++i)
			c1.emplace_back(i + s1.size());

		sender->load_db(s1, labels);

		atomic<bool> stop_sender = false;

		auto thrd = thread([&]() {
			SenderDispatcher dispatcher(sender);
			dispatcher.run(stop_sender, /* port */ 5550);
			});

		receiver.handshake(recvChl);
		auto intersection = receiver.query(c1, recvChl);
		stop_sender = true;
		thrd.join();

		// Done with everything. Print the results!
		verify_intersection_results(c1, intersectionSize, intersection, label_bit_length > 0, cc1.second, labels);
	}

	PSIParams create_params(size_t sender_set_size, bool use_oprf, bool use_labels)
	{
		PSIParams::PSIConfParams psiconf_params;
		psiconf_params.item_bit_count = 60;
		psiconf_params.sender_size = sender_set_size;
		psiconf_params.use_labels = use_labels;
		psiconf_params.use_oprf = use_oprf;

		PSIParams::CuckooParams cuckoo_params;
		cuckoo_params.hash_func_count = 3;
		cuckoo_params.hash_func_seed = 0;
		cuckoo_params.max_probe = 100;

		PSIParams::TableParams table_params;
		table_params.binning_sec_level = 40;
		table_params.log_table_size = 10;
		table_params.split_count = 128;
		table_params.window_size = 1;

		PSIParams::SEALParams seal_params;
		seal_params.decomposition_bit_count = 30;
		seal_params.encryption_params.set_poly_modulus_degree(4096);

		vector<SmallModulus> coeff_modulus = DefaultParams::coeff_modulus_128(seal_params.encryption_params.poly_modulus_degree());
		seal_params.encryption_params.set_coeff_modulus(coeff_modulus);
		seal_params.encryption_params.set_plain_modulus(0x13ff);

		PSIParams::ExFieldParams exfield_params;
		exfield_params.characteristic = seal_params.encryption_params.plain_modulus().value();
		exfield_params.degree = 8;

		PSIParams params(psiconf_params, table_params, cuckoo_params, seal_params, exfield_params);
		return params;
	}

	void initialize_db(vector<Item>& items, Matrix<u8>& labels, size_t item_count, unsigned label_byte_count)
	{
		items.resize(item_count);
		labels.resize(item_count, label_byte_count);

		for (int i = 0; i < items.size(); i++)
		{
			items[i] = i;

			if (label_byte_count > 0)
			{
				memset(labels[i].data(), 0, labels[i].size());

				labels[i][0] = i;
				labels[i][1] = (i >> 8);
			}
		}
	}

	void initialize_query(std::vector<apsi::Item>& items, size_t item_count)
	{
		items.resize(20);

		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_int_distribution<> dis(0, 20);

		// Elements that should be in the query
		for (int i = 0; i < 10; i++)
		{
			items[i] = dis(gen);
		}

		// Elements that should not be in the query
		for (int i = 10; i < 20; i++)
		{
			items[i] = (item_count + i);
		}
	}
}


namespace APSITests
{
	TEST(SenderReceiverTests, OPRFandLabelsTest)
	{
		size_t senderActualSize = 2000;
		PSIParams params = create_params(senderActualSize, /* use_oprf */ true, /* use_labels */ true);
		RunTest(senderActualSize, params);
	}

	TEST(SenderReceiverTests, OPRFTest)
	{
		size_t senderActualSize = 3000;
		PSIParams params = create_params(senderActualSize, /* use_oprf */ true, /* use_label */ false);
		RunTest(senderActualSize, params);
	}

	TEST(SenderReceiverTests, LabelsTest)
	{
		size_t senderActualSize = 2000;
		PSIParams params = create_params(senderActualSize, /* use_oprf */ false, /* use_labels */ true);
		RunTest(senderActualSize, params);
	}

	TEST(SenderReceiverTests, NoOPRFNoLabelsTest)
	{
		size_t senderActualSize = 3000;
		PSIParams params = create_params(senderActualSize, /* use_oprf */ false, /* use_labels */ false);
		RunTest(senderActualSize, params);
	}
}