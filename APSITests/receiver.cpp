#include "stdafx.h"
#include "CppUnitTest.h"
#include "psiparams.h"
#include "Receiver/receiver.h"
#include "util/exring.h"
#include "ciphertext.h"
#include <vector>
#include <map>
#include "cuckoo.h"
#include <set>
#include "Sender/sender.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace apsi;
using namespace apsi::receiver;
using namespace apsi::sender;
using namespace seal::util;
using namespace std;
using namespace seal;
using namespace cuckoo;

namespace APSITests
{
	TEST_CLASS(ReceiverTests)
	{
	public:
		TEST_METHOD(TestCuckooHashing)
		{
			PSIParams params(8, 11, 32, 2, 4);
			Receiver receiver(params, MemoryPoolHandle::acquire_new(true));
			vector<Item> data{ string("1"), string("f"), string("i"), string("c") };
			
			unique_ptr<PermutationBasedCuckoo> cuckoo = receiver.cuckoo_hashing(data);

			const uint64_t *null_value = cuckoo->null_value();

			Assert::AreEqual(cuckoo->capacity(), (uint64_t)2048);

			int null_count = 0;
			for (int i = 0; i < 2048; i++)
			{
				const uint64_t *tmp = cuckoo->hash_table_item(i);
				if (tmp[0] == null_value[0] && tmp[1] == null_value[1])
					null_count++;
			}
			Assert::AreEqual(null_count, 2044);

			for(int i = 0; i < 4; i++)
				Assert::IsTrue(cuckoo->query_item(data[i].data()));
		}

		TEST_METHOD(TESTCuckooIndices)
		{
			PSIParams params(8, 11, 32, 2, 4);
			Receiver receiver(params, MemoryPoolHandle::acquire_new(true));
			vector<Item> data{ string("1"), string("f"), string("i"), string("c") };

			unique_ptr<PermutationBasedCuckoo> cuckoo = receiver.cuckoo_hashing(data);

			const uint64_t *null_value = cuckoo->null_value();

			set<int> indices;
			for (int i = 0; i < 2048; i++)
			{
				const uint64_t *tmp = cuckoo->hash_table_item(i);
				if (tmp[0] == null_value[0] && tmp[1] == null_value[1])
					continue;
				indices.emplace(i);
			}

			vector<int> indices2 = receiver.cuckoo_indices(data, *cuckoo);
			Assert::AreEqual(indices.size(), indices2.size());

			set<int> indices3(indices2.begin(), indices2.end());

			Assert::AreEqual(indices.size(), indices3.size());

			for (set<int>::iterator it = indices.begin(); it != indices.end(); it++)
				Assert::AreEqual(indices3.count(*it), (size_t)1);
		}

		TEST_METHOD(TestExRingEncoding)
		{
			PSIParams params(8, 11, 32, 2, 4);
			Receiver receiver(params, MemoryPoolHandle::acquire_new(true));
			vector<Item> data{ string("1"), string("f"), string("i"), string("c") };

			unique_ptr<PermutationBasedCuckoo> cuckoo = receiver.cuckoo_hashing(data);
			vector<ExRingElement> encoded_data = receiver.exring_encoding(*cuckoo);

			Assert::AreEqual(encoded_data.size(), (size_t)2048);

			for (int i = 0; i < 2048; i++)
			{
				const uint64_t *item = cuckoo->hash_table_item(i);
				Item tmp;
				tmp[0] = item[0];
				tmp[1] = item[1];
				Assert::IsTrue(encoded_data[i] == tmp.to_exring_element(receiver.exring()));
			}
		}

		TEST_METHOD(TestGeneratePowers)
		{
			PSIParams params(8, 8, 32, 4, 8);
			Receiver receiver(params);
			std::shared_ptr<ExRing> ring = receiver.exring();

			vector<ExRingElement> v1(10);
			for (int i = 0; i < 10; i++)
				v1[i] = ring->random_element();
			map<uint64_t, vector<ExRingElement>> r1 = receiver.generate_powers(v1);
			for (map<uint64_t, vector<ExRingElement>>::iterator it = r1.begin(); it != r1.end(); it++)
			{
				uint64_t exponent = it->first;
				for (int i = 0; i < it->second.size(); i++)
				{
					Assert::IsTrue(it->second[i] == (v1[i] ^ exponent));
				}
			}

		}

		TEST_METHOD(TestEncryptDecrypt)
		{
			PSIParams params(8, 8, 32, 4, 8);
			Receiver receiver(params);
			shared_ptr<ExRing> ring = receiver.exring();

			vector<ExRingElement> v1(10);
			for (int i = 0; i < 10; i++)
				v1[i] = ring->random_element();
			vector<Ciphertext> enc_v1 = receiver.encrypt(v1);

			vector<ExRingElement> recovered_v1 = receiver.decrypt(enc_v1);
			for (int i = 0; i < 10; i++)
				Assert::IsTrue(v1[i] == recovered_v1[i]);
		}

		TEST_METHOD(TestQuery)
		{
			PSIParams params(8, 8, 32, 2, 4);
			params.set_item_bit_length(32);
			params.set_decomposition_bit_count(2);
			params.set_log_poly_degree(11);
			params.set_exring_characteristic(string("101"));
			params.set_exring_polymod(string("1x^16 + 3"));
			params.set_coeff_mod_bit_count(60);
			params.validate();
			Receiver receiver(params, MemoryPoolHandle::acquire_new(true));

			Sender sender(params, MemoryPoolHandle::acquire_new(true));
			sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
			sender.set_secret_key(receiver.secret_key());
			sender.load_db(vector<Item>{string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h")});

			vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);

			Assert::IsFalse(intersection[0]);
			Assert::IsTrue(intersection[1]);
			Assert::IsFalse(intersection[2]);
			Assert::IsTrue(intersection[3]);
		}
	};
}