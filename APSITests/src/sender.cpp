// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// #include "stdafx.h"
// #include "CppUnitTest.h"
// #include "psiparams.h"
// #include "Receiver/receiver.h"
// #include "Sender/sender.h"
// #include "seal/util/exfield.h"
// #include "seal/ciphertext.h"
// #include <vector>
// #include <map>

// using namespace Microsoft::VisualStudio::CppUnitTestFramework;
// using namespace apsi;
// using namespace apsi::receiver;
// using namespace apsi::sender;
// using namespace seal::util;
// using namespace std;
// using namespace seal;

// namespace APSITests
// {		
// 	TEST_CLASS(SenderTests)
// 	{
// 	public:
		
// 		TEST_METHOD(TestAllPowers)
// 		{
// 			PSIParams params(8, 8, 1, 8, 32, 4, 8);
// 			Sender sender(params);
// 			Receiver receiver(params);
// 			std::shared_ptr<ExField> ring = receiver.ex_field();
// 			sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
			
// 			vector<ExFieldElement> v1(10);
// 			for (int i = 0; i < 10; i++)
// 				v1[i] = ring->random_element();
// 			map<uint64_t, vector<ExFieldElement>> r1 = receiver.generate_powers(v1);
// 			map<uint64_t, vector<Ciphertext>> enc_r1 = receiver.encrypt(r1);

// 			vector<vector<Ciphertext>> enc_powers;
// 			sender.compute_all_powers(enc_r1, enc_powers);

// 			for (int i = 0; i < enc_powers.size(); i++)
// 			{
// 				for (int j = 0; j < enc_powers[i].size(); j++)
// 					sender.local_session().evaluator_->transform_from_ntt(enc_powers[i][j]);

// 				vector<ExFieldElement> recovered_power = receiver.decrypt(enc_powers[i]);
// 				for (int j = 0; j < 10; j++)
// 					Assert::IsTrue(recovered_power[j] == (v1[j] ^ i));
// 			}

// 		}

// 		TEST_METHOD(TestUpdateDB)
// 		{
// 			PSIParams params(8, 8, 1, 10, 32, 2, 4);
// 			params.set_item_bit_length(32);
// 			params.set_decomposition_bit_count(2);
// 			params.set_log_poly_degree(11);
// 			params.set_exfield_characteristic(0x101);
// 			params.set_exfield_polymod(string("1x^16 + 3"));
// 			params.set_coeff_mod_bit_count(60);
// 			params.validate();
// 			Receiver receiver(params, MemoryPoolHandle::New(true));

// 			Sender sender(params, MemoryPoolHandle::New(true));
// 			sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
// 			sender.set_secret_key(receiver.secret_key());
// 			sender.load_db(vector<Item>{string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h")});

// 			vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);

// 			Assert::IsFalse(intersection[0]);
// 			Assert::IsTrue(intersection[1]);
// 			Assert::IsFalse(intersection[2]);
// 			Assert::IsTrue(intersection[3]);

// 			/* Now we update the database, and precompute again. It should be faster because we only update stale blocks. */
// 			sender.add_data(string("i"));
// 			sender.add_data(string("h")); // duplicated item
// 			sender.add_data(string("x"));
// 			sender.offline_compute();

// 			intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);
// 			Assert::IsFalse(intersection[0]);
// 			Assert::IsTrue(intersection[1]);
// 			Assert::IsTrue(intersection[2]);
// 			Assert::IsTrue(intersection[3]);
// 		}

// 	};
// }