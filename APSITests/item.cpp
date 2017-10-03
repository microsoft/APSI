#include "stdafx.h"
#include "CppUnitTest.h"
#include "psiparams.h"
#include "util/exfield.h"
#include "ciphertext.h"
#include <vector>
#include <map>
#include "item.h"
#include "cuckoo.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace apsi;
using namespace seal::util;
using namespace std;
using namespace seal;
using namespace cuckoo;

namespace APSITests
{
	TEST_CLASS(ItemTests)
	{
	public:
		TEST_METHOD(TestConstruction)
		{
			Item::set_item_bit_length(4);
			Item item(17);

			Assert::AreEqual(item[0], (uint64_t)1);
			Assert::AreEqual(item[1], (uint64_t)0);
		}

		TEST_METHOD(TestSplits)
		{
			Item item;
			item[0] = 0x3850683f4a;
			item[1] = 0x238bc3df32;

			Assert::AreEqual(item.item_part(0, 12), (uint64_t)0xf4a);
			Assert::AreEqual(item.item_part(3, 12), (uint64_t)0x3);
			Assert::AreEqual(item.item_part(5, 12), (uint64_t)0x320);
			Assert::AreEqual(item.item_part(7, 12), (uint64_t)0x8bc);
		}

		TEST_METHOD(TestConversion)
		{
			Item::set_reduced_bit_length(128);
			Item item;
			item[0] = 0x3850683f4a;
			item[1] = 0x238bc3df32;

			shared_ptr<ExField> field = ExField::Acquire(0x1e01, string("1x^16 + 3e"));

			ExFieldElement e = item.to_exfield_element(field);

			ExFieldElement e_manual(field, "23x^8 + 8bcx^7 + 3dfx^6 + 320x^5 + 3x^3 + 850x^2 + 683x^1 + f4a");

			Assert::IsTrue(e == e_manual);
		}

		TEST_METHOD(TestPermutationHashing)
		{
			Item item;
			item[0] = 0x238bc3df32U;
			item[1] = 0xbd23763850683f4aU;

			PermutationBasedCuckoo cuckoo(3, 0, 12, 120, 1000);

			Item new_item = item.itemL(cuckoo, 0);

			Assert::AreEqual(new_item[0], 0xf4a000000238bc3dU);
			Assert::AreEqual(new_item[1], (uint64_t)0x23763850683U);

			new_item = item.itemL(cuckoo, 1);
			Assert::AreEqual(new_item[0], 0xf4a000000238bc3dU);
			Assert::AreEqual(new_item[1], (uint64_t)0x123763850683U);

			new_item = item.itemL(cuckoo, 2);
			Assert::AreEqual(new_item[0], 0xf4a000000238bc3dU);
			Assert::AreEqual(new_item[1], (uint64_t)0x223763850683U);
		}
	};
}