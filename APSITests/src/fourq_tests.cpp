
#include "gtest/gtest.h"
#include "apsi/tools/fourq.h"

using namespace std;
using namespace apsi;
using namespace apsi::tools;


namespace
{
	TEST(FourQTests, CreationTest)
	{
		FourQCoordinate coord;

		ASSERT_EQ((u64)0, coord.data()[0]);
		ASSERT_EQ((u64)0, coord.data()[1]);
		ASSERT_EQ((u64)0, coord.data()[2]);
		ASSERT_EQ((u64)0, coord.data()[3]);

		PRNG pp(cc_block);
		FourQCoordinate coord2(pp);

		ASSERT_TRUE(coord2.data()[0] != 0);
		ASSERT_TRUE(coord2.data()[1] != 0);
		ASSERT_TRUE(coord2.data()[2] != 0);
		ASSERT_TRUE(coord2.data()[3] != 0);

		vector<u64> buff = { 1, 2, 3, 4 };

		FourQCoordinate coord3(buff.data());

		ASSERT_EQ(buff[0], coord3.data()[0]);
		ASSERT_EQ(buff[1], coord3.data()[1]);
		ASSERT_EQ(buff[2], coord3.data()[2]);
		ASSERT_EQ(buff[3], coord3.data()[3]);

		// Default copy constructor should work
		FourQCoordinate coord4(coord3);

		ASSERT_EQ(coord3.data()[0], coord4.data()[0]);
		ASSERT_EQ(coord3.data()[1], coord4.data()[1]);
		ASSERT_EQ(coord3.data()[2], coord4.data()[2]);
		ASSERT_EQ(coord3.data()[3], coord4.data()[3]);
	}

	TEST(FourQTests, MultiplicationTest)
	{
		PRNG pp(all_one_block);
		FourQCoordinate coord1(pp);
		FourQCoordinate coord2(pp);
		FourQCoordinate coord1_copy(coord1);

		coord1.multiply_mod_order(coord2);

		ASSERT_TRUE(coord1.data()[0] != coord1_copy.data()[0]);
		ASSERT_TRUE(coord1.data()[1] != coord1_copy.data()[1]);
		ASSERT_TRUE(coord1.data()[2] != coord1_copy.data()[2]);
		ASSERT_TRUE(coord1.data()[3] != coord1_copy.data()[3]);

		coord1_copy.multiply_mod_order(coord2.data());

		ASSERT_EQ(coord1.data()[0], coord1_copy.data()[0]);
		ASSERT_EQ(coord1.data()[1], coord1_copy.data()[1]);
		ASSERT_EQ(coord1.data()[2], coord1_copy.data()[2]);
		ASSERT_EQ(coord1.data()[3], coord1_copy.data()[3]);
	}

	TEST(FourQTests, InversionTest)
	{
		PRNG pp(zero_block);
		FourQCoordinate c1(pp);
		FourQCoordinate c2(pp);
		FourQCoordinate c2_copy(c2);

		FourQCoordinate c1_inv(c1);
		c1_inv.inversion_mod_order();

		c2.multiply_mod_order(c1);

		ASSERT_TRUE(c2.data()[0] != c2_copy.data()[0]);
		ASSERT_TRUE(c2.data()[1] != c2_copy.data()[1]);
		ASSERT_TRUE(c2.data()[2] != c2_copy.data()[2]);
		ASSERT_TRUE(c2.data()[3] != c2_copy.data()[3]);

		c2.multiply_mod_order(c1_inv);

		ASSERT_EQ(c2_copy.data()[0], c2.data()[0]);
		ASSERT_EQ(c2_copy.data()[1], c2.data()[1]);
		ASSERT_EQ(c2_copy.data()[2], c2.data()[2]);
		ASSERT_EQ(c2_copy.data()[3], c2.data()[3]);
	}

	TEST(FourQTests, BufferTest)
	{
		vector<u8> buffer(FourQCoordinate::byte_count());
		PRNG pp(cc_block);
		FourQCoordinate c1(pp);
		FourQCoordinate c2;

		c1.to_buffer(buffer.data());
		c2.from_buffer(buffer.data());

		ASSERT_EQ(c1.data()[0], c2.data()[0]);
		ASSERT_EQ(c1.data()[1], c2.data()[1]);
		ASSERT_EQ(c1.data()[2], c2.data()[2]);
		ASSERT_EQ(c1.data()[3], c2.data()[3]);
	}
}