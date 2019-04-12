
#include "gtest/gtest.h"
#include "apsi/plaintextarith.h"

using namespace apsi;
using namespace std;
using namespace seal;
using namespace seal::util;

namespace APSITests
{
	TEST(TestPlainArith, TestMult)
	{
		Plaintext plain1(string("1x^7 + 3")),
			plain2(string("1x^2")),
			modulus(string("1x^8 + 1"));
		SmallModulus coeff_mod(5);
		PolyModulus poly_mod(modulus.data(), 9, 1);

		Plaintext result = apsi::multiply(plain1, plain2, poly_mod, coeff_mod);

		ASSERT_TRUE(result == Plaintext(string("3x^2 + 4x^1")));
	}
}
