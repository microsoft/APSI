#include "stdafx.h"
#include "CppUnitTest.h"
#include "Sender/sender.h"
#include "Receiver/receiver.h"
#include "psiparams.h"
#include "util/exfield.h"
#include "util/exfieldpolycrt.h"
#include "context.h"
#include "plaintextarith.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace apsi::sender;
using namespace apsi::receiver;
using namespace apsi;
using namespace std;
using namespace seal;
using namespace seal::util;

namespace APSITests
{
    TEST_CLASS(TestPlainArith)
    {
    public:
        TEST_METHOD(TestMult)
        {
            Plaintext plain1(string("1x^7 + 3")),
                plain2(string("1x^2")),
                modulus(string("1x^8 + 1"));
            SmallModulus coeff_mod(5);
            PolyModulus poly_mod(modulus.get_poly().pointer(), 9, 1);

            Plaintext result = apsi::multiply(plain1, plain2, poly_mod, coeff_mod);

            Assert::IsTrue(result == Plaintext(string("3x^2 + 4x^1")));

        }
    };
}