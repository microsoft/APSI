#include "utils_tests.h" 
#include "apsi/tools/utils.h"

#include <vector>

using namespace APSITests;
using namespace std;
using namespace apsi;
using namespace apsi::tools;

void UtilsTests::conversion_to_digits_test()
{
    u64 number = 1234;
    vector<u64> digits = conversion_to_digits(number, /* base */ 10);

    CPPUNIT_ASSERT_EQUAL((size_t)4, digits.size());
    CPPUNIT_ASSERT_EQUAL((u64)1, digits[3]);
    CPPUNIT_ASSERT_EQUAL((u64)2, digits[2]);
    CPPUNIT_ASSERT_EQUAL((u64)3, digits[1]);
    CPPUNIT_ASSERT_EQUAL((u64)4, digits[0]);

    digits = conversion_to_digits(number, /* base */ 16);

    CPPUNIT_ASSERT_EQUAL((size_t)3, digits.size());
    CPPUNIT_ASSERT_EQUAL((u64)0x4, digits[2]);
    CPPUNIT_ASSERT_EQUAL((u64)0xd, digits[1]);
    CPPUNIT_ASSERT_EQUAL((u64)0x2, digits[0]);

    digits = conversion_to_digits(number, /* base */ 8);

    CPPUNIT_ASSERT_EQUAL((size_t)4, digits.size());
    CPPUNIT_ASSERT_EQUAL((u64)2, digits[3]);
    CPPUNIT_ASSERT_EQUAL((u64)3, digits[2]);
    CPPUNIT_ASSERT_EQUAL((u64)2, digits[1]);
    CPPUNIT_ASSERT_EQUAL((u64)2, digits[0]);
}
