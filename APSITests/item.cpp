#include "apsi/item.h"
#include "item.h"
#include "utils.h"

using namespace std;
using namespace APSITests;
using namespace apsi;

CPPUNIT_TEST_SUITE_REGISTRATION(ItemTests);

void ItemTests::parse_test()
{
    // 128 bit string
    string input = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    Item item;

    item.parse(input, /* base */ 16);

    CPPUNIT_ASSERT_EQUAL((u64)0xFFFFFFFFFFFFFFFF, item[0]);
    CPPUNIT_ASSERT_EQUAL((u64)0xFFFFFFFFFFFFFFFF, item[1]);

    // One more nibble is out of range
    input = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    ASSERT_THROWS(item.parse(input, /* base */ 16));

    input = "80000000000000000000000000000001";
    item.parse(input, /* base */ 16);

    CPPUNIT_ASSERT_EQUAL((u64)0x8000000000000000, item[1]);
    CPPUNIT_ASSERT_EQUAL((u64)0x0000000000000001, item[0]);

    input = "FEDCBA9876543210";
    item.parse(input, /* base */ 16);

    CPPUNIT_ASSERT_EQUAL((u64)0xFEDCBA9876543210, item[0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, item[1]);

    input = "abcdef";
    item.parse(input, /* base */ 16);

    CPPUNIT_ASSERT_EQUAL((u64)0xABCDEF, item[0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, item[1]);

    input = "fedcba9876543210";
    item.parse(input, /* base */ 16);

    CPPUNIT_ASSERT_EQUAL((u64)0xFEDCBA9876543210, item[0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, item[1]);

    input = "12345";
    item.parse(input, /* base */ 10);

    CPPUNIT_ASSERT_EQUAL((u64)12345, item[0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, item[1]);

    input = "9223372036854775807";
    item.parse(input, /* base */ 10);

    CPPUNIT_ASSERT_EQUAL((u64)0x7FFFFFFFFFFFFFFF, item[0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, item[1]);

    input = "2361200000000000000000";
    item.parse(input, /* base */ 10);

    CPPUNIT_ASSERT_EQUAL((u64)0x003b89d384580000, item[0]);
    CPPUNIT_ASSERT_EQUAL((u64)0x80, item[1]);
}

void ItemTests::parse_empty_test()
{
    string input = "";
    Item item;

    item.parse(input);

    CPPUNIT_ASSERT_EQUAL((u64)0, item[0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, item[1]);
}

void ItemTests::parse_diff_base_test()
{
    Item item;

    // Base 8 not supported
    ASSERT_THROWS(item.parse("12345", /* base */ 8));

    // Base 2 not supported
    ASSERT_THROWS(item.parse("1010101010", /* base */ 2));
}

void ItemTests::parse_non_regular_string_test()
{
    Item item;

    item.parse("12345hello", /* base */ 10);

    // We should be able to parse until finding someting other than a number
    CPPUNIT_ASSERT_EQUAL((u64)12345, item[0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, item[1]);

    item.parse("   45321   ", /* base */ 10);

    // Whitespace should be ignored
    CPPUNIT_ASSERT_EQUAL((u64)45321, item[0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, item[1]);

    item.parse("800000000000000000000001ABCDG", /* base */ 16);

    CPPUNIT_ASSERT_EQUAL((u64)0x1ABCD, item[0]);
    CPPUNIT_ASSERT_EQUAL((u64)0x800000000000, item[1]);
}

void ItemTests::parse_auto_detect_hex_test()
{
    Item item;

    item.parse("  0xFFF ");

    CPPUNIT_ASSERT_EQUAL((u64)0xFFF, item[0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, item[1]);

    item.parse("0XABCDEF");

    CPPUNIT_ASSERT_EQUAL((u64)0xABCDEF, item[0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, item[1]);

    item.parse("   4566789abcdef");

    CPPUNIT_ASSERT_EQUAL((u64)4566789, item[0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, item[1]);
}
