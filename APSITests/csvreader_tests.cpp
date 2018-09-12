#include "csvreader_tests.h"
#include "apsi/tools/csvreader.h"

using namespace std;
using namespace APSITests;
using namespace apsi;
using namespace apsi::tools;


void CSVReaderTests::read_test()
{
    CSVReader reader;
    stringstream ss("1,2\n3,4\n5,6\n7,8");

    vector<Item> items;
    Matrix<u8> labels;
    reader.read(ss, items, labels, /* label_byte_count */ 8);

    CPPUNIT_ASSERT_EQUAL((size_t)4, items.size());
    CPPUNIT_ASSERT_EQUAL((size_t)4, labels.rows());
    CPPUNIT_ASSERT_EQUAL((size_t)8, labels.columns());

    CPPUNIT_ASSERT_EQUAL((u64)1, items[0][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, items[0][1]);
    CPPUNIT_ASSERT_EQUAL((u64)3, items[1][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, items[1][1]);
    CPPUNIT_ASSERT_EQUAL((u64)5, items[2][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, items[2][1]);
    CPPUNIT_ASSERT_EQUAL((u64)7, items[3][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, items[3][1]);

    CPPUNIT_ASSERT_EQUAL((u8)2, labels[0][0]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[0][1]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[0][2]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[0][3]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[0][4]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[0][5]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[0][6]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[0][7]);

    CPPUNIT_ASSERT_EQUAL((u8)4, labels[1][0]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[1][1]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[1][2]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[1][3]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[1][4]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[1][5]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[1][6]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[1][7]);

    CPPUNIT_ASSERT_EQUAL((u8)6, labels[2][0]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[2][1]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[2][2]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[2][3]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[2][4]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[2][5]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[2][6]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[2][7]);

    CPPUNIT_ASSERT_EQUAL((u8)8, labels[3][0]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[3][1]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[3][2]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[3][3]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[3][4]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[3][5]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[3][6]);
    CPPUNIT_ASSERT_EQUAL((u8)0, labels[3][7]);
}

void CSVReaderTests::read_no_label_test()
{
    CSVReader reader;
    stringstream ss("1\n3\n5\n7");

    vector<Item> items;
    Matrix<u8> labels;
    reader.read(ss, items, labels, /* label_byte_count */ 0);

    CPPUNIT_ASSERT_EQUAL((size_t)4, items.size());
    CPPUNIT_ASSERT_EQUAL((size_t)0, labels.rows());
    CPPUNIT_ASSERT_EQUAL((size_t)0, labels.columns());

    CPPUNIT_ASSERT_EQUAL((u64)1, items[0][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, items[0][1]);
    CPPUNIT_ASSERT_EQUAL((u64)3, items[1][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, items[1][1]);
    CPPUNIT_ASSERT_EQUAL((u64)5, items[2][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, items[2][1]);
    CPPUNIT_ASSERT_EQUAL((u64)7, items[3][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, items[3][1]);
}

void CSVReaderTests::read_max_bits_test()
{
    CSVReader reader;
    stringstream ss("432345564227567615,432345564227567614");

    vector<Item> items;
    Matrix<u8> labels;
    reader.read(ss, items, labels, /* label_byte_count */ 8);

    CPPUNIT_ASSERT_EQUAL((size_t)1, items.size());
    CPPUNIT_ASSERT_EQUAL((size_t)1, labels.rows());
    CPPUNIT_ASSERT_EQUAL((size_t)8, labels.columns());

    CPPUNIT_ASSERT_EQUAL((u64)0x5FFFFFFFFFFFFFF, items[0][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0, items[0][1]);

    CPPUNIT_ASSERT_EQUAL((u8)0xFE, labels[0][0]);
    CPPUNIT_ASSERT_EQUAL((u8)0xFF, labels[0][1]);
    CPPUNIT_ASSERT_EQUAL((u8)0xFF, labels[0][2]);
    CPPUNIT_ASSERT_EQUAL((u8)0xFF, labels[0][3]);
    CPPUNIT_ASSERT_EQUAL((u8)0xFF, labels[0][4]);
    CPPUNIT_ASSERT_EQUAL((u8)0xFF, labels[0][5]);
    CPPUNIT_ASSERT_EQUAL((u8)0xFF, labels[0][6]);
    CPPUNIT_ASSERT_EQUAL((u8)0x05, labels[0][7]);
}

void CSVReaderTests::read_empty_file_test()
{
    CSVReader reader;
    stringstream ss("");

    vector<Item> items;
    Matrix<u8> labels;
    reader.read(ss, items, labels, /* label_byte_count */ 8);

    CPPUNIT_ASSERT_EQUAL((size_t)0, items.size());
    CPPUNIT_ASSERT_EQUAL((size_t)0, labels.rows());
    CPPUNIT_ASSERT_EQUAL((size_t)0, labels.columns());
}
