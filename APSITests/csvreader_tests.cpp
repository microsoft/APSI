#include "csvreader_tests.h"
#include "apsi/tools/csvreader.h"
#include "utils.h"

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

void CSVReaderTests::read_extra_info_test()
{
    CSVReader reader;
    stringstream ss("1,2,3,4,5\n6,7,8,9,10\n11,12,13");

    vector<Item> items;
    Matrix<u8> labels;
    reader.read(ss, items, labels, /* label_byte_count */ 8);

    CPPUNIT_ASSERT_EQUAL((size_t)3, items.size());
    CPPUNIT_ASSERT_EQUAL((u64)3,    labels.rows());
    CPPUNIT_ASSERT_EQUAL((u64)8,    labels.columns());

    CPPUNIT_ASSERT_EQUAL((u64)1,  items[0][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0,  items[0][1]);
    CPPUNIT_ASSERT_EQUAL((u64)6,  items[1][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0,  items[1][1]);
    CPPUNIT_ASSERT_EQUAL((u64)11, items[2][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0,  items[2][1]);

    CPPUNIT_ASSERT_EQUAL((u8)2,  labels[0][0]);
    CPPUNIT_ASSERT_EQUAL((u8)7,  labels[1][0]);
    CPPUNIT_ASSERT_EQUAL((u8)12, labels[2][0]);

    for (int r = 0; r < labels.rows(); r++)
    {
        // Other than column 0, the rest should be zero
        for (int c = 1; c < labels.columns(); c++)
        {
            CPPUNIT_ASSERT_EQUAL((u8)0, labels[r][c]);
        }
    }
}

void CSVReaderTests::read_missing_info_test()
{
    CSVReader reader;
    stringstream ss("1,2\n3,4\n5\n6,7\n8,9\n10\n11,12\n13");

    vector<Item> items;
    Matrix<u8> labels;
    reader.read(ss, items, labels, /* label_byte_count */ 8);

    CPPUNIT_ASSERT_EQUAL((size_t)8, items.size());
    CPPUNIT_ASSERT_EQUAL((u64)8,    labels.rows());
    CPPUNIT_ASSERT_EQUAL((u64)8,    labels.columns());

    CPPUNIT_ASSERT_EQUAL((u64)1,  items[0][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0,  items[0][1]);
    CPPUNIT_ASSERT_EQUAL((u64)3,  items[1][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0,  items[1][1]);
    CPPUNIT_ASSERT_EQUAL((u64)5,  items[2][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0,  items[2][1]);
    CPPUNIT_ASSERT_EQUAL((u64)6,  items[3][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0,  items[3][1]);
    CPPUNIT_ASSERT_EQUAL((u64)8,  items[4][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0,  items[4][1]);
    CPPUNIT_ASSERT_EQUAL((u64)10, items[5][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0,  items[5][1]);
    CPPUNIT_ASSERT_EQUAL((u64)11, items[6][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0,  items[6][1]);
    CPPUNIT_ASSERT_EQUAL((u64)13, items[7][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0,  items[7][1]);

    CPPUNIT_ASSERT_EQUAL((u8)2,  labels[0][0]);
    CPPUNIT_ASSERT_EQUAL((u8)4,  labels[1][0]);
    CPPUNIT_ASSERT_EQUAL((u8)0,  labels[2][0]);
    CPPUNIT_ASSERT_EQUAL((u8)7,  labels[3][0]);
    CPPUNIT_ASSERT_EQUAL((u8)9,  labels[4][0]);
    CPPUNIT_ASSERT_EQUAL((u8)0,  labels[5][0]);
    CPPUNIT_ASSERT_EQUAL((u8)12, labels[6][0]);
    CPPUNIT_ASSERT_EQUAL((u8)0,  labels[7][0]);

    for (int r = 0; r < labels.rows(); r++)
    {
        // Other than column 0, the rest should be zero
        for (int c = 1; c < labels.columns(); c++)
        {
            CPPUNIT_ASSERT_EQUAL((u8)0, labels[r][c]);
        }
    }
}

void CSVReaderTests::read_max_bits_test()
{
    CSVReader reader;
    stringstream ss("432345564227567615,432345564227567614");

    vector<Item> items;
    Matrix<u8> labels;
    reader.read(ss, items, labels, /* label_byte_count */ 8);

    CPPUNIT_ASSERT_EQUAL((size_t)1, items.size());
    CPPUNIT_ASSERT_EQUAL((u64)1, labels.rows());
    CPPUNIT_ASSERT_EQUAL((u64)8, labels.columns());

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

    items.clear();
    labels.resize(0, 0);

    stringstream ss2("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    reader.read(ss2, items, labels, /* label_byte_count */ 16);

    CPPUNIT_ASSERT_EQUAL((size_t)1, items.size());
    CPPUNIT_ASSERT_EQUAL((u64)1,    labels.rows());
    CPPUNIT_ASSERT_EQUAL((u64)16,   labels.columns());

    CPPUNIT_ASSERT_EQUAL(0xFFFFFFFFFFFFFFFF, items[0][0]);
    CPPUNIT_ASSERT_EQUAL(0xFFFFFFFFFFFFFFFF, items[0][1]);

    for (int r = 0; r < labels.rows(); r++)
    {
        for (int c = 0; c < labels.columns(); c++)
        {
            CPPUNIT_ASSERT_EQUAL((u8)0xFF, labels[r][c]);
        }
    }
}

void CSVReaderTests::read_hex_values_test()
{
    CSVReader reader;
    stringstream ss("0x123A, 0xDEADBEEF \n 456, 789 \n 0XABCDEF123 , 0XFDCBA321 ");

    vector<Item> items;
    Matrix<u8> labels;

    reader.read(ss, items, labels, /* label_byte_count */ 8);

    CPPUNIT_ASSERT_EQUAL((size_t)3, items.size());
    CPPUNIT_ASSERT_EQUAL((u64)3, labels.rows());
    CPPUNIT_ASSERT_EQUAL((u64)8, labels.columns());

    CPPUNIT_ASSERT_EQUAL((u64)0x123a,      items[0][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0,           items[0][1]);
    CPPUNIT_ASSERT_EQUAL((u64)456,         items[1][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0,           items[1][1]);
    CPPUNIT_ASSERT_EQUAL((u64)0xABCDEF123, items[2][0]);
    CPPUNIT_ASSERT_EQUAL((u64)0,           items[2][1]);

    CPPUNIT_ASSERT_EQUAL((u8)0xEF, labels[0][0]);
    CPPUNIT_ASSERT_EQUAL((u8)0xBE, labels[0][1]);
    CPPUNIT_ASSERT_EQUAL((u8)0xAD, labels[0][2]);
    CPPUNIT_ASSERT_EQUAL((u8)0xDE, labels[0][3]);
    CPPUNIT_ASSERT_EQUAL((u8)0xEF, labels[0][0]);
    CPPUNIT_ASSERT_EQUAL((u8)0x15, labels[1][0]);
    CPPUNIT_ASSERT_EQUAL((u8)0x03, labels[1][1]);
    CPPUNIT_ASSERT_EQUAL((u8)0x21, labels[2][0]);
    CPPUNIT_ASSERT_EQUAL((u8)0xa3, labels[2][1]);
    CPPUNIT_ASSERT_EQUAL((u8)0xcb, labels[2][2]);
    CPPUNIT_ASSERT_EQUAL((u8)0xfd, labels[2][3]);
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

void CSVReaderTests::file_not_exist_test()
{
    ASSERT_THROWS(CSVReader reader("this file should not exist"));
}
