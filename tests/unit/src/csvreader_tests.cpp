// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "apsi/util/csvreader.h"
#include "gtest/gtest.h"
#include "utils.h"

using namespace std;
using namespace apsi;
using namespace apsi::util;

namespace APSITests
{
    TEST(CSVReaderTests, read_test)
    {
        CSVReader reader;
        stringstream ss("1,2\n3,4\n5,6\n7,8");

        vector<Item> items;
        Matrix<unsigned char> labels;
        reader.read(ss, items, labels, /* label_byte_count */ 8);

        ASSERT_EQ((size_t)4, items.size());
        ASSERT_EQ((size_t)4, labels.rows());
        ASSERT_EQ((size_t)8, labels.columns());

        ASSERT_EQ((uint64_t)1, items[0][0]);
        ASSERT_EQ((uint64_t)0, items[0][1]);
        ASSERT_EQ((uint64_t)3, items[1][0]);
        ASSERT_EQ((uint64_t)0, items[1][1]);
        ASSERT_EQ((uint64_t)5, items[2][0]);
        ASSERT_EQ((uint64_t)0, items[2][1]);
        ASSERT_EQ((uint64_t)7, items[3][0]);
        ASSERT_EQ((uint64_t)0, items[3][1]);

        ASSERT_EQ((unsigned char)2, labels[0][0]);
        ASSERT_EQ((unsigned char)0, labels[0][1]);
        ASSERT_EQ((unsigned char)0, labels[0][2]);
        ASSERT_EQ((unsigned char)0, labels[0][3]);
        ASSERT_EQ((unsigned char)0, labels[0][4]);
        ASSERT_EQ((unsigned char)0, labels[0][5]);
        ASSERT_EQ((unsigned char)0, labels[0][6]);
        ASSERT_EQ((unsigned char)0, labels[0][7]);

        ASSERT_EQ((unsigned char)4, labels[1][0]);
        ASSERT_EQ((unsigned char)0, labels[1][1]);
        ASSERT_EQ((unsigned char)0, labels[1][2]);
        ASSERT_EQ((unsigned char)0, labels[1][3]);
        ASSERT_EQ((unsigned char)0, labels[1][4]);
        ASSERT_EQ((unsigned char)0, labels[1][5]);
        ASSERT_EQ((unsigned char)0, labels[1][6]);
        ASSERT_EQ((unsigned char)0, labels[1][7]);

        ASSERT_EQ((unsigned char)6, labels[2][0]);
        ASSERT_EQ((unsigned char)0, labels[2][1]);
        ASSERT_EQ((unsigned char)0, labels[2][2]);
        ASSERT_EQ((unsigned char)0, labels[2][3]);
        ASSERT_EQ((unsigned char)0, labels[2][4]);
        ASSERT_EQ((unsigned char)0, labels[2][5]);
        ASSERT_EQ((unsigned char)0, labels[2][6]);
        ASSERT_EQ((unsigned char)0, labels[2][7]);

        ASSERT_EQ((unsigned char)8, labels[3][0]);
        ASSERT_EQ((unsigned char)0, labels[3][1]);
        ASSERT_EQ((unsigned char)0, labels[3][2]);
        ASSERT_EQ((unsigned char)0, labels[3][3]);
        ASSERT_EQ((unsigned char)0, labels[3][4]);
        ASSERT_EQ((unsigned char)0, labels[3][5]);
        ASSERT_EQ((unsigned char)0, labels[3][6]);
        ASSERT_EQ((unsigned char)0, labels[3][7]);
    }

    TEST(CSVReaderTests, read_no_label_test)
    {
        CSVReader reader;
        stringstream ss("1\n3\n5\n7");

        vector<Item> items;
        Matrix<unsigned char> labels;
        reader.read(ss, items, labels, /* label_byte_count */ 0);

        ASSERT_EQ((size_t)4, items.size());
        ASSERT_EQ((size_t)0, labels.rows());
        ASSERT_EQ((size_t)0, labels.columns());

        ASSERT_EQ((uint64_t)1, items[0][0]);
        ASSERT_EQ((uint64_t)0, items[0][1]);
        ASSERT_EQ((uint64_t)3, items[1][0]);
        ASSERT_EQ((uint64_t)0, items[1][1]);
        ASSERT_EQ((uint64_t)5, items[2][0]);
        ASSERT_EQ((uint64_t)0, items[2][1]);
        ASSERT_EQ((uint64_t)7, items[3][0]);
        ASSERT_EQ((uint64_t)0, items[3][1]);
    }

    TEST(CSVReaderTests, read_extra_info_test)
    {
        CSVReader reader;
        stringstream ss("1,2,3,4,5\n6,7,8,9,10\n11,12,13");

        vector<Item> items;
        Matrix<unsigned char> labels;
        reader.read(ss, items, labels, /* label_byte_count */ 8);

        ASSERT_EQ((size_t)3, items.size());
        ASSERT_EQ((uint64_t)3, labels.rows());
        ASSERT_EQ((uint64_t)8, labels.columns());

        ASSERT_EQ((uint64_t)1, items[0][0]);
        ASSERT_EQ((uint64_t)0, items[0][1]);
        ASSERT_EQ((uint64_t)6, items[1][0]);
        ASSERT_EQ((uint64_t)0, items[1][1]);
        ASSERT_EQ((uint64_t)11, items[2][0]);
        ASSERT_EQ((uint64_t)0, items[2][1]);

        ASSERT_EQ((unsigned char)2, labels[0][0]);
        ASSERT_EQ((unsigned char)7, labels[1][0]);
        ASSERT_EQ((unsigned char)12, labels[2][0]);

        for (size_t r = 0; r < labels.rows(); r++)
        {
            // Other than column 0, the rest should be zero
            for (size_t c = 1; c < labels.columns(); c++)
            {
                ASSERT_EQ((unsigned char)0, labels[r][c]);
            }
        }
    }

    TEST(CSVReaderTests, read_missing_info_test)
    {
        CSVReader reader;
        stringstream ss("1,2\n3,4\n5\n6,7\n8,9\n10\n11,12\n13");

        vector<Item> items;
        Matrix<unsigned char> labels;
        reader.read(ss, items, labels, /* label_byte_count */ 8);

        ASSERT_EQ((size_t)8, items.size());
        ASSERT_EQ((uint64_t)8, labels.rows());
        ASSERT_EQ((uint64_t)8, labels.columns());

        ASSERT_EQ((uint64_t)1, items[0][0]);
        ASSERT_EQ((uint64_t)0, items[0][1]);
        ASSERT_EQ((uint64_t)3, items[1][0]);
        ASSERT_EQ((uint64_t)0, items[1][1]);
        ASSERT_EQ((uint64_t)5, items[2][0]);
        ASSERT_EQ((uint64_t)0, items[2][1]);
        ASSERT_EQ((uint64_t)6, items[3][0]);
        ASSERT_EQ((uint64_t)0, items[3][1]);
        ASSERT_EQ((uint64_t)8, items[4][0]);
        ASSERT_EQ((uint64_t)0, items[4][1]);
        ASSERT_EQ((uint64_t)10, items[5][0]);
        ASSERT_EQ((uint64_t)0, items[5][1]);
        ASSERT_EQ((uint64_t)11, items[6][0]);
        ASSERT_EQ((uint64_t)0, items[6][1]);
        ASSERT_EQ((uint64_t)13, items[7][0]);
        ASSERT_EQ((uint64_t)0, items[7][1]);

        ASSERT_EQ((unsigned char)2, labels[0][0]);
        ASSERT_EQ((unsigned char)4, labels[1][0]);
        ASSERT_EQ((unsigned char)0, labels[2][0]);
        ASSERT_EQ((unsigned char)7, labels[3][0]);
        ASSERT_EQ((unsigned char)9, labels[4][0]);
        ASSERT_EQ((unsigned char)0, labels[5][0]);
        ASSERT_EQ((unsigned char)12, labels[6][0]);
        ASSERT_EQ((unsigned char)0, labels[7][0]);

        for (size_t r = 0; r < labels.rows(); r++)
        {
            // Other than column 0, the rest should be zero
            for (size_t c = 1; c < labels.columns(); c++)
            {
                ASSERT_EQ((unsigned char)0, labels[r][c]);
            }
        }
    }

    TEST(CSVReaderTests, read_max_bits_test)
    {
        CSVReader reader;
        stringstream ss("432345564227567615,432345564227567614");

        vector<Item> items;
        Matrix<unsigned char> labels;
        reader.read(ss, items, labels, /* label_byte_count */ 8);

        ASSERT_EQ((size_t)1, items.size());
        ASSERT_EQ((uint64_t)1, labels.rows());
        ASSERT_EQ((uint64_t)8, labels.columns());

        ASSERT_EQ((uint64_t)0x5FFFFFFFFFFFFFF, items[0][0]);
        ASSERT_EQ((uint64_t)0, items[0][1]);

        ASSERT_EQ((unsigned char)0xFE, labels[0][0]);
        ASSERT_EQ((unsigned char)0xFF, labels[0][1]);
        ASSERT_EQ((unsigned char)0xFF, labels[0][2]);
        ASSERT_EQ((unsigned char)0xFF, labels[0][3]);
        ASSERT_EQ((unsigned char)0xFF, labels[0][4]);
        ASSERT_EQ((unsigned char)0xFF, labels[0][5]);
        ASSERT_EQ((unsigned char)0xFF, labels[0][6]);
        ASSERT_EQ((unsigned char)0x05, labels[0][7]);

        items.clear();
        labels.resize(0, 0);

        stringstream ss2("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        reader.read(ss2, items, labels, /* label_byte_count */ 16);

        ASSERT_EQ((size_t)1, items.size());
        ASSERT_EQ((uint64_t)1, labels.rows());
        ASSERT_EQ((uint64_t)16, labels.columns());

        ASSERT_EQ(0xFFFFFFFFFFFFFFFF, items[0][0]);
        ASSERT_EQ(0xFFFFFFFFFFFFFFFF, items[0][1]);

        for (size_t r = 0; r < labels.rows(); r++)
        {
            for (size_t c = 0; c < labels.columns(); c++)
            {
                ASSERT_EQ((unsigned char)0xFF, labels[r][c]);
            }
        }
    }

    TEST(CSVReaderTests, read_hex_values_test)
    {
        CSVReader reader;
        stringstream ss("0x123A, 0xDEADBEEF \n 456, 789 \n 0XABCDEF123 , 0XFDCBA321 ");

        vector<Item> items;
        Matrix<unsigned char> labels;

        reader.read(ss, items, labels, /* label_byte_count */ 8);

        ASSERT_EQ((size_t)3, items.size());
        ASSERT_EQ((uint64_t)3, labels.rows());
        ASSERT_EQ((uint64_t)8, labels.columns());

        ASSERT_EQ((uint64_t)0x123a, items[0][0]);
        ASSERT_EQ((uint64_t)0, items[0][1]);
        ASSERT_EQ((uint64_t)456, items[1][0]);
        ASSERT_EQ((uint64_t)0, items[1][1]);
        ASSERT_EQ((uint64_t)0xABCDEF123, items[2][0]);
        ASSERT_EQ((uint64_t)0, items[2][1]);

        ASSERT_EQ((unsigned char)0xEF, labels[0][0]);
        ASSERT_EQ((unsigned char)0xBE, labels[0][1]);
        ASSERT_EQ((unsigned char)0xAD, labels[0][2]);
        ASSERT_EQ((unsigned char)0xDE, labels[0][3]);
        ASSERT_EQ((unsigned char)0xEF, labels[0][0]);
        ASSERT_EQ((unsigned char)0x15, labels[1][0]);
        ASSERT_EQ((unsigned char)0x03, labels[1][1]);
        ASSERT_EQ((unsigned char)0x21, labels[2][0]);
        ASSERT_EQ((unsigned char)0xa3, labels[2][1]);
        ASSERT_EQ((unsigned char)0xcb, labels[2][2]);
        ASSERT_EQ((unsigned char)0xfd, labels[2][3]);
    }

    TEST(CSVReaderTests, read_empty_file_test)
    {
        CSVReader reader;
        stringstream ss("");

        vector<Item> items;
        Matrix<unsigned char> labels;
        reader.read(ss, items, labels, /* label_byte_count */ 8);

        ASSERT_EQ((size_t)0, items.size());
        ASSERT_EQ((size_t)0, labels.rows());
        ASSERT_EQ((size_t)0, labels.columns());
    }

    TEST(CSVReaderTests, file_not_exist_test)
    {
        ASSERT_ANY_THROW(CSVReader reader("this file should not exist"));
    }
} // namespace APSITests
