// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSI
#include "apsi/util/csvreader.h"
#include "apsi/util/utils.h"

#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::util;

namespace APSITests
{
    TEST(CSVReaderTests, ReadWithLabel)
    {
        CSVReader reader;
        stringstream ss("1,2\n3,4\n5,6\n7,8");

        vector<Item> items;
        vector<FullWidthLabel> labels;
        reader.read(ss, items, labels);

        ASSERT_EQ((size_t)4, items.size());
        ASSERT_EQ((size_t)4, labels.size());

        ASSERT_EQ((uint64_t)1, items[0][0]);
        ASSERT_EQ((uint64_t)0, items[0][1]);
        ASSERT_EQ((uint64_t)3, items[1][0]);
        ASSERT_EQ((uint64_t)0, items[1][1]);
        ASSERT_EQ((uint64_t)5, items[2][0]);
        ASSERT_EQ((uint64_t)0, items[2][1]);
        ASSERT_EQ((uint64_t)7, items[3][0]);
        ASSERT_EQ((uint64_t)0, items[3][1]);

        ASSERT_EQ((uint64_t)2, labels[0][0]);
        ASSERT_EQ((uint64_t)0, labels[0][1]);
        ASSERT_EQ((uint64_t)4, labels[1][0]);
        ASSERT_EQ((uint64_t)0, labels[1][1]);
        ASSERT_EQ((uint64_t)6, labels[2][0]);
        ASSERT_EQ((uint64_t)0, labels[2][1]);
        ASSERT_EQ((uint64_t)8, labels[3][0]);
        ASSERT_EQ((uint64_t)0, labels[3][1]);
    }

    TEST(CSVReaderTests, ReadNoLabel)
    {
        CSVReader reader;
        stringstream ss("1\n3\n5\n7");

        vector<Item> items;
        vector<FullWidthLabel> labels;
        reader.read(ss, items, labels);

        ASSERT_EQ((size_t)4, items.size());
        ASSERT_EQ((size_t)4, labels.size());

        ASSERT_EQ((uint64_t)1, items[0][0]);
        ASSERT_EQ((uint64_t)0, items[0][1]);
        ASSERT_EQ((uint64_t)3, items[1][0]);
        ASSERT_EQ((uint64_t)0, items[1][1]);
        ASSERT_EQ((uint64_t)5, items[2][0]);
        ASSERT_EQ((uint64_t)0, items[2][1]);
        ASSERT_EQ((uint64_t)7, items[3][0]);
        ASSERT_EQ((uint64_t)0, items[3][1]);
    }

    TEST(CSVReaderTests, ReadExtraInfo)
    {
        CSVReader reader;
        stringstream ss("1,2,3,4,5\n6,7,8,9,10\n11,12,13");

        vector<Item> items;
        vector<FullWidthLabel> labels;
        reader.read(ss, items, labels);

        ASSERT_EQ((size_t)3, items.size());
        ASSERT_EQ((uint64_t)3, labels.size());

        ASSERT_EQ((uint64_t)1, items[0][0]);
        ASSERT_EQ((uint64_t)0, items[0][1]);
        ASSERT_EQ((uint64_t)6, items[1][0]);
        ASSERT_EQ((uint64_t)0, items[1][1]);
        ASSERT_EQ((uint64_t)11, items[2][0]);
        ASSERT_EQ((uint64_t)0, items[2][1]);

        ASSERT_EQ((uint64_t)2, labels[0][0]);
        ASSERT_EQ((uint64_t)0, labels[0][1]);
        ASSERT_EQ((uint64_t)7, labels[1][0]);
        ASSERT_EQ((uint64_t)0, labels[1][1]);
        ASSERT_EQ((uint64_t)12, labels[2][0]);
        ASSERT_EQ((uint64_t)0, labels[2][1]);
    }

    TEST(CSVReaderTests, ReadMissingInfo)
    {
        CSVReader reader;
        stringstream ss("1,2\n3,4\n5\n6,7\n8,9\n10\n11,12\n13");

        vector<Item> items;
        vector<FullWidthLabel> labels;
        reader.read(ss, items, labels);

        ASSERT_EQ((size_t)8, items.size());
        ASSERT_EQ((size_t)8, labels.size());

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

        ASSERT_EQ((uint64_t)2, labels[0][0]);
        ASSERT_EQ((uint64_t)0, labels[0][1]);
        ASSERT_EQ((uint64_t)4, labels[1][0]);
        ASSERT_EQ((uint64_t)0, labels[1][1]);
        ASSERT_EQ((uint64_t)0, labels[2][0]);
        ASSERT_EQ((uint64_t)0, labels[2][1]);
        ASSERT_EQ((uint64_t)7, labels[3][0]);
        ASSERT_EQ((uint64_t)0, labels[3][1]);
        ASSERT_EQ((uint64_t)9, labels[4][0]);
        ASSERT_EQ((uint64_t)0, labels[4][1]);
        ASSERT_EQ((uint64_t)0, labels[5][0]);
        ASSERT_EQ((uint64_t)0, labels[5][1]);
        ASSERT_EQ((uint64_t)12, labels[6][0]);
        ASSERT_EQ((uint64_t)0, labels[6][1]);
        ASSERT_EQ((uint64_t)0, labels[7][0]);
        ASSERT_EQ((uint64_t)0, labels[7][1]);
    }

    TEST(CSVReaderTests, ReadMaxBits)
    {
        CSVReader reader;
        stringstream ss("432345564227567615,432345564227567614");

        vector<Item> items;
        vector<FullWidthLabel> labels;
        reader.read(ss, items, labels);

        ASSERT_EQ((size_t)1, items.size());
        ASSERT_EQ((size_t)1, labels.size());

        ASSERT_EQ((uint64_t)0x5FFFFFFFFFFFFFF, items[0][0]);
        ASSERT_EQ((uint64_t)0, items[0][1]);

        ASSERT_EQ((uint64_t)0x5FFFFFFFFFFFFFE, labels[0][0]);
        ASSERT_EQ((uint64_t)0x0, labels[0][1]);

        items.clear();
        labels.resize(0);

        stringstream ss2("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        reader.read(ss2, items, labels);

        ASSERT_EQ((size_t)1, items.size());
        ASSERT_EQ((size_t)1, labels.size());

        ASSERT_EQ(0xFFFFFFFFFFFFFFFF, items[0][0]);
        ASSERT_EQ(0xFFFFFFFFFFFFFFFF, items[0][1]);

        ASSERT_EQ(0xFFFFFFFFFFFFFFFF, labels[0][0]);
        ASSERT_EQ(0xFFFFFFFFFFFFFFFF, labels[0][1]);
    }

    TEST(CSVReaderTests, ReadHexValues)
    {
        CSVReader reader;
        stringstream ss("0x123A, 0xDEADBEEF \n 456, 789 \n 0XABCDEF123 , 0XFDCBA321 ");

        vector<Item> items;
        vector<FullWidthLabel> labels;

        reader.read(ss, items, labels);

        ASSERT_EQ((size_t)3, items.size());
        ASSERT_EQ((size_t)3, labels.size());

        ASSERT_EQ((uint64_t)0x123a, items[0][0]);
        ASSERT_EQ((uint64_t)0, items[0][1]);
        ASSERT_EQ((uint64_t)456, items[1][0]);
        ASSERT_EQ((uint64_t)0, items[1][1]);
        ASSERT_EQ((uint64_t)0xABCDEF123, items[2][0]);
        ASSERT_EQ((uint64_t)0, items[2][1]);

        ASSERT_EQ((uint64_t)0xDEADBEEF, labels[0][0]);
        ASSERT_EQ((uint64_t)0x0, labels[0][1]);
        ASSERT_EQ((uint64_t)789, labels[1][0]);
        ASSERT_EQ((uint64_t)0, labels[1][1]);
        ASSERT_EQ((uint64_t)0xFDCBA321, labels[2][0]);
        ASSERT_EQ((uint64_t)0x0, labels[2][1]);
    }

    TEST(CSVReaderTests, ReadEmptyFile)
    {
        CSVReader reader;
        stringstream ss("");

        vector<Item> items;
        vector<FullWidthLabel> labels;
        reader.read(ss, items, labels);

        ASSERT_EQ((size_t)0, items.size());
        ASSERT_EQ((size_t)0, labels.size());
    }

    TEST(CSVReaderTests, ReadFileNotExist)
    {
        ASSERT_ANY_THROW(CSVReader reader("this file should not exist"));
    }
} // namespace APSITests
