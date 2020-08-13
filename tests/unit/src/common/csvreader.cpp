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
