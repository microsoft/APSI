// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD

// APSI
#include "gtest/gtest.h"
#include "apsi/util/cuckoo_filter_table.h"

using namespace std;
using namespace apsi;
using namespace apsi::sender;
using namespace apsi::sender::util;

namespace APSITests {

    TEST(SenderUtilsTests, CuckooFilterTableBasics)
    {
        CuckooFilterTable table(/* num_items */ 70 * 2, 12);

        ASSERT_EQ(64, table.get_num_buckets());

        table.write_tag(0, 0, 0x00000AAA);
        table.write_tag(0, 1, 0x00000CCC);
        table.write_tag(0, 2, 0x00000AAA);
        table.write_tag(0, 3, 0x00000CCC);
        table.write_tag(1, 0, 0x00000AAA);
        table.write_tag(1, 1, 0x00000CCC);
        table.write_tag(1, 2, 0x00000AAA);
        table.write_tag(1, 3, 0x00000CCC);
        table.write_tag(2, 0, 0x00000AAA);
        table.write_tag(2, 1, 0x00000CCC);
        table.write_tag(2, 2, 0x00000AAA);
        table.write_tag(2, 3, 0x00000CCC);

        ASSERT_EQ(0x00000AAA, table.read_tag(0, 0));
        ASSERT_EQ(0x00000CCC, table.read_tag(0, 1));
        ASSERT_EQ(0x00000AAA, table.read_tag(0, 2));
        ASSERT_EQ(0x00000CCC, table.read_tag(0, 3));
        ASSERT_EQ(0x00000AAA, table.read_tag(1, 0));
        ASSERT_EQ(0x00000CCC, table.read_tag(1, 1));
        ASSERT_EQ(0x00000AAA, table.read_tag(1, 2));
        ASSERT_EQ(0x00000CCC, table.read_tag(1, 3));
        ASSERT_EQ(0x00000AAA, table.read_tag(2, 0));
        ASSERT_EQ(0x00000CCC, table.read_tag(2, 1));
        ASSERT_EQ(0x00000AAA, table.read_tag(2, 2));
        ASSERT_EQ(0x00000CCC, table.read_tag(2, 3));
    }

    TEST(SenderUtilsTests, CuckooFilterTableOverwrite)
    {
        CuckooFilterTable table(70 * 2, 12);

        ASSERT_EQ(64, table.get_num_buckets());

        table.write_tag(0, 0, 0xAAA);
        table.write_tag(0, 1, 0xCCC);
        table.write_tag(0, 2, 0xAAA);
        table.write_tag(0, 3, 0xCCC);
        table.write_tag(1, 0, 0xAAA);
        table.write_tag(1, 1, 0xCCC);
        table.write_tag(1, 2, 0xAAA);
        table.write_tag(1, 3, 0xCCC);

        ASSERT_EQ(0xAAA, table.read_tag(0, 0));
        ASSERT_EQ(0xCCC, table.read_tag(0, 1));
        ASSERT_EQ(0xAAA, table.read_tag(0, 2));
        ASSERT_EQ(0xCCC, table.read_tag(0, 3));
        ASSERT_EQ(0xAAA, table.read_tag(1, 0));
        ASSERT_EQ(0xCCC, table.read_tag(1, 1));
        ASSERT_EQ(0xAAA, table.read_tag(1, 2));
        ASSERT_EQ(0xCCC, table.read_tag(1, 3));

        table.write_tag(0, 0, 0xCCC);
        table.write_tag(0, 1, 0xAAA);
        table.write_tag(0, 2, 0xCCC);
        table.write_tag(0, 3, 0xAAA);
        table.write_tag(1, 0, 0xCCC);
        table.write_tag(1, 1, 0xAAA);
        table.write_tag(1, 2, 0xCCC);
        table.write_tag(1, 3, 0xAAA);

        ASSERT_EQ(0xCCC, table.read_tag(0, 0));
        ASSERT_EQ(0xAAA, table.read_tag(0, 1));
        ASSERT_EQ(0xCCC, table.read_tag(0, 2));
        ASSERT_EQ(0xAAA, table.read_tag(0, 3));
        ASSERT_EQ(0xCCC, table.read_tag(1, 0));
        ASSERT_EQ(0xAAA, table.read_tag(1, 1));
        ASSERT_EQ(0xCCC, table.read_tag(1, 2));
        ASSERT_EQ(0xAAA, table.read_tag(1, 3));
    }

    TEST(SenderUtilsTests, CuckooFilterTableBasics2)
    {
        CuckooFilterTable table(/* num_items */ 70 * 2, 12);

        ASSERT_EQ(64, table.get_num_buckets());

        table.write_tag(0, 0, 0x123);
        table.write_tag(0, 1, 0x456);
        table.write_tag(0, 2, 0x789);
        table.write_tag(0, 3, 0xABC);
        table.write_tag(1, 0, 0xDEF);
        table.write_tag(1, 1, 0x123);
        table.write_tag(1, 2, 0x456);
        table.write_tag(1, 3, 0x789);
        table.write_tag(2, 0, 0xABC);
        table.write_tag(2, 1, 0xDEF);
        table.write_tag(2, 2, 0x123);
        table.write_tag(2, 3, 0x456);

        ASSERT_EQ(0x123, table.read_tag(0, 0));
        ASSERT_EQ(0x456, table.read_tag(0, 1));
        ASSERT_EQ(0x789, table.read_tag(0, 2));
        ASSERT_EQ(0xABC, table.read_tag(0, 3));
        ASSERT_EQ(0xDEF, table.read_tag(1, 0));
        ASSERT_EQ(0x123, table.read_tag(1, 1));
        ASSERT_EQ(0x456, table.read_tag(1, 2));
        ASSERT_EQ(0x789, table.read_tag(1, 3));
        ASSERT_EQ(0xABC, table.read_tag(2, 0));
        ASSERT_EQ(0xDEF, table.read_tag(2, 1));
        ASSERT_EQ(0x123, table.read_tag(2, 2));
        ASSERT_EQ(0x456, table.read_tag(2, 3));
    }
} // namespace APSITests
