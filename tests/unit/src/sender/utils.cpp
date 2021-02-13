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

    TEST(SenderUtilsTests, CuckooFilterTableInvalidTag)
    {
        CuckooFilterTable table1(70, 4);
        CuckooFilterTable table2(70, 8);
        CuckooFilterTable table3(70, 12);
        CuckooFilterTable table4(70, 16);

        ASSERT_NO_THROW(table1.write_tag(0, 0, 0x0000000F));
        ASSERT_NO_THROW(table2.write_tag(0, 0, 0x000000FF));
        ASSERT_NO_THROW(table3.write_tag(0, 0, 0x00000FFF));
        ASSERT_NO_THROW(table4.write_tag(0, 0, 0x0000FFFF));

        ASSERT_THROW(table1.write_tag(0, 0, 0x0000001F), std::invalid_argument);
        ASSERT_THROW(table2.write_tag(0, 0, 0x000001FF), std::invalid_argument);
        ASSERT_THROW(table3.write_tag(0, 0, 0x00001FFF), std::invalid_argument);
        ASSERT_THROW(table4.write_tag(0, 0, 0x0001FFFF), std::invalid_argument);
    }
} // namespace APSITests
