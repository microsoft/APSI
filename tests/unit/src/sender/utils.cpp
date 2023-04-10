// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSI
#include "apsi/util/cuckoo_filter.h"
#include "apsi/util/cuckoo_filter_table.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::sender;
using namespace apsi::sender::util;

namespace APSITests {
    TEST(SenderUtilsTests, CuckooFilterBasics)
    {
        CuckooFilter filter(70 * 2, 12);

        for (uint64_t elem = 1; elem <= 100; elem++) {
            ASSERT_EQ(true, filter.add(elem));
        }

        for (uint64_t elem = 1; elem <= 100; elem++) {
            ASSERT_EQ(true, filter.contains(elem));
        }

        ASSERT_EQ(true, filter.contains(1));
        ASSERT_EQ(true, filter.contains(2));
        ASSERT_EQ(true, filter.contains(10));
        ASSERT_EQ(true, filter.contains(11));
        ASSERT_EQ(true, filter.contains(20));
        ASSERT_EQ(true, filter.contains(21));
        ASSERT_EQ(true, filter.contains(80));
        ASSERT_EQ(true, filter.contains(81));

        ASSERT_EQ(100, filter.get_num_items());

        ASSERT_EQ(true, filter.remove(1));
        ASSERT_EQ(true, filter.remove(10));
        ASSERT_EQ(true, filter.remove(20));
        ASSERT_EQ(true, filter.remove(80));

        ASSERT_EQ(false, filter.contains(1));
        ASSERT_EQ(true, filter.contains(2));
        ASSERT_EQ(false, filter.contains(10));
        ASSERT_EQ(true, filter.contains(11));
        ASSERT_EQ(false, filter.contains(20));
        ASSERT_EQ(true, filter.contains(21));
        ASSERT_EQ(false, filter.contains(80));
        ASSERT_EQ(true, filter.contains(81));

        ASSERT_EQ(96, filter.get_num_items());
    }

    TEST(SenderUtilsTests, CuckooFilterLongTag)
    {
        CuckooFilter filter(70 * 2, 63);

        for (uint64_t elem = 1; elem <= 100; elem++) {
            ASSERT_EQ(true, filter.add(elem));
        }

        for (uint64_t elem = 1; elem <= 100; elem++) {
            ASSERT_EQ(true, filter.contains(elem));
        }

        ASSERT_EQ(true, filter.contains(1));
        ASSERT_EQ(true, filter.contains(2));
        ASSERT_EQ(true, filter.contains(10));
        ASSERT_EQ(true, filter.contains(11));
        ASSERT_EQ(true, filter.contains(20));
        ASSERT_EQ(true, filter.contains(21));
        ASSERT_EQ(true, filter.contains(80));
        ASSERT_EQ(true, filter.contains(81));

        ASSERT_EQ(100, filter.get_num_items());

        ASSERT_EQ(true, filter.remove(1));
        ASSERT_EQ(true, filter.remove(10));
        ASSERT_EQ(true, filter.remove(20));
        ASSERT_EQ(true, filter.remove(80));

        ASSERT_EQ(false, filter.contains(1));
        ASSERT_EQ(true, filter.contains(2));
        ASSERT_EQ(false, filter.contains(10));
        ASSERT_EQ(true, filter.contains(11));
        ASSERT_EQ(false, filter.contains(20));
        ASSERT_EQ(true, filter.contains(21));
        ASSERT_EQ(false, filter.contains(80));
        ASSERT_EQ(true, filter.contains(81));

        ASSERT_EQ(96, filter.get_num_items());
    }

    TEST(SenderUtilsTests, CuckooFilterSaveLoad)
    {
        stringstream ss;
        CuckooFilter filter_template(70 * 2, 12);
        for (uint64_t elem = 1; elem <= 100; elem++) {
            ASSERT_EQ(true, filter_template.add(elem));
        }
        auto save_size = filter_template.save(ss);

        size_t bytes_read;
        auto filter = CuckooFilter::Load(ss, bytes_read);
        ASSERT_EQ(save_size, bytes_read);

        for (uint64_t elem = 1; elem <= 100; elem++) {
            ASSERT_EQ(true, filter.contains(elem));
        }

        ASSERT_EQ(true, filter.contains(1));
        ASSERT_EQ(true, filter.contains(2));
        ASSERT_EQ(true, filter.contains(10));
        ASSERT_EQ(true, filter.contains(11));
        ASSERT_EQ(true, filter.contains(20));
        ASSERT_EQ(true, filter.contains(21));
        ASSERT_EQ(true, filter.contains(80));
        ASSERT_EQ(true, filter.contains(81));

        ASSERT_EQ(100, filter.get_num_items());

        ASSERT_EQ(true, filter.remove(1));
        ASSERT_EQ(true, filter.remove(10));
        ASSERT_EQ(true, filter.remove(20));
        ASSERT_EQ(true, filter.remove(80));

        ASSERT_EQ(false, filter.contains(1));
        ASSERT_EQ(true, filter.contains(2));
        ASSERT_EQ(false, filter.contains(10));
        ASSERT_EQ(true, filter.contains(11));
        ASSERT_EQ(false, filter.contains(20));
        ASSERT_EQ(true, filter.contains(21));
        ASSERT_EQ(false, filter.contains(80));
        ASSERT_EQ(true, filter.contains(81));

        ASSERT_EQ(96, filter.get_num_items());
    }

    TEST(SenderUtilsTests, CuckooFilterLimits)
    {
        size_t max_items = 140;
        CuckooFilter filter(max_items, 12);
        uint64_t last_elem = 0;

        for (uint64_t elem = 1; elem < 1000; elem++) {
            if (!filter.add(elem)) {
                last_elem = elem - 1;
                break;
            }
        }

        ASSERT_TRUE(filter.get_num_items() > max_items);
        ASSERT_TRUE(filter.get_num_items() < (max_items * 2));

        for (uint64_t elem = 1; elem <= last_elem; elem++) {
            ASSERT_TRUE(filter.contains(elem));
        }

        max_items = 128000;
        CuckooFilter filter_big(max_items, 16);
        last_elem = 0;

        for (uint64_t elem = 1; elem < (max_items * 10); elem++) {
            if (!filter_big.add(elem)) {
                last_elem = elem - 1;
                break;
            }
        }

        for (uint64_t elem = 1; elem <= last_elem; elem++) {
            ASSERT_TRUE(filter_big.contains(elem));
        }

        max_items = 600000;
        CuckooFilter filter_big2(max_items, 24);
        last_elem = 0;

        for (uint64_t elem = 1; elem < (max_items * 10); elem++) {
            if (!filter_big2.add(elem)) {
                last_elem = elem - 1;
                break;
            }
        }

        for (uint64_t elem = 1; elem <= last_elem; elem++) {
            ASSERT_TRUE(filter_big2.contains(elem));
        }
    }

    TEST(SenderUtilsTests, CuckooFilterTableBasics12)
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

    TEST(SenderUtilsTests, CuckooFilterTableBasics8)
    {
        CuckooFilterTable table(/* num_items */ 70 * 2, 8);

        ASSERT_EQ(64, table.get_num_buckets());

        table.write_tag(0, 0, 0xAA);
        table.write_tag(0, 1, 0xCC);
        table.write_tag(0, 2, 0xAA);
        table.write_tag(0, 3, 0xCC);
        table.write_tag(1, 0, 0xAA);
        table.write_tag(1, 1, 0xCC);
        table.write_tag(1, 2, 0xAA);
        table.write_tag(1, 3, 0xCC);
        table.write_tag(2, 0, 0xAA);
        table.write_tag(2, 1, 0xCC);
        table.write_tag(2, 2, 0xAA);
        table.write_tag(2, 3, 0xCC);

        ASSERT_EQ(0xAA, table.read_tag(0, 0));
        ASSERT_EQ(0xCC, table.read_tag(0, 1));
        ASSERT_EQ(0xAA, table.read_tag(0, 2));
        ASSERT_EQ(0xCC, table.read_tag(0, 3));
        ASSERT_EQ(0xAA, table.read_tag(1, 0));
        ASSERT_EQ(0xCC, table.read_tag(1, 1));
        ASSERT_EQ(0xAA, table.read_tag(1, 2));
        ASSERT_EQ(0xCC, table.read_tag(1, 3));
        ASSERT_EQ(0xAA, table.read_tag(2, 0));
        ASSERT_EQ(0xCC, table.read_tag(2, 1));
        ASSERT_EQ(0xAA, table.read_tag(2, 2));
        ASSERT_EQ(0xCC, table.read_tag(2, 3));
    }

    TEST(SenderUtilsTests, CuckooFilterTableBasics4)
    {
        CuckooFilterTable table(/* num_items */ 70 * 2, 4);

        ASSERT_EQ(64, table.get_num_buckets());

        table.write_tag(0, 0, 0xA);
        table.write_tag(0, 1, 0xC);
        table.write_tag(0, 2, 0xA);
        table.write_tag(0, 3, 0xC);
        table.write_tag(1, 0, 0xA);
        table.write_tag(1, 1, 0xC);
        table.write_tag(1, 2, 0xA);
        table.write_tag(1, 3, 0xC);
        table.write_tag(2, 0, 0xA);
        table.write_tag(2, 1, 0xC);
        table.write_tag(2, 2, 0xA);
        table.write_tag(2, 3, 0xC);

        ASSERT_EQ(0xA, table.read_tag(0, 0));
        ASSERT_EQ(0xC, table.read_tag(0, 1));
        ASSERT_EQ(0xA, table.read_tag(0, 2));
        ASSERT_EQ(0xC, table.read_tag(0, 3));
        ASSERT_EQ(0xA, table.read_tag(1, 0));
        ASSERT_EQ(0xC, table.read_tag(1, 1));
        ASSERT_EQ(0xA, table.read_tag(1, 2));
        ASSERT_EQ(0xC, table.read_tag(1, 3));
        ASSERT_EQ(0xA, table.read_tag(2, 0));
        ASSERT_EQ(0xC, table.read_tag(2, 1));
        ASSERT_EQ(0xA, table.read_tag(2, 2));
        ASSERT_EQ(0xC, table.read_tag(2, 3));
    }

    TEST(SenderUtilsTests, CuckooFilterTableOverwrite12)
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

    TEST(SenderUtilsTests, CuckooFilterTableOverwrite8)
    {
        CuckooFilterTable table(70 * 2, 8);

        ASSERT_EQ(64, table.get_num_buckets());

        table.write_tag(0, 0, 0xAA);
        table.write_tag(0, 1, 0xCC);
        table.write_tag(0, 2, 0xAA);
        table.write_tag(0, 3, 0xCC);
        table.write_tag(1, 0, 0xAA);
        table.write_tag(1, 1, 0xCC);
        table.write_tag(1, 2, 0xAA);
        table.write_tag(1, 3, 0xCC);

        ASSERT_EQ(0xAA, table.read_tag(0, 0));
        ASSERT_EQ(0xCC, table.read_tag(0, 1));
        ASSERT_EQ(0xAA, table.read_tag(0, 2));
        ASSERT_EQ(0xCC, table.read_tag(0, 3));
        ASSERT_EQ(0xAA, table.read_tag(1, 0));
        ASSERT_EQ(0xCC, table.read_tag(1, 1));
        ASSERT_EQ(0xAA, table.read_tag(1, 2));
        ASSERT_EQ(0xCC, table.read_tag(1, 3));

        table.write_tag(0, 0, 0xCC);
        table.write_tag(0, 1, 0xAA);
        table.write_tag(0, 2, 0xCC);
        table.write_tag(0, 3, 0xAA);
        table.write_tag(1, 0, 0xCC);
        table.write_tag(1, 1, 0xAA);
        table.write_tag(1, 2, 0xCC);
        table.write_tag(1, 3, 0xAA);

        ASSERT_EQ(0xCC, table.read_tag(0, 0));
        ASSERT_EQ(0xAA, table.read_tag(0, 1));
        ASSERT_EQ(0xCC, table.read_tag(0, 2));
        ASSERT_EQ(0xAA, table.read_tag(0, 3));
        ASSERT_EQ(0xCC, table.read_tag(1, 0));
        ASSERT_EQ(0xAA, table.read_tag(1, 1));
        ASSERT_EQ(0xCC, table.read_tag(1, 2));
        ASSERT_EQ(0xAA, table.read_tag(1, 3));
    }

    TEST(SenderUtilsTests, CuckooFilterTableOverwrite4)
    {
        CuckooFilterTable table(70 * 2, 4);

        ASSERT_EQ(64, table.get_num_buckets());

        table.write_tag(0, 0, 0xA);
        table.write_tag(0, 1, 0xC);
        table.write_tag(0, 2, 0xA);
        table.write_tag(0, 3, 0xC);
        table.write_tag(1, 0, 0xA);
        table.write_tag(1, 1, 0xC);
        table.write_tag(1, 2, 0xA);
        table.write_tag(1, 3, 0xC);

        ASSERT_EQ(0xA, table.read_tag(0, 0));
        ASSERT_EQ(0xC, table.read_tag(0, 1));
        ASSERT_EQ(0xA, table.read_tag(0, 2));
        ASSERT_EQ(0xC, table.read_tag(0, 3));
        ASSERT_EQ(0xA, table.read_tag(1, 0));
        ASSERT_EQ(0xC, table.read_tag(1, 1));
        ASSERT_EQ(0xA, table.read_tag(1, 2));
        ASSERT_EQ(0xC, table.read_tag(1, 3));

        table.write_tag(0, 0, 0xC);
        table.write_tag(0, 1, 0xA);
        table.write_tag(0, 2, 0xC);
        table.write_tag(0, 3, 0xA);
        table.write_tag(1, 0, 0xC);
        table.write_tag(1, 1, 0xA);
        table.write_tag(1, 2, 0xC);
        table.write_tag(1, 3, 0xA);

        ASSERT_EQ(0xC, table.read_tag(0, 0));
        ASSERT_EQ(0xA, table.read_tag(0, 1));
        ASSERT_EQ(0xC, table.read_tag(0, 2));
        ASSERT_EQ(0xA, table.read_tag(0, 3));
        ASSERT_EQ(0xC, table.read_tag(1, 0));
        ASSERT_EQ(0xA, table.read_tag(1, 1));
        ASSERT_EQ(0xC, table.read_tag(1, 2));
        ASSERT_EQ(0xA, table.read_tag(1, 3));
    }

    TEST(SenderUtilsTests, CuckooFilterTableBasics2_12)
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

    TEST(SenderUtilsTests, CuckooFilterTableBasics2_8)
    {
        CuckooFilterTable table(/* num_items */ 70 * 2, 8);

        ASSERT_EQ(64, table.get_num_buckets());

        table.write_tag(0, 0, 0x12);
        table.write_tag(0, 1, 0x23);
        table.write_tag(0, 2, 0x56);
        table.write_tag(0, 3, 0x78);
        table.write_tag(1, 0, 0x9A);
        table.write_tag(1, 1, 0xBC);
        table.write_tag(1, 2, 0xDE);
        table.write_tag(1, 3, 0xF0);
        table.write_tag(2, 0, 0x12);
        table.write_tag(2, 1, 0x34);
        table.write_tag(2, 2, 0x56);
        table.write_tag(2, 3, 0x78);

        ASSERT_EQ(0x12, table.read_tag(0, 0));
        ASSERT_EQ(0x23, table.read_tag(0, 1));
        ASSERT_EQ(0x56, table.read_tag(0, 2));
        ASSERT_EQ(0x78, table.read_tag(0, 3));
        ASSERT_EQ(0x9A, table.read_tag(1, 0));
        ASSERT_EQ(0xBC, table.read_tag(1, 1));
        ASSERT_EQ(0xDE, table.read_tag(1, 2));
        ASSERT_EQ(0xF0, table.read_tag(1, 3));
        ASSERT_EQ(0x12, table.read_tag(2, 0));
        ASSERT_EQ(0x34, table.read_tag(2, 1));
        ASSERT_EQ(0x56, table.read_tag(2, 2));
        ASSERT_EQ(0x78, table.read_tag(2, 3));
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

    TEST(SenderUtilsTests, CuckooFilterTableFindTag12)
    {
        CuckooFilterTable table(/* num_items */ 70 * 2, 12);

        ASSERT_EQ(64, table.get_num_buckets());

        table.write_tag(0, 0, 0x123);
        table.write_tag(0, 1, 0x456);
        table.write_tag(0, 2, 0x789);
        table.write_tag(0, 3, 0xABC);
        table.write_tag(1, 0, 0xDEF);
        table.write_tag(1, 1, 0x321);
        table.write_tag(1, 2, 0x654);
        table.write_tag(1, 3, 0x987);
        table.write_tag(2, 0, 0xCBA);
        table.write_tag(2, 1, 0xFED);
        table.write_tag(2, 2, 0x123);
        table.write_tag(2, 3, 0x456);

        ASSERT_TRUE(table.find_tag_in_bucket(0, 0x456));
        ASSERT_TRUE(table.find_tag_in_bucket(0, 0x123));
        ASSERT_TRUE(table.find_tag_in_bucket(0, 0xABC));
        ASSERT_TRUE(table.find_tag_in_bucket(1, 0x987));
        ASSERT_TRUE(table.find_tag_in_bucket(1, 0x654));
        ASSERT_TRUE(table.find_tag_in_bucket(2, 0x456));
        ASSERT_TRUE(table.find_tag_in_bucket(2, 0xCBA));

        ASSERT_TRUE(table.find_tag_in_buckets(0, 2, 0xFED));
        ASSERT_TRUE(table.find_tag_in_buckets(0, 1, 0x321));
        ASSERT_TRUE(table.find_tag_in_buckets(0, 1, 0xABC));

        ASSERT_FALSE(table.find_tag_in_bucket(0, 0xDEF));
        ASSERT_FALSE(table.find_tag_in_bucket(1, 0xABC));
        ASSERT_FALSE(table.find_tag_in_bucket(2, 0x987));

        ASSERT_FALSE(table.find_tag_in_buckets(0, 1, 0xFFF));
        ASSERT_FALSE(table.find_tag_in_buckets(0, 2, 0x321));
    }

    TEST(SenderUtilsTests, CuckooFilterTableFindTag8)
    {
        CuckooFilterTable table(/* num_items */ 70 * 2, 8);

        ASSERT_EQ(64, table.get_num_buckets());

        table.write_tag(0, 0, 0x12);
        table.write_tag(0, 1, 0x23);
        table.write_tag(0, 2, 0x56);
        table.write_tag(0, 3, 0x78);
        table.write_tag(1, 0, 0x9A);
        table.write_tag(1, 1, 0xBC);
        table.write_tag(1, 2, 0xDE);
        table.write_tag(1, 3, 0xF0);
        table.write_tag(2, 0, 0x12);
        table.write_tag(2, 1, 0x34);
        table.write_tag(2, 2, 0x56);
        table.write_tag(2, 3, 0x78);

        ASSERT_TRUE(table.find_tag_in_bucket(0, 0x12));
        ASSERT_TRUE(table.find_tag_in_bucket(0, 0x56));
        ASSERT_TRUE(table.find_tag_in_bucket(0, 0x78));
        ASSERT_TRUE(table.find_tag_in_bucket(1, 0xBC));
        ASSERT_TRUE(table.find_tag_in_bucket(1, 0xDE));
        ASSERT_TRUE(table.find_tag_in_bucket(2, 0x12));
        ASSERT_TRUE(table.find_tag_in_bucket(2, 0x78));

        ASSERT_TRUE(table.find_tag_in_buckets(0, 2, 0x34));
        ASSERT_TRUE(table.find_tag_in_buckets(0, 1, 0x78));
        ASSERT_TRUE(table.find_tag_in_buckets(0, 1, 0x78));

        ASSERT_FALSE(table.find_tag_in_bucket(0, 0xDE));
        ASSERT_FALSE(table.find_tag_in_bucket(1, 0x12));
        ASSERT_FALSE(table.find_tag_in_bucket(2, 0xF0));

        ASSERT_FALSE(table.find_tag_in_buckets(0, 1, 0x21));
        ASSERT_FALSE(table.find_tag_in_buckets(0, 2, 0x65));
    }
} // namespace APSITests
