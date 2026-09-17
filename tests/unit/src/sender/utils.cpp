// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSI
#include "apsi/util/cuckoo_filter.h"
#include "apsi/util/cuckoo_filter_table.h"
#include <array>
#include <cstddef>
#include <limits>
#include <sstream>
#include <string>
#include <vector>
#include "flatbuffers/flatbuffers.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::sender;
using namespace apsi::sender::util;

namespace APSITests {
    TEST(SenderUtilsTests, CuckooFilterBasics)
    {
        CuckooFilter filter(static_cast<std::size_t>(70 * 2), 12);

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
        CuckooFilter filter(static_cast<std::size_t>(70 * 2), 63);

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
        CuckooFilter filter_template(static_cast<std::size_t>(70 * 2), 12);
        for (uint64_t elem = 1; elem <= 100; elem++) {
            ASSERT_EQ(true, filter_template.add(elem));
        }
        auto save_size = filter_template.save(ss);

        size_t bytes_read = 0;
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
        CuckooFilterTable table(/* num_items */ static_cast<std::size_t>(70 * 2), 12);

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
        CuckooFilterTable table(/* num_items */ static_cast<std::size_t>(70 * 2), 8);

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
        CuckooFilterTable table(/* num_items */ static_cast<std::size_t>(70 * 2), 4);

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
        CuckooFilterTable table(static_cast<std::size_t>(70 * 2), 12);

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
        CuckooFilterTable table(static_cast<std::size_t>(70 * 2), 8);

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
        CuckooFilterTable table(static_cast<std::size_t>(70 * 2), 4);

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
        CuckooFilterTable table(/* num_items */ static_cast<std::size_t>(70 * 2), 12);

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
        CuckooFilterTable table(/* num_items */ static_cast<std::size_t>(70 * 2), 8);

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
        CuckooFilterTable table(/* num_items */ static_cast<std::size_t>(70 * 2), 12);

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
        CuckooFilterTable table(/* num_items */ static_cast<std::size_t>(70 * 2), 8);

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

    TEST(SenderUtilsTests, CuckooFilterTableRejectsATableTooSmallForItsBuckets)
    {
        // A table holds tags_per_bucket tags per bucket, so its size follows from num_buckets and
        // bits_per_tag. Every read and write bounds the bucket against num_buckets and then
        // indexes the table at a position derived from it, so a table smaller than num_buckets
        // calls for turns those bounds checks into no-ops and indexes past the end of the vector.
        // CuckooFilter::Load builds a table from a serialized filter, which an application may
        // have read from anywhere.
        constexpr size_t bits_per_tag = 12;
        constexpr size_t tags_per_bucket = 4;
        constexpr size_t num_buckets = 64;
        constexpr size_t required_words =
            ((tags_per_bucket * bits_per_tag * num_buckets) + 63) / 64;

        // The exact size is accepted.
        ASSERT_NO_THROW(
            CuckooFilterTable(vector<uint64_t>(required_words), num_buckets, bits_per_tag));

        // One word short, and far short, are both refused.
        ASSERT_THROW(
            CuckooFilterTable(vector<uint64_t>(required_words - 1), num_buckets, bits_per_tag),
            invalid_argument);
        ASSERT_THROW(
            CuckooFilterTable(vector<uint64_t>(1), num_buckets, bits_per_tag), invalid_argument);

        // So is a table larger than the parameters call for: it did not come from save().
        ASSERT_THROW(
            CuckooFilterTable(vector<uint64_t>(required_words + 1), num_buckets, bits_per_tag),
            invalid_argument);

        // Zero buckets would make every bucket out of range, and the alternate-bucket mask
        // num_buckets - 1 would underflow.
        ASSERT_THROW(CuckooFilterTable(vector<uint64_t>(), 0, bits_per_tag), invalid_argument);

        // The alternate bucket for a tag is found by masking with num_buckets - 1, which only
        // reaches every bucket when num_buckets is a power of two.
        ASSERT_THROW(
            CuckooFilterTable(
                vector<uint64_t>(((4 * bits_per_tag * 3) + 63) / 64), 3, bits_per_tag),
            invalid_argument);

        // A tag as wide as the machine word would make the tag mask shift by the width of its
        // own type.
        ASSERT_THROW(CuckooFilterTable(vector<uint64_t>(4), 1, 64), invalid_argument);
        // A num_buckets large enough to overflow the size computation must not wrap into a small
        // requirement that a short table satisfies. At 16 bits per tag a bucket is exactly one
        // word, so 2^58 buckets multiply out to exactly 2^64 bits: unchecked, the requirement
        // wraps to zero and an empty table is accepted for a filter claiming 2^58 buckets.
        ASSERT_THROW(
            CuckooFilterTable(vector<uint64_t>(), static_cast<size_t>(1) << 58U, 16),
            invalid_argument);
        ASSERT_THROW(
            CuckooFilterTable(vector<uint64_t>(), (numeric_limits<size_t>::max)(), bits_per_tag),
            invalid_argument);
    }

    TEST(SenderUtilsTests, CuckooFilterSaveLoadRoundTripsAcrossTagSizes)
    {
        // A control against over-rejection: every filter save() produces must load again, at
        // every tag width. It passes whether or not the constructor validates its input, and so
        // guards the validation's boundaries rather than its presence.
        const array<size_t, 5> tag_sizes{ 4, 8, 12, 16, 32 };
        for (size_t bits_per_tag : tag_sizes) {
            CuckooFilter filter(/* key_count */ 140, bits_per_tag);
            for (uint64_t i = 0; i < 100; i++) {
                ASSERT_TRUE(filter.add(i));
            }

            stringstream ss;
            filter.save(ss);

            size_t bytes_read = 0;
            CuckooFilter loaded = CuckooFilter::Load(ss, bytes_read);
            ASSERT_LT(size_t(0), bytes_read);
            for (uint64_t i = 0; i < 100; i++) {
                ASSERT_TRUE(loaded.contains(i));
            }
        }
    }

    namespace {
        /**
        Serializes a CuckooFilter from field values chosen by the caller, including combinations
        save() would never produce. Written through the raw builder because the generated one
        asserts on a missing required field.
        */
        string make_cuckoo_filter_buffer(
            uint64_t num_buckets,
            uint64_t bits_per_tag,
            size_t table_word_count,
            uint64_t overflow_index,
            bool overflow_used)
        {
            flatbuffers::FlatBufferBuilder fbb(1024);

            vector<uint64_t> words(table_word_count, 0);
            auto table_vec = fbb.CreateVector(words);

            const flatbuffers::uoffset_t table_off = [&] {
                flatbuffers::uoffset_t start = fbb.StartTable();
                fbb.AddElement<uint64_t>(4 /* num_buckets */, num_buckets, 0);
                fbb.AddElement<uint64_t>(6 /* bits_per_tag */, bits_per_tag, 0);
                fbb.AddOffset(8 /* table */, table_vec);
                return fbb.EndTable(start);
            }();

            const flatbuffers::uoffset_t overflow_off = [&] {
                flatbuffers::uoffset_t start = fbb.StartTable();
                fbb.AddElement<uint64_t>(4 /* index */, overflow_index, 0);
                fbb.AddElement<uint64_t>(6 /* tag */, 1, 0);
                fbb.AddElement<uint8_t>(8 /* used */, overflow_used ? 1 : 0, 0);
                return fbb.EndTable(start);
            }();

            const flatbuffers::uoffset_t filter_off = [&] {
                flatbuffers::uoffset_t start = fbb.StartTable();
                fbb.AddOffset(4 /* table */, flatbuffers::Offset<void>(table_off));
                fbb.AddElement<uint64_t>(6 /* num_items */, 0, 0);
                fbb.AddOffset(8 /* overflow */, flatbuffers::Offset<void>(overflow_off));
                return fbb.EndTable(start);
            }();

            fbb.FinishSizePrefixed(flatbuffers::Offset<void>(filter_off));
            return { reinterpret_cast<const char *>(fbb.GetBufferPointer()), fbb.GetSize() };
        }

        CuckooFilter load_cuckoo_filter(const string &buffer)
        {
            stringstream ss(buffer);
            size_t bytes_read = 0;
            return CuckooFilter::Load(ss, bytes_read);
        }
    } // namespace

    TEST(SenderUtilsTests, CuckooFilterLoadRejectsInconsistentFields)
    {
        constexpr uint64_t bits_per_tag = 12;
        constexpr uint64_t num_buckets = 64;
        constexpr size_t required_words = ((4 * bits_per_tag * num_buckets) + 63) / 64;

        // A table too small for the buckets it declares. Every read and write bounds the bucket
        // against num_buckets and then indexes the table at a position derived from it, so this
        // reads and writes past the end of the vector.
        ASSERT_THROW(
            load_cuckoo_filter(make_cuckoo_filter_buffer(num_buckets, bits_per_tag, 1, 0, false)),
            runtime_error);

        // An overflow slot in use naming a bucket the table does not have. try_eliminate_overflow
        // hands that bucket to the table on the next successful removal.
        ASSERT_THROW(
            load_cuckoo_filter(make_cuckoo_filter_buffer(
                num_buckets, bits_per_tag, required_words, num_buckets, true)),
            runtime_error);

        // A consistent buffer loads.
        ASSERT_NO_THROW(load_cuckoo_filter(
            make_cuckoo_filter_buffer(num_buckets, bits_per_tag, required_words, 0, false)));
    }

    TEST(SenderUtilsTests, SaveLoadPreservesThatAFilterHasDroppedItems)
    {
        // A filter that has refused an item no longer knows everything it was asked to hold, so
        // its negative answers stop being conclusive. That fact has to survive serialization:
        // a reloaded filter which believed itself complete would start reporting items absent
        // that its caller had stored elsewhere.
        //
        // These nine values share a 12-bit fingerprint, which saturates both buckets that
        // fingerprint can occupy plus the single overflow slot. The tenth is then refused.
        const array<uint64_t, 9> colliding{
            1, 252, 11389, 12874, 17547, 21064, 37127, 40541, 41546,
        };

        CuckooFilter filter(/* key_count */ 16, /* bits_per_tag */ 12);
        for (uint64_t item : colliding) {
            ASSERT_TRUE(filter.add(item));
        }
        ASSERT_FALSE(filter.has_dropped_items());

        ASSERT_FALSE(filter.add(100000));
        ASSERT_TRUE(filter.has_dropped_items());

        stringstream ss;
        filter.save(ss);

        size_t bytes_read = 0;
        CuckooFilter loaded = CuckooFilter::Load(ss, bytes_read);
        ASSERT_TRUE(loaded.has_dropped_items());

        // Everything the filter did hold is still there.
        for (uint64_t item : colliding) {
            ASSERT_TRUE(loaded.contains(item));
        }
    }

    TEST(SenderUtilsTests, SaveLoadPreservesThatAFilterHasNotDroppedItems)
    {
        // The other side of the previous test. A filter that stored everything it was given must
        // still say so after a round trip, or every reloaded filter would answer the safe way and
        // no negative answer would ever be conclusive again.
        CuckooFilter filter(/* key_count */ 50, /* bits_per_tag */ 12);
        for (uint64_t i = 0; i < 20; i++) {
            ASSERT_TRUE(filter.add(i));
        }
        ASSERT_FALSE(filter.has_dropped_items());

        stringstream ss;
        filter.save(ss);

        size_t bytes_read = 0;
        CuckooFilter loaded = CuckooFilter::Load(ss, bytes_read);
        ASSERT_FALSE(loaded.has_dropped_items());
    }

    TEST(SenderUtilsTests, AFilterThatMakesNoClaimIsLoadedAsHavingDroppedItems)
    {
        // A filter written before the schema recorded this says nothing either way, and a filter
        // whose caller ignored a refusal looks exactly like one that was never refused. Neither
        // can be trusted to answer conclusively, so absence of the claim is read as a drop.
        //
        // make_cuckoo_filter_buffer omits the field, which is precisely what an older version
        // wrote. The claim is stored positively so that this stays true: were it stored as
        // "dropped", a filter that had dropped items would encode that as the default value and
        // FlatBuffers would leave it out, making it indistinguishable from a clean one.
        constexpr uint64_t bits_per_tag = 12;
        constexpr uint64_t num_buckets = 64;
        constexpr size_t required_words = ((4 * bits_per_tag * num_buckets) + 63) / 64;

        CuckooFilter loaded = load_cuckoo_filter(
            make_cuckoo_filter_buffer(num_buckets, bits_per_tag, required_words, 0, false));
        ASSERT_TRUE(loaded.has_dropped_items());
    }

    TEST(SenderUtilsTests, RemovingAnItemThatWasNeverAddedCanLoseAnother)
    {
        // A filter stores fingerprints, not items, so it cannot tell two items with the same
        // fingerprint apart. Removing one that was never added therefore deletes a fingerprint
        // belonging to whichever item does hold it, and that item is then reported absent even
        // though nothing about it changed.
        //
        // This is why CuckooFilter::remove documents that it may only be called for an item known
        // to be in the set, and why BinBundle::try_multi_remove locates every item in its bin
        // before removing any of them. The behaviour is pinned here so that a future change which
        // makes removal speculative fails rather than silently reintroducing false negatives.
        CuckooFilter filter(/* key_count */ 50, /* bits_per_tag */ 12);
        ASSERT_TRUE(filter.add(1));
        ASSERT_TRUE(filter.contains(1));

        // 40541 was never added, but shares a fingerprint with 1.
        ASSERT_TRUE(filter.remove(40541));

        // The filter now denies an item it was holding, and nothing in its own state says so.
        ASSERT_FALSE(filter.contains(1));
        ASSERT_FALSE(filter.has_dropped_items());
    }
} // namespace APSITests
