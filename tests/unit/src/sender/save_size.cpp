// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <utility>
#include <vector>

// APSI
#include "apsi/bin_bundle_generated.h"
#include "apsi/oprf/oprf_common.h"
#include "apsi/psi_params.h"
#include "apsi/util/save_size.h"
#include "apsi/util/utils.h"

// FlatBuffers
#include "flatbuffers/flatbuffers.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi::sender::util;

namespace APSITests {
    namespace {
        constexpr size_t max_size = apsi::util::max_buffer_size;

        /**
        The voffset and kind of each field of a table
        */
        using TableLayout = vector<pair<flatbuffers::voffset_t, size_t>>;

        /**
        Builds a table of fields of every kind, in any order, with fbb, adds it to bounds, and
        records it in built. Half the time it is laid out as one of layouts, so that tables share
        vtables, and otherwise in a new layout, which is added to layouts. A scalar is zero, its
        default, a fifth of the time, and is then not added.
        */
        void add_random_table(
            flatbuffers::FlatBufferBuilder &fbb,
            FlatBufferSizeBounds &bounds,
            vector<flatbuffers::uoffset_t> &built,
            vector<TableLayout> &layouts,
            mt19937_64 &rng)
        {
            auto pick = [&](size_t bound) {
                return static_cast<size_t>(rng() % (bound + 1));
            };

            if (layouts.empty() || pick(1)) {
                // A field is an offset (0), a scalar of 1, 2, 4 or 8 bytes (1 to 4), or an
                // ItemHash (5)
                TableLayout layout;
                for (flatbuffers::voffset_t voffset = 4; voffset < 36; voffset += 2) {
                    if (!pick(3)) {
                        layout.emplace_back(voffset, pick(5));
                    }
                }
                shuffle(layout.begin(), layout.end(), rng);
                layouts.push_back(std::move(layout));
            }

            vector<FlatBufferField> fields;
            flatbuffers::uoffset_t start = fbb.StartTable();
            for (const auto &[voffset, kind] : layouts[pick(layouts.size() - 1)]) {
                uint64_t value = pick(4) ? rng() | 1 : 0;
                switch (kind) {
                case 0:
                    if (!built.empty()) {
                        fbb.AddOffset(
                            voffset, flatbuffers::Offset<void>(built[pick(built.size() - 1)]));
                        fields.push_back(offset_field(voffset));
                    }
                    break;
                case 1:
                    fbb.AddElement<uint8_t>(voffset, static_cast<uint8_t>(value), 0);
                    if (value) {
                        fields.push_back(scalar_field<uint8_t>(voffset));
                    }
                    break;
                case 2:
                    fbb.AddElement<uint16_t>(voffset, static_cast<uint16_t>(value), 0);
                    if (value) {
                        fields.push_back(scalar_field<uint16_t>(voffset));
                    }
                    break;
                case 3:
                    fbb.AddElement<uint32_t>(voffset, static_cast<uint32_t>(value), 0);
                    if (value) {
                        fields.push_back(scalar_field<uint32_t>(voffset));
                    }
                    break;
                case 4:
                    fbb.AddElement<uint64_t>(voffset, value, 0);
                    if (value) {
                        fields.push_back(scalar_field<uint64_t>(voffset));
                    }
                    break;
                default: {
                    apsi::fbs::ItemHash item_hash(value, ~value);
                    fbb.AddStruct(voffset, &item_hash);
                    fields.push_back(struct_field<apsi::fbs::ItemHash>(voffset));
                    break;
                }
                }
            }
            built.push_back(fbb.EndTable(start));
            bounds.add_table(fields.data(), fields.size());
        }

        /**
        Builds the same random vectors and tables with a FlatBufferBuilder and a
        FlatBufferSizeBounds, and checks that each of them, and finishing the buffer, adds to the
        size of the builder's buffer no less than it adds to the lower bound, and no more than it
        adds to the upper bound.
        */
        void build_at_random(mt19937_64 &rng)
        {
            flatbuffers::FlatBufferBuilder fbb(1);
            FlatBufferSizeBounds bounds;
            SaveSizeBounds checked_bounds;
            size_t checked_size = 0;
            auto check_bounds = [&] {
                size_t added = fbb.GetSize() - checked_size;
                ASSERT_LE(bounds.bounds().lower - checked_bounds.lower, added);
                ASSERT_GE(bounds.bounds().upper - checked_bounds.upper, added);
                checked_bounds = bounds.bounds();
                checked_size = fbb.GetSize();
            };

            // What has been built, for tables and vectors of offsets to refer to, and the layouts
            // of the tables
            vector<flatbuffers::uoffset_t> built;
            vector<TableLayout> layouts;
            auto pick = [&](size_t bound) {
                return static_cast<size_t>(rng() % (bound + 1));
            };

            size_t op_count = 1 + pick(40);
            for (size_t op = 0; op < op_count; op++) {
                size_t count = pick(op % 4 ? 3 : 40);
                switch (pick(5)) {
                case 0: {
                    // Bytes, whose count the bounds know only within a range
                    vector<uint8_t> v(count, 0x5A);
                    built.push_back(fbb.CreateVector(v.data(), v.size()).o);
                    bounds.add_vector(SaveSizeBounds{ count / 2, count + pick(9) }, 1, 1);
                    break;
                }
                case 1: {
                    vector<uint16_t> v(count, 0x5A5A);
                    built.push_back(fbb.CreateVector(v.data(), v.size()).o);
                    bounds.add_vector(count, sizeof(uint16_t), sizeof(uint16_t));
                    break;
                }
                case 2: {
                    vector<uint64_t> v(count, 0x5A5A5A5A5A5A5A5AULL);
                    built.push_back(fbb.CreateVector(v.data(), v.size()).o);
                    bounds.add_vector(count, sizeof(uint64_t), sizeof(uint64_t));
                    break;
                }
                case 3: {
                    vector<apsi::fbs::ItemHash> v(count, apsi::fbs::ItemHash(1, 2));
                    built.push_back(fbb.CreateVectorOfStructs(v).o);
                    bounds.add_vector(
                        count,
                        sizeof(apsi::fbs::ItemHash),
                        flatbuffers::AlignOf<apsi::fbs::ItemHash>());
                    break;
                }
                case 4: {
                    // A vector of offsets to what has been built
                    vector<flatbuffers::Offset<void>> v;
                    for (size_t i = 0; !built.empty() && (i < count); i++) {
                        v.emplace_back(built[pick(built.size() - 1)]);
                    }
                    built.push_back(fbb.CreateVector(v.data(), v.size()).o);
                    bounds.add_vector(
                        v.size(), sizeof(flatbuffers::uoffset_t), sizeof(flatbuffers::uoffset_t));
                    break;
                }
                default:
                    add_random_table(fbb, bounds, built, layouts, rng);
                    break;
                }
                ASSERT_NO_FATAL_FAILURE(check_bounds());
            }

            fbb.FinishSizePrefixed(flatbuffers::Offset<void>(built.back()));
            bounds.finish_size_prefixed();
            ASSERT_NO_FATAL_FAILURE(check_bounds());

            // The size prefix gives the size of the rest
            ASSERT_EQ(
                fbb.GetSize() - sizeof(flatbuffers::uoffset_t),
                flatbuffers::ReadScalar<flatbuffers::uoffset_t>(fbb.GetBufferPointer()));
        }
    } // namespace

    TEST(SaveSizeTests, BoundsBracketWhatTheBuilderBuilds)
    {
        mt19937_64 rng(0x5A5E);
        for (int run = 0; run < 500; run++) {
            SCOPED_TRACE(run);
            build_at_random(rng);
            if (HasFatalFailure()) {
                return;
            }
        }
    }

    TEST(SaveSizeTests, UnstrippedHeaderHoldsAbout134MillionItems)
    {
        // The header that SenderDB::save writes ahead of the BinBundles holds the HashedItem of
        // every item unless the SenderDB is stripped. With parameters for 256 million items, the
        // HashedItems of that many take 4.1 GB, so an unstripped SenderDB can be saved with no
        // more than about 134 million items; stripped, the header takes a few hundred bytes.
        ifstream file(filesystem::path(APSI_PARAMETERS_DIR) / "256M-1.json");
        ASSERT_TRUE(file.is_open());
        stringstream json;
        json << file.rdbuf();
        stringstream params_ss;
        size_t params_byte_count = apsi::PSIParams::Load(json.str()).save(params_ss);

        auto header_bounds = [&](size_t item_count) {
            return sender_db_header_save_size_bounds(
                params_byte_count, apsi::oprf::oprf_key_size, item_count, 1);
        };
        ASSERT_LT(header_bounds(0).upper, size_t(1000));
        ASSERT_GT(header_bounds(256000000).lower, size_t(4096000000));

        // Every item adds 16 bytes to both bounds, and the rest stays the same
        size_t fixed_size = header_bounds(0).upper;
        size_t max_item_count = (max_size - fixed_size) / 16;
        ASSERT_EQ(fixed_size + 16 * max_item_count, header_bounds(max_item_count).upper);
        ASSERT_LE(header_bounds(max_item_count).upper, max_size);
        ASSERT_GT(header_bounds(max_item_count + 1).upper, max_size);
        ASSERT_GT(max_item_count, size_t(134000000));
        ASSERT_LT(max_item_count, size_t(134217728));
    }

    TEST(SaveSizeTests, ScopedSaveSizeLimitOnlyLowersTheLimit)
    {
        ASSERT_EQ(max_size, save_size_limit());
        {
            ScopedSaveSizeLimit lower(1000);
            ASSERT_EQ(size_t(1000), save_size_limit());
            {
                ScopedSaveSizeLimit higher(max_size + 1000);
                ASSERT_EQ(size_t(1000), save_size_limit());
                ScopedSaveSizeLimit lowest(10);
                ASSERT_EQ(size_t(10), save_size_limit());
            }
            ASSERT_EQ(size_t(1000), save_size_limit());
        }
        ASSERT_EQ(max_size, save_size_limit());
    }
} // namespace APSITests
