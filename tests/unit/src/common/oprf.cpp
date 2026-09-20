// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>

// APSI
#include "apsi/oprf/oprf_receiver.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/randomgen.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::oprf;

namespace APSITests {
    TEST(OPRFTests, OPRFKeyCreate)
    {
        // Creates a random key
        OPRFKey oprf_key;

        // Set the key to zero
        oprf_key.clear();
        auto oprf_key_span = oprf_key.key_span();
        ASSERT_TRUE(
            all_of(oprf_key_span.begin(), oprf_key_span.end(), [](auto a) { return a == 0; }));

        // Create some new random keys
        oprf_key.create();
        ASSERT_FALSE(
            all_of(oprf_key_span.begin(), oprf_key_span.end(), [](auto a) { return a == 0; }));
        OPRFKey oprf_key2;
        auto oprf_key2_span = oprf_key2.key_span();
        ASSERT_FALSE(
            all_of(oprf_key2_span.begin(), oprf_key2_span.end(), [](auto a) { return a == 0; }));
        ASSERT_FALSE(equal(oprf_key_span.begin(), oprf_key_span.end(), oprf_key2_span.begin()));
    }

    TEST(OPRFTests, OPRFKeySaveLoad)
    {
        OPRFKey oprf_key;
        stringstream ss;
        oprf_key.save(ss);
        OPRFKey oprf_key2;
        oprf_key2.load(ss);

        auto oprf_key_span = oprf_key.key_span();
        auto oprf_key2_span = oprf_key2.key_span();
        ASSERT_TRUE(equal(oprf_key_span.begin(), oprf_key_span.end(), oprf_key2_span.begin()));
    }

    TEST(OPRFTests, OPRFOperation)
    {
        size_t item_count = 100;
        vector<Item> items;

        shared_ptr<UniformRandomGeneratorFactory> rng_factory(make_shared<Blake2xbPRNGFactory>());
        auto rng = rng_factory->create();
        for (size_t i = 0; i < item_count; i++) {
            Item it;
            rng->generate(sizeof(Item), reinterpret_cast<seal_byte *>(it.value().data()));
            items.push_back(it);
        }

        // Create random key
        OPRFKey oprf_key;

        vector<HashedItem> out_items = OPRFSender::ComputeHashes(items, oprf_key);

        vector<Item> items_vec(items.begin(), items.end());
        OPRFReceiver receiver(items_vec);
        auto query = receiver.query_data();

        vector<unsigned char> responses = OPRFSender::ProcessQueries(query, oprf_key);

        vector<HashedItem> receiver_hashes(item_count);
        vector<LabelKey> label_keys(item_count);
        receiver.process_responses(responses, receiver_hashes, label_keys);

        for (auto &recv_hash : receiver_hashes) {
            bool found = out_items.end() !=
                         find_if(out_items.begin(), out_items.end(), [&](HashedItem &item) {
                             return item == recv_hash;
                         });
            ASSERT_TRUE(found);
        }
    }

    TEST(OPRFTests, ProcessQueriesRejectsTooManyItems)
    {
        OPRFKey oprf_key;

        // The work is one scalar multiplication per item and lands entirely on the sender, whose
        // dispatcher serves one request at a time, so an unbounded request occupies it for as long
        // as the request takes while every other peer waits. The bound is checked here rather than
        // only at the protocol call site, so that every caller of the primitive is covered.
        //
        // The buffer is never processed, only measured, so sizing one at the limit costs nothing.
        vector<unsigned char> too_many((oprf_query_count_max + 1) * oprf_query_size);
        ASSERT_THROW((void)OPRFSender::ProcessQueries(too_many, oprf_key), invalid_argument);

        // A ragged buffer is still rejected on its own grounds.
        vector<unsigned char> ragged(oprf_query_size + 1);
        ASSERT_THROW((void)OPRFSender::ProcessQueries(ragged, oprf_key), invalid_argument);

        // An ordinary request is unaffected. The largest shipped parameter set recommends 11041
        // receiver items, so the bound leaves roughly two orders of magnitude of headroom.
        vector<unsigned char> ordinary(4 * oprf_query_size);
        OPRFReceiver oprf_receiver(vector<Item>(4));
        auto query = oprf_receiver.query_data();
        copy(query.cbegin(), query.cend(), ordinary.begin());
        ASSERT_NO_THROW((void)OPRFSender::ProcessQueries(ordinary, oprf_key));
    }

    TEST(OPRFTests, Hash2Curve)
    {
        {
            std::array<unsigned char, 1> val{ 0 };
            ECPoint pt(val);
            std::array<unsigned char, ECPoint::save_size> buf{};
            pt.save(buf);
            uint64_t w1 = *reinterpret_cast<uint64_t *>(buf.data());
            uint64_t w2 = *reinterpret_cast<uint64_t *>(buf.data() + 8);
            uint64_t w3 = *reinterpret_cast<uint64_t *>(buf.data() + 16);
            uint64_t w4 = *reinterpret_cast<uint64_t *>(buf.data() + 24);

            ASSERT_EQ(16185258159125907415ULL, w1);
            ASSERT_EQ(4603673558532365532ULL, w2);
            ASSERT_EQ(16070562417338412736ULL, w3);
            ASSERT_EQ(16055866365372562508ULL, w4);
        }
        {
            std::array<unsigned char, 2> val{ 0, 0 };
            ECPoint pt(val);
            std::array<unsigned char, ECPoint::save_size> buf{};
            pt.save(buf);
            uint64_t w1 = *reinterpret_cast<uint64_t *>(buf.data());
            uint64_t w2 = *reinterpret_cast<uint64_t *>(buf.data() + 8);
            uint64_t w3 = *reinterpret_cast<uint64_t *>(buf.data() + 16);
            uint64_t w4 = *reinterpret_cast<uint64_t *>(buf.data() + 24);

            ASSERT_EQ(1351976583327153065ULL, w1);
            ASSERT_EQ(6824769698500631404ULL, w2);
            ASSERT_EQ(4564688725223058933ULL, w3);
            ASSERT_EQ(17703950788644595294ULL, w4);
        }
        {
            std::array<unsigned char, 16> val{
                0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
            };
            ECPoint pt(val);
            std::array<unsigned char, ECPoint::save_size> buf{};
            pt.save(buf);
            uint64_t w1 = *reinterpret_cast<uint64_t *>(buf.data());
            uint64_t w2 = *reinterpret_cast<uint64_t *>(buf.data() + 8);
            uint64_t w3 = *reinterpret_cast<uint64_t *>(buf.data() + 16);
            uint64_t w4 = *reinterpret_cast<uint64_t *>(buf.data() + 24);

            ASSERT_EQ(14742796689443832496ULL, w1);
            ASSERT_EQ(2501201975610406569ULL, w2);
            ASSERT_EQ(5901317566272664835ULL, w3);
            ASSERT_EQ(15287245637096301833ULL, w4);
        }
    }

    TEST(OPRFTests, LoadAcceptsEveryEncodingSaveProduces)
    {
        // The canonical-encoding requirement on load must never reject what APSI itself writes,
        // so a point has to survive a save/load round trip whatever it hashes to.
        array<unsigned char, ECPoint::save_size> buf{};
        for (unsigned char i = 0; i < 128; i++) {
            array<unsigned char, 16> val{};
            val[0] = i;
            val[15] = static_cast<unsigned char>(0xFF - i);
            ECPoint pt(val);
            pt.save(buf);

            ECPoint loaded;
            ASSERT_NO_THROW(loaded.load(buf));
        }
    }

    TEST(OPRFTests, LoadRejectsNonCanonicalEncodings)
    {
        // A serialized point is two field elements modulo p = 2^127 - 1. decode() masks the sign
        // bit out of the high half but range-checks neither half, and the curve equation it then
        // validates is not sound on an unreduced coordinate, so a large fraction of these would
        // otherwise reach scalar multiplication with the long-term OPRF key. Each iteration
        // corrupts a freshly saved encoding three different ways, all of which name a value that
        // is at or above p and so cannot come from an honest peer.
        array<unsigned char, ECPoint::save_size> buf{};
        for (unsigned char i = 0; i < 128; i++) {
            array<unsigned char, 16> val{};
            val[0] = i;
            ECPoint pt(val);
            ECPoint loaded;

            // Bit 127 of the low half is data, and decode() never clears it.
            pt.save(buf);
            buf[15] |= 0x80;
            ASSERT_THROW(loaded.load(buf), logic_error);

            // The low half becomes exactly p, the redundant encoding of zero.
            pt.save(buf);
            fill_n(buf.begin(), 16, static_cast<unsigned char>(0xFF));
            buf[15] = 0x7F;
            ASSERT_THROW(loaded.load(buf), logic_error);

            // The high half becomes p once its sign bit is masked away.
            pt.save(buf);
            fill_n(buf.begin() + 16, 16, static_cast<unsigned char>(0xFF));
            ASSERT_THROW(loaded.load(buf), logic_error);
        }
    }

    TEST(OPRFTests, LoadFromStreamRejectsNonCanonicalEncodings)
    {
        // The stream overload decodes the same encoding and needs the same guard.
        array<unsigned char, ECPoint::save_size> buf{};
        for (unsigned char i = 0; i < 32; i++) {
            array<unsigned char, 16> val{};
            val[0] = i;
            ECPoint pt(val);
            pt.save(buf);
            buf[15] |= 0x80;

            stringstream ss;
            ss.write(
                reinterpret_cast<const char *>(buf.data()), static_cast<streamsize>(buf.size()));

            ECPoint loaded;
            ASSERT_THROW(loaded.load(ss), logic_error);
        }
    }
    TEST(OPRFTests, ProcessResponsesRejectsPointsOutsidePrimeOrderSubgroup)
    {
        // Only a point of the curve's large prime order is a legitimate response. The vectors
        // below cover what the alternatives look like: the identity, a cofactor-order point with
        // a nonzero x coordinate, an order-eight point, and a point carrying a small-order
        // component alongside a prime-order one. The last is the case a cofactor test alone
        // accepts, since clearing the cofactor leaves its prime-order part behind.
        auto reject = [](const array<unsigned char, ECPoint::save_size> &encoding) {
            vector<Item> items(4);
            for (size_t i = 0; i < items.size(); i++) {
                items[i].value()[0] = static_cast<unsigned char>(i);
            }
            OPRFReceiver receiver(items);

            vector<unsigned char> responses(items.size() * oprf_response_size);
            for (size_t i = 0; i < items.size(); i++) {
                copy_n(
                    encoding.data(), encoding.size(), responses.data() + (i * oprf_response_size));
            }

            vector<HashedItem> hashes(items.size());
            vector<LabelKey> keys(items.size());
            receiver.process_responses(responses, hashes, keys);
        };

        // The neutral element: y = 1, x = 0.
        array<unsigned char, ECPoint::save_size> neutral{};
        neutral[0] = 1;
        ASSERT_THROW(reject(neutral), runtime_error);

        // A cofactor-order point with x != 0.
        array<unsigned char, ECPoint::save_size> small_order{
            0xcf, 0x57, 0x51, 0x3b, 0x1b, 0xd2, 0xb9, 0x3f, 0xbc, 0x6d, 0x29,
            0x9e, 0xd8, 0x1a, 0x3e, 0x69, 0x5d, 0xc9, 0x11, 0x0c, 0x40, 0xd5,
            0x58, 0x87, 0xeb, 0xce, 0xfb, 0x66, 0x22, 0x24, 0x97, 0x3f,
        };
        ASSERT_THROW(reject(small_order), runtime_error);

        // An order-eight point. Unblinding maps this onto a degenerate value that answers the
        // order test differently, so it is caught only while the test is applied to the received
        // point.
        array<unsigned char, ECPoint::save_size> order_eight{
            0xeb, 0xc3, 0x99, 0x6e, 0xc2, 0x88, 0xaa, 0x1d, 0x2c, 0xd0, 0xb2,
            0x9f, 0xea, 0x9c, 0xaf, 0x3c, 0x60, 0x67, 0xc0, 0x79, 0x70, 0x1b,
            0xfc, 0x8f, 0x04, 0xb4, 0x2f, 0xf0, 0xb8, 0xe1, 0xcb, 0x17,
        };
        ASSERT_THROW(reject(order_eight), runtime_error);

        // A point with both a prime-order and a small-order component.
        array<unsigned char, ECPoint::save_size> mixed_order{
            0xc7, 0x93, 0x7e, 0x8c, 0xa0, 0x69, 0x3f, 0xcd, 0xc7, 0xb6, 0x73,
            0x6c, 0x3c, 0xe9, 0x0a, 0x1b, 0x0b, 0x46, 0xbc, 0xcd, 0x69, 0x3b,
            0xf9, 0xdc, 0x22, 0xd4, 0xee, 0x7b, 0xeb, 0x35, 0xdc, 0x79,
        };
        ASSERT_THROW(reject(mixed_order), runtime_error);
    }

    TEST(OPRFTests, ProcessResponsesAcceptsHonestResponses)
    {
        // Honest responses must still be accepted and still agree with the sender.
        vector<Item> items(16);
        for (size_t i = 0; i < items.size(); i++) {
            items[i].value()[0] = static_cast<unsigned char>(i);
            items[i].value()[15] = static_cast<unsigned char>(0xFF - i);
        }
        OPRFKey key;
        OPRFReceiver receiver(items);

        auto responses = OPRFSender::ProcessQueries(receiver.query_data(), key);

        vector<HashedItem> hashes(items.size());
        vector<LabelKey> keys(items.size());
        ASSERT_NO_THROW(receiver.process_responses(responses, hashes, keys));

        // The sender computing the same hashes directly must agree.
        auto direct = OPRFSender::ComputeHashes(items, key);
        ASSERT_EQ(direct.size(), hashes.size());
        for (size_t i = 0; i < hashes.size(); i++) {
            ASSERT_EQ(direct[i], hashes[i]);
        }
    }

    namespace {
        // Painting a region of stack, letting the frame that held it die, and then looking at
        // what a later call disturbed is how the depth of that call is measured. The canvas is
        // four times the scrub window so that a call tree which has outgrown the window is still
        // measurable rather than merely off the end of the ruler.
        constexpr size_t depth_canvas_byte_count = 4 * apsi::util::stack_scrub_byte_count;
        constexpr unsigned char depth_canvas_pattern = 0x5A;

        volatile unsigned char *depth_canvas = nullptr;

#ifdef _MSC_VER
        __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
        __attribute__((noinline))
#endif
        void paint_depth_canvas()
        {
            array<unsigned char, depth_canvas_byte_count> buf{};
            volatile unsigned char *painted = buf.data();
            for (size_t i = 0; i < depth_canvas_byte_count; i++) {
                painted[i] = depth_canvas_pattern;
            }
            depth_canvas = painted;
        }

        // Bytes below the top of the canvas that something disturbed after the painting frame
        // died. The canvas runs low address to high, and the stack grows down, so the first
        // disturbed byte is the deepest point reached.
        size_t depth_reached()
        {
            for (size_t i = 0; i < depth_canvas_byte_count; i++) {
                if (depth_canvas[i] != depth_canvas_pattern) {
                    return depth_canvas_byte_count - i;
                }
            }
            return 0;
        }
    } // namespace

    TEST(OPRFTests, StackDepthFitsScrubWindow)
    {
        // The scrub window is a fixed size chosen to cover the curve arithmetic, and nothing
        // checks that at run time: a call tree that outgrows it is simply covered in part. This
        // measures the depth so that becomes a build failure. It measures the primitives rather
        // than the OPRF entry points, which scrub internally and would report the window back.
        OPRFKey key;
        array<unsigned char, 16> raw{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        paint_depth_canvas();
        {
            ECPoint pt(ECPoint::input_span_const_type(raw.data(), raw.size()));
            ASSERT_TRUE(pt.scalar_multiply(key.key_span(), true));
        }
        size_t normal_depth = depth_reached();

        // Leaving a scope by exception is the deeper path, so it is the one that sizes the
        // window.
        bool threw = false;
        paint_depth_canvas();
        try {
            ECPoint pt(ECPoint::input_span_const_type(raw.data(), raw.size()));
            ASSERT_TRUE(pt.scalar_multiply(key.key_span(), true));
            throw runtime_error("unwind with curve state on the stack");
        } catch (const runtime_error &) {
            threw = true;
        }
        size_t throwing_depth = depth_reached();
        ASSERT_TRUE(threw);

        // The measurement has to have worked at all before its value means anything.
        ASSERT_GT(normal_depth, 0);
        ASSERT_GT(throwing_depth, 0);

        // Fail while there is still margin rather than once coverage is already lost. The depth
        // varies by a factor of three between build types, so the margin has to absorb that
        // without the figure being retuned per compiler.
        constexpr size_t depth_budget = (apsi::util::stack_scrub_byte_count * 3) / 4;
        ASSERT_LT(normal_depth, depth_budget)
            << "the curve arithmetic now reaches " << normal_depth << " bytes, against a "
            << apsi::util::stack_scrub_byte_count << "-byte scrub window. Raise "
            << "util::stack_scrub_byte_count; the scrub is otherwise covering only part of what "
            << "it is meant to erase.";
        ASSERT_LT(throwing_depth, depth_budget)
            << "unwinding now reaches " << throwing_depth << " bytes, against a "
            << apsi::util::stack_scrub_byte_count << "-byte scrub window. Raise "
            << "util::stack_scrub_byte_count; the scrub is otherwise covering only part of what "
            << "it is meant to erase.";
    }
} // namespace APSITests
