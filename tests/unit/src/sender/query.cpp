// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <cstdint>
#include <memory>
#include <sstream>
#include <utility>
#include <vector>

// APSI
#include "apsi/item.h"
#include "apsi/network/sender_operation.h"
#include "apsi/network/stream_channel.h"
#include "apsi/psi_params.h"
#include "apsi/query.h"
#include "apsi/receiver.h"
#include "apsi/requests.h"
#include "apsi/sender.h"
#include "apsi/sender_db.h"

// SEAL
#include "seal/context.h"
#include "seal/evaluator.h"
#include "seal/modulus.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::network;
using namespace apsi::receiver;
using namespace apsi::sender;
using namespace seal;

namespace APSITests {
    namespace {
        PSIParams make_test_params()
        {
            PSIParams::ItemParams item_params;
            item_params.felts_per_item = 8;

            PSIParams::TableParams table_params;
            table_params.hash_func_count = 3;
            table_params.max_items_per_bin = 16;
            table_params.table_size = 512;

            PSIParams::QueryParams query_params;
            query_params.query_powers = { 1, 3, 5 };

            size_t pmd = 4096;
            PSIParams::SEALParams seal_params;
            seal_params.set_poly_modulus_degree(pmd);
            seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
            seal_params.set_plain_modulus(65537);

            return { item_params, table_params, query_params, seal_params };
        }

        // Same as make_test_params but with a different bundle_idx_count. The SEAL parameters are
        // left alone so that relinearization keys built for one remain valid for the other.
        PSIParams make_wider_params()
        {
            PSIParams::ItemParams item_params;
            item_params.felts_per_item = 8;

            PSIParams::TableParams table_params;
            table_params.hash_func_count = 3;
            table_params.max_items_per_bin = 16;
            table_params.table_size = 1024;

            PSIParams::QueryParams query_params;
            query_params.query_powers = { 1, 3, 5 };

            size_t pmd = 4096;
            PSIParams::SEALParams seal_params;
            seal_params.set_poly_modulus_degree(pmd);
            seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
            seal_params.set_plain_modulus(65537);

            return { item_params, table_params, query_params, seal_params };
        }

        // Same as make_test_params but with a smaller max_items_per_bin. table_size and the SEAL
        // parameters are unchanged, so the bundle count and the relinearization keys still match
        // and only the PowersDag disagrees.
        PSIParams make_shallow_params()
        {
            PSIParams::ItemParams item_params;
            item_params.felts_per_item = 8;

            PSIParams::TableParams table_params;
            table_params.hash_func_count = 3;
            table_params.max_items_per_bin = 8;
            table_params.table_size = 512;

            PSIParams::QueryParams query_params;
            query_params.query_powers = { 1, 3, 5 };

            size_t pmd = 4096;
            PSIParams::SEALParams seal_params;
            seal_params.set_poly_modulus_degree(pmd);
            seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
            seal_params.set_plain_modulus(65537);

            return { item_params, table_params, query_params, seal_params };
        }

        // Builds a query exactly as a well-behaved receiver would.
        QueryRequest make_honest_query(const PSIParams &params)
        {
            Receiver receiver(params);
            vector<HashedItem> items{ HashedItem{ 1, 1 }, HashedItem{ 2, 2 } };
            return to_query_request(receiver.create_query(items).first);
        }

        // Replaces one of the query's source-power ciphertexts with a tampered version, the way a
        // malicious receiver or an active man in the middle would.
        template <typename Tamper>
        void tamper_with_a_ciphertext(
            const QueryRequest &query, const shared_ptr<SEALContext> &context, Tamper tamper)
        {
            auto &cts = query->data.begin()->second;
            Ciphertext ct = cts[0].extract(context);
            tamper(ct);
            cts[0].set(std::move(ct));
        }
    } // namespace

    TEST(QueryTests, AcceptsHonestQuery)
    {
        auto sender_db = make_shared<SenderDB>(make_test_params());
        Query query(make_honest_query(sender_db->get_params()), sender_db);
        ASSERT_TRUE(query.is_valid());
    }

    TEST(QueryTests, RejectsModulusSwitchedCiphertext)
    {
        auto sender_db = make_shared<SenderDB>(make_test_params());
        auto context = sender_db->get_seal_context();
        Evaluator evaluator(*context);

        // Sender::ComputePowers multiplies source powers together, which SEAL rejects when the
        // operands sit at different levels of the modulus chain.
        QueryRequest request = make_honest_query(sender_db->get_params());
        tamper_with_a_ciphertext(request, context, [&evaluator](Ciphertext &ct) {
            evaluator.mod_switch_to_next_inplace(ct);
        });

        Query query(std::move(request), sender_db);
        ASSERT_FALSE(query.is_valid());
    }

    TEST(QueryTests, RejectsNttFormCiphertext)
    {
        auto sender_db = make_shared<SenderDB>(make_test_params());
        auto context = sender_db->get_seal_context();
        Evaluator evaluator(*context);

        // The sender transforms powers to NTT form itself, after the DAG has been evaluated;
        // an NTT-form operand makes Evaluator::multiply throw.
        QueryRequest request = make_honest_query(sender_db->get_params());
        tamper_with_a_ciphertext(request, context, [&evaluator](Ciphertext &ct) {
            evaluator.transform_to_ntt_inplace(ct);
        });

        Query query(std::move(request), sender_db);
        ASSERT_FALSE(query.is_valid());
    }

    TEST(QueryTests, RejectsOversizeCiphertext)
    {
        auto sender_db = make_shared<SenderDB>(make_test_params());
        auto context = sender_db->get_seal_context();
        Evaluator evaluator(*context);

        // A ciphertext larger than a fresh encryption outruns the relinearization keys.
        QueryRequest request = make_honest_query(sender_db->get_params());
        tamper_with_a_ciphertext(request, context, [&evaluator](Ciphertext &ct) {
            Ciphertext squared;
            evaluator.square(ct, squared);
            ct = std::move(squared);
        });

        Query query(std::move(request), sender_db);
        ASSERT_FALSE(query.is_valid());
    }

    TEST(QueryTests, RunQueryRejectsAQueryThatNoLongerMatchesTheSenderDB)
    {
        // A Query checks its data against the SenderDB's parameters when it is built, and
        // RunQuery reads those parameters again. RunQuery indexes the query data by counts taken
        // from its own read and does so without bounds checks, so it must reject a query that the
        // parameters it reads no longer describe.
        auto sender_db = make_shared<SenderDB>(make_test_params(), 0);
        Query query(make_honest_query(sender_db->get_params()), sender_db);
        ASSERT_TRUE(query.is_valid());

        // Replace the database with one whose bundle_idx_count differs. The query still holds the
        // ciphertext counts required by the old parameters.
        *sender_db = SenderDB(make_wider_params(), 0);

        stringstream ss;
        StreamChannel chl(ss);
        ASSERT_THROW(Sender::RunQuery(query, chl), invalid_argument);

        // The rejection must come before the QueryResponse is sent. Failing later leaves the
        // receiver waiting for packages that never arrive, and means the query was already being
        // indexed by counts it does not match.
        ASSERT_TRUE(ss.str().empty());
    }

    TEST(QueryTests, RunQueryRejectsAQueryWhosePowersDagNoLongerMatches)
    {
        // A Query configures its PowersDag from max_items_per_bin, and RunQuery sizes each
        // bundle's power vector from its own read of that value and then indexes it by the DAG's
        // node powers. A database whose bundle count and SEAL parameters are unchanged passes
        // every check on the query data itself, so the DAG must be checked separately: otherwise
        // the powers above the new maximum are written past the end of the vector, and after the
        // QueryResponse has already been sent.
        auto sender_db = make_shared<SenderDB>(make_test_params(), 0);
        Query query(make_honest_query(sender_db->get_params()), sender_db);
        ASSERT_TRUE(query.is_valid());

        auto replacement = SenderDB(make_shallow_params(), 0);
        replacement.insert_or_assign(Item(3, 3));
        *sender_db = std::move(replacement);

        stringstream ss;
        StreamChannel chl(ss);
        ASSERT_THROW(Sender::RunQuery(query, chl), invalid_argument);
        ASSERT_TRUE(ss.str().empty());
    }
} // namespace APSITests
