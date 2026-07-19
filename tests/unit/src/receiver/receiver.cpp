// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <unordered_set>
#include <utility>
#include <vector>

// APSI
#include "apsi/item.h"
#include "apsi/network/sender_operation.h"
#include "apsi/psi_params.h"
#include "apsi/receiver.h"
#include "apsi/requests.h"
#include "apsi/seal_object.h"

// SEAL
#include "seal/modulus.h"
#include "seal/relinkeys.h"
#include "seal/serialization.h"

// GSL
#include "gsl/span"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::network;
using namespace apsi::receiver;
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

        HashedItem make_hashed_item(uint64_t lw, uint64_t hw)
        {
            // HashedItem inherits Item's (uint64_t, uint64_t) constructor — sidestepping the
            // OPRF flow lets us exercise create_query/IndexTranslationTable without standing up
            // a sender, but the values are not real OPRF outputs.
            return HashedItem{ lw, hw };
        }

        vector<unsigned char> save_relin_keys(const SEALObject<RelinKeys> &keys)
        {
            size_t size = keys.save_size(compr_mode_type::none);
            vector<unsigned char> buf(size);
            keys.save(gsl::span<unsigned char>(buf.data(), buf.size()), compr_mode_type::none);
            return buf;
        }
    } // namespace

    TEST(ReceiverApiTests, ConstructFromParams)
    {
        Receiver receiver(make_test_params());

        // PowersDag and CryptoContext should be populated and consistent with the params.
        ASSERT_EQ(size_t{ 3 }, receiver.get_powers_dag().source_nodes().size());
        ASSERT_NE(nullptr, receiver.get_seal_context());
        ASSERT_TRUE(receiver.get_seal_context()->parameters_set());
        ASSERT_NE(nullptr, receiver.get_crypto_context().seal_context());
    }

    TEST(ReceiverApiTests, CreateParamsRequestProducesParmsType)
    {
        Request req = Receiver::CreateParamsRequest();
        ASSERT_NE(nullptr, req);
        ASSERT_EQ(SenderOperationType::sop_parms, req->type());

        // The to_*_request downcasts should match the type discriminant.
        ASSERT_NE(nullptr, to_params_request(std::move(req)));
    }

    TEST(ReceiverApiTests, CreateOPRFRequestProducesOprfType)
    {
        vector<Item> items;
        items.emplace_back(uint64_t{ 1 }, uint64_t{ 2 });
        items.emplace_back(uint64_t{ 3 }, uint64_t{ 4 });

        auto oprf_recv = Receiver::CreateOPRFReceiver(items);
        ASSERT_EQ(items.size(), oprf_recv.item_count());

        Request req = Receiver::CreateOPRFRequest(oprf_recv);
        ASSERT_NE(nullptr, req);
        ASSERT_EQ(SenderOperationType::sop_oprf, req->type());
        ASSERT_NE(nullptr, to_oprf_request(std::move(req)));
    }

    TEST(ReceiverApiTests, CreateQueryReturnsQueryRequest)
    {
        Receiver receiver(make_test_params());

        vector<HashedItem> items;
        items.push_back(make_hashed_item(1, 2));
        items.push_back(make_hashed_item(3, 4));
        items.push_back(make_hashed_item(5, 6));

        auto query = receiver.create_query(items);
        Request &req = query.first;

        ASSERT_NE(nullptr, req);
        ASSERT_EQ(SenderOperationType::sop_query, req->type());

        // The downcast should succeed; the underlying QueryRequest should hold ciphertexts for
        // each source power configured in PSIParams::QueryParams.
        auto query_req = to_query_request(std::move(req));
        ASSERT_NE(nullptr, query_req);
        ASSERT_EQ(size_t{ 3 }, query_req->data.size());
        ASSERT_NE(query_req->data.end(), query_req->data.find(1));
        ASSERT_NE(query_req->data.end(), query_req->data.find(3));
        ASSERT_NE(query_req->data.end(), query_req->data.find(5));
    }

    TEST(ReceiverApiTests, IndexTranslationTableItemCount)
    {
        Receiver receiver(make_test_params());

        vector<HashedItem> items;
        items.push_back(make_hashed_item(1, 2));
        items.push_back(make_hashed_item(3, 4));
        items.push_back(make_hashed_item(5, 6));
        items.push_back(make_hashed_item(7, 8));
        items.push_back(make_hashed_item(9, 10));

        auto [req, itt] = receiver.create_query(items);
        ASSERT_EQ(items.size(), itt.item_count());
    }

    TEST(ReceiverApiTests, IndexTranslationTableUnpopulatedReturnsItemCount)
    {
        PSIParams params = make_test_params();
        size_t table_size = params.table_params().table_size;
        Receiver receiver(params);

        vector<HashedItem> items;
        items.push_back(make_hashed_item(1, 2));
        items.push_back(make_hashed_item(3, 4));

        auto [req, itt] = receiver.create_query(items);

        // With only two items inserted into a 512-slot cuckoo table, the vast majority of slots
        // are unpopulated. The contract states unpopulated indices return item_count().
        size_t miss_count = 0;
        for (size_t table_idx = 0; table_idx < table_size; table_idx++) {
            if (itt.find_item_idx(table_idx) == itt.item_count()) {
                miss_count++;
            }
        }
        // At minimum, table_size - hash_func_count * item_count slots must be misses; with
        // two items and three hash functions that's at least 512 - 6 = 506.
        ASSERT_GE(miss_count, size_t{ 506 });
    }

    TEST(ReceiverApiTests, IndexTranslationTablePopulatedIndicesCoverAllItems)
    {
        PSIParams params = make_test_params();
        size_t table_size = params.table_params().table_size;
        Receiver receiver(params);

        vector<HashedItem> items;
        items.push_back(make_hashed_item(1, 2));
        items.push_back(make_hashed_item(3, 4));
        items.push_back(make_hashed_item(5, 6));
        items.push_back(make_hashed_item(7, 8));

        auto [req, itt] = receiver.create_query(items);

        // Every input item index must appear in the table at least once. We do not assume
        // anything about which slot maps where (that is cuckoo-internal), only that every item
        // is reachable from some populated slot.
        unordered_set<size_t> seen_item_indices;
        for (size_t table_idx = 0; table_idx < table_size; table_idx++) {
            size_t item_idx = itt.find_item_idx(table_idx);
            if (item_idx != itt.item_count()) {
                ASSERT_LT(item_idx, items.size());
                seen_item_indices.insert(item_idx);
            }
        }
        ASSERT_EQ(items.size(), seen_item_indices.size());
    }

    TEST(ReceiverApiTests, ResetKeysProducesDifferentRelinKeys)
    {
        Receiver receiver(make_test_params());

        vector<HashedItem> items;
        items.push_back(make_hashed_item(1, 2));

        auto query1_req = to_query_request(receiver.create_query(items).first);
        ASSERT_NE(nullptr, query1_req);
        vector<unsigned char> buf_before = save_relin_keys(query1_req->relin_keys);

        receiver.reset_keys();

        auto query2_req = to_query_request(receiver.create_query(items).first);
        ASSERT_NE(nullptr, query2_req);
        vector<unsigned char> buf_after = save_relin_keys(query2_req->relin_keys);

        // The relin keys are derived from a freshly drawn secret key, so the serialized blobs
        // should differ. (They could in principle collide, but the probability is cryptographically
        // negligible — a collision would be a far bigger bug than this test failing once.)
        ASSERT_NE(buf_before, buf_after);
    }
} // namespace APSITests
