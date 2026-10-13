// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

// APSI
#include "apsi/item.h"
#include "apsi/network/result_package.h"
#include "apsi/network/sender_operation.h"
#include "apsi/network/sender_operation_response.h"
#include "apsi/psi_params.h"
#include "apsi/receiver.h"
#include "apsi/requests.h"
#include "apsi/responses.h"
#include "apsi/seal_object.h"
#include "apsi/util/db_encoding.h"
#include "apsi/util/label_encryptor.h"
#include "apsi/util/match_tag.h"

// SEAL
#include "seal/ciphertext.h"
#include "seal/modulus.h"
#include "seal/plaintext.h"
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

        /**
        Keeps the relinearization keys, compression mode and parameter fingerprint of every query
        the receiver sends, and answers each with a response announcing no result packages at all,
        which is what lets request_query complete without a sender.
        */
        class CapturingChannel final : public NetworkChannel {
        public:
            void send(unique_ptr<SenderOperation> sop) override
            {
                auto query = to_query_request(std::move(sop));
                if (query) {
                    sent_relin_keys.push_back(save_relin_keys(query->relin_keys));
                    sent_compr_modes.push_back(query->compr_mode);
                    sent_fingerprints.push_back(query->params_fingerprint);
                }
            }

            unique_ptr<SenderOperation> receive_operation(
                shared_ptr<SEALContext>, SenderOperationType) override
            {
                return nullptr;
            }

            void send(unique_ptr<SenderOperationResponse>) override
            {}

            unique_ptr<SenderOperationResponse> receive_response(SenderOperationType) override
            {
                auto response = make_unique<SenderOperationResponseQuery>();
                response->package_count = 0;
                return response;
            }

            void send(unique_ptr<ResultPackage>) override
            {}

            unique_ptr<ResultPackage> receive_result(shared_ptr<SEALContext>) override
            {
                return nullptr;
            }

            vector<vector<unsigned char>> sent_relin_keys;

            vector<compr_mode_type> sent_compr_modes;

            vector<optional<PSIParams::Fingerprint>> sent_fingerprints;
        }; // class CapturingChannel
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
    TEST(ReceiverApiTests, RequestQueryRotatesKeysBetweenQueries)
    {
        // The relinearization keys travel to the sender with every query, so two queries from one
        // Receiver must not carry the same ones: a sender that saw them would know the queries
        // came from one receiver even across separate connections.
        Receiver receiver(make_test_params());

        vector<HashedItem> items;
        items.push_back(make_hashed_item(1, 2));
        LabelKeyVector label_keys;

        CapturingChannel chl;
        static_cast<void>(receiver.request_query(items, label_keys, chl));
        static_cast<void>(receiver.request_query(items, label_keys, chl));
        static_cast<void>(receiver.request_query(items, label_keys, chl));

        ASSERT_EQ(size_t(3), chl.sent_relin_keys.size());
        for (const auto &keys : chl.sent_relin_keys) {
            ASSERT_FALSE(keys.empty());
        }
        ASSERT_NE(chl.sent_relin_keys[0], chl.sent_relin_keys[1]);
        ASSERT_NE(chl.sent_relin_keys[1], chl.sent_relin_keys[2]);
        ASSERT_NE(chl.sent_relin_keys[0], chl.sent_relin_keys[2]);
    }

    TEST(ReceiverApiTests, CreateQueryKeepsKeysSoPipelinedResultsStayDecryptable)
    {
        // create_query is the other half of the contract: it must not rotate, because a caller
        // driving the split API may still be holding the result of an earlier query, which is
        // encrypted under the key a rotation would discard.
        Receiver receiver(make_test_params());

        vector<HashedItem> items;
        items.push_back(make_hashed_item(1, 2));

        auto first = to_query_request(receiver.create_query(items).first);
        auto second = to_query_request(receiver.create_query(items).first);
        ASSERT_NE(nullptr, first);
        ASSERT_NE(nullptr, second);

        ASSERT_EQ(save_relin_keys(first->relin_keys), save_relin_keys(second->relin_keys));
    }

    namespace {
        vector<compr_mode_type> supported_compr_modes()
        {
            vector<compr_mode_type> compr_modes;
            for (unsigned value = 0; value <= 0xFF; value++) {
                if (Serialization::IsSupportedComprMode(static_cast<uint8_t>(value))) {
                    compr_modes.push_back(static_cast<compr_mode_type>(value));
                }
            }
            return compr_modes;
        }

        QueryRequest create_query(Receiver &receiver)
        {
            vector<HashedItem> items{ HashedItem{ 1, 2 }, HashedItem{ 3, 4 } };
            return to_query_request(receiver.create_query(items).first);
        }
    } // namespace

    TEST(ReceiverComprModeTests, DefaultIsBitpack)
    {
        ASSERT_EQ(compr_mode_type::bitpack, Receiver::default_compr_mode);

        Receiver receiver(make_test_params());
        ASSERT_EQ(compr_mode_type::bitpack, receiver.get_compr_mode());
        ASSERT_EQ(compr_mode_type::bitpack, create_query(receiver)->compr_mode);
    }

    TEST(ReceiverComprModeTests, SetComprModeAcceptsEverySupportedMode)
    {
        Receiver receiver(make_test_params());
        for (compr_mode_type compr_mode : supported_compr_modes()) {
            SCOPED_TRACE(compr_mode_str(compr_mode));
            receiver.set_compr_mode(compr_mode);
            ASSERT_EQ(compr_mode, receiver.get_compr_mode());
            ASSERT_EQ(compr_mode, create_query(receiver)->compr_mode);
        }
    }

    TEST(ReceiverComprModeTests, SetComprModeRejectsUnsupportedModes)
    {
        Receiver receiver(make_test_params());
        receiver.set_compr_mode(compr_mode_type::none);

        size_t unsupported_count = 0;
        for (unsigned value = 0; value <= 0xFF; value++) {
            if (Serialization::IsSupportedComprMode(static_cast<uint8_t>(value))) {
                continue;
            }
            unsupported_count++;
            ASSERT_THROW(
                receiver.set_compr_mode(static_cast<compr_mode_type>(value)), invalid_argument);
            ASSERT_EQ(compr_mode_type::none, receiver.get_compr_mode());
        }
        ASSERT_LT(size_t(0), unsupported_count);
    }

    TEST(ReceiverComprModeTests, RequestQueryUsesTheComprMode)
    {
        Receiver receiver(make_test_params());
        vector<HashedItem> items{ HashedItem{ 1, 2 } };
        LabelKeyVector label_keys;
        CapturingChannel chl;

        static_cast<void>(receiver.request_query(items, label_keys, chl));
        receiver.set_compr_mode(compr_mode_type::none);
        static_cast<void>(receiver.request_query(items, label_keys, chl));

        vector<compr_mode_type> expected{ compr_mode_type::bitpack, compr_mode_type::none };
        ASSERT_EQ(expected, chl.sent_compr_modes);
    }

    TEST(ReceiverFingerprintTests, QueriesCarryTheParamsFingerprint)
    {
        PSIParams params = make_test_params();
        Receiver receiver(params);

        QueryRequest query = create_query(receiver);
        ASSERT_EQ(params.fingerprint(), query->params_fingerprint);

        // The fingerprint is what a sender reads from the serialized query
        stringstream ss;
        query->save(ss);
        string saved = ss.str();
        ASSERT_EQ(
            params.fingerprint(),
            SenderOperationQuery::ExtractParamsFingerprint(
                gsl::span<const unsigned char>(
                    reinterpret_cast<const unsigned char *>(saved.data()), saved.size())));

        // And request_query sends it, too
        CapturingChannel chl;
        vector<HashedItem> items{ HashedItem{ 1, 2 } };
        LabelKeyVector label_keys;
        static_cast<void>(receiver.request_query(items, label_keys, chl));
        ASSERT_EQ(size_t(1), chl.sent_fingerprints.size());
        ASSERT_EQ(params.fingerprint(), chl.sent_fingerprints[0]);
    }

    namespace {
        /**
        Parameters with match tags of tag_part_count parts and a single bundle index.
        */
        PSIParams make_tag_test_params(
            uint32_t tag_part_count = 3,
            size_t poly_modulus_degree = 4096,
            uint64_t plain_modulus = 65537)
        {
            PSIParams::ItemParams item_params;
            item_params.felts_per_item = 1;
            item_params.tag_part_count = tag_part_count;

            PSIParams::TableParams table_params;
            table_params.hash_func_count = 3;
            table_params.max_items_per_bin = 16;
            table_params.table_size = static_cast<uint32_t>(poly_modulus_degree);

            PSIParams::QueryParams query_params;
            query_params.query_powers = { 1, 3, 5 };

            PSIParams::SEALParams seal_params;
            seal_params.set_poly_modulus_degree(poly_modulus_degree);
            seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
            seal_params.set_plain_modulus(plain_modulus);

            return { item_params, table_params, query_params, seal_params };
        }

        LabelKey make_label_key(size_t seed)
        {
            LabelKey key{};
            for (size_t i = 0; i < key.size(); i++) {
                key[i] = static_cast<unsigned char>((seed * 31) + (i * 7) + 1);
            }
            return key;
        }

        /**
        A query a Receiver made: its items, a label key for each, its index translation table, and
        the position of each item in the receiver's cuckoo table.
        */
        struct TagQuery {
            vector<HashedItem> items;

            LabelKeyVector label_keys;

            IndexTranslationTable itt;

            vector<size_t> positions;
        };

        TagQuery make_tag_query(Receiver &receiver, const PSIParams &params, size_t item_count)
        {
            vector<HashedItem> items;
            LabelKeyVector label_keys;
            for (size_t i = 0; i < item_count; i++) {
                items.push_back(make_hashed_item(i + 1, 1000 + i));
                label_keys.push_back(make_label_key(i));
            }
            IndexTranslationTable itt = receiver.create_query(items).second;

            size_t table_size = params.table_params().table_size;
            vector<size_t> positions(item_count, table_size);
            for (size_t table_idx = 0; table_idx < table_size; table_idx++) {
                size_t item_idx = itt.find_item_idx(table_idx);
                if (item_idx != itt.item_count()) {
                    positions[item_idx] = table_idx;
                }
            }
            return TagQuery{
                std::move(items), std::move(label_keys), std::move(itt), std::move(positions)
            };
        }

        /**
        Slot values for the result of one bin bundle: part_count parts of random values, which
        is what a sender's polynomials give in slots where they hold no item.
        */
        vector<vector<uint64_t>> random_parts(const PSIParams &params, size_t part_count)
        {
            mt19937_64 rng(part_count);
            uniform_int_distribution<uint64_t> dist(
                0, params.seal_params().plain_modulus().value() - 1);
            vector<vector<uint64_t>> parts(
                part_count, vector<uint64_t>(params.seal_params().poly_modulus_degree()));
            for (auto &part : parts) {
                for (auto &value : part) {
                    value = dist(rng);
                }
            }
            return parts;
        }

        /**
        Writes into parts what a sender holding the item with the given tag and encrypted label
        gives in the item's slots: the label parts algebraize_item_tag_label lays out.
        */
        void put_item(
            vector<vector<uint64_t>> &parts,
            const PSIParams &params,
            const HashedItem &item,
            size_t table_idx,
            const vector<apsi::util::felt_t> &tag,
            const EncryptedLabel &encrypted_label)
        {
            apsi::util::AlgItemLabel alg_item_label = apsi::util::algebraize_item_tag_label(
                item,
                tag,
                encrypted_label,
                params.item_bit_count(),
                params.seal_params().plain_modulus());
            size_t felts_per_item = params.item_params().felts_per_item;
            size_t bundle_pos = table_idx % params.items_per_bundle();
            for (size_t s = 0; s < felts_per_item; s++) {
                ASSERT_EQ(parts.size(), alg_item_label[s].second.size());
                for (size_t p = 0; p < parts.size(); p++) {
                    parts[p][(bundle_pos * felts_per_item) + s] = alg_item_label[s].second[p];
                }
            }
        }

        vector<apsi::util::felt_t> tag_of(const LabelKey &key, const PSIParams &params)
        {
            return apsi::util::compute_match_tag(
                key,
                params.tag_part_count() * params.item_params().felts_per_item,
                params.item_bit_count_per_felt());
        }

        /**
        A ResultPackage for bundle index 0 holding the given parts, encrypted under the receiver's
        key, as label_result.
        */
        unique_ptr<ResultPackage> make_package(
            const Receiver &receiver,
            uint32_t label_byte_count,
            uint32_t nonce_byte_count,
            const vector<vector<uint64_t>> &parts)
        {
            const CryptoContext &crypto_context = receiver.get_crypto_context();
            auto package = make_unique<ResultPackage>();
            package->bundle_idx = 0;
            package->compr_mode = compr_mode_type::none;
            package->label_byte_count = label_byte_count;
            package->nonce_byte_count = nonce_byte_count;
            for (const auto &part : parts) {
                Plaintext pt;
                crypto_context.encoder()->encode(part, pt);
                Ciphertext ct;
                crypto_context.encryptor()->encrypt_symmetric(pt, ct);
                package->label_result.emplace_back(std::move(ct));
            }
            return package;
        }

        unique_ptr<ResultPackage> copy_package(const ResultPackage &package)
        {
            auto copy = make_unique<ResultPackage>();
            copy->bundle_idx = package.bundle_idx;
            copy->compr_mode = package.compr_mode;
            copy->psi_result = package.psi_result;
            copy->label_byte_count = package.label_byte_count;
            copy->nonce_byte_count = package.nonce_byte_count;
            copy->label_result = package.label_result;
            return copy;
        }

        vector<ResultPart> one_part(unique_ptr<ResultPackage> package)
        {
            vector<ResultPart> result;
            result.push_back(std::move(package));
            return result;
        }
    } // namespace

    TEST(ReceiverTagTests, EmptyTableEntriesHoldNoSenderPoint)
    {
        // Without match tags an empty entry of the receiver's cuckoo table is the all-zero item.
        // With them it is 2^item_bit_count_per_felt in every slot, a value no field element of a
        // sender's item can take, so that an empty entry never picks out a sender's tag.
        for (bool tags : { false, true }) {
            PSIParams params = tags ? make_tag_test_params() : make_test_params();
            Receiver receiver(params);
            const CryptoContext &crypto_context = receiver.get_crypto_context();

            vector<HashedItem> items{ make_hashed_item(1, 2),
                                      make_hashed_item(3, 4),
                                      make_hashed_item(5, 6) };
            auto [request, itt] = receiver.create_query(items);
            auto query = to_query_request(std::move(request));
            ASSERT_NE(nullptr, query);

            size_t felts_per_item = params.item_params().felts_per_item;
            size_t items_per_bundle = params.items_per_bundle();
            apsi::util::felt_t empty_value =
                tags ? (uint64_t(1) << params.item_bit_count_per_felt()) : 0;
            const auto &power_one = query->data.at(1);
            ASSERT_EQ(params.bundle_idx_count(), power_one.size());

            size_t filled_count = 0;
            for (size_t bundle_idx = 0; bundle_idx < power_one.size(); bundle_idx++) {
                SEALObject<Ciphertext> encrypted = power_one[bundle_idx];
                Ciphertext ct = encrypted.extract(receiver.get_seal_context());
                Plaintext pt;
                crypto_context.decryptor()->decrypt(ct, pt);
                vector<uint64_t> slots;
                crypto_context.encoder()->decode(pt, slots);

                for (size_t pos = 0; pos < items_per_bundle; pos++) {
                    size_t item_idx = itt.find_item_idx((bundle_idx * items_per_bundle) + pos);
                    vector<apsi::util::felt_t> expected(felts_per_item, empty_value);
                    if (item_idx != itt.item_count()) {
                        expected = apsi::util::algebraize_item(
                            items[item_idx],
                            params.item_bit_count(),
                            params.seal_params().plain_modulus());
                        filled_count++;
                    }
                    for (size_t s = 0; s < felts_per_item; s++) {
                        ASSERT_EQ(expected[s], slots[(pos * felts_per_item) + s]);
                    }
                }
            }
            ASSERT_EQ(items.size(), filled_count);
        }
    }

    TEST(ReceiverTagTests, ItemsMatchByTheirTags)
    {
        PSIParams params = make_tag_test_params();
        Receiver receiver(params);
        TagQuery query = make_tag_query(receiver, params, 20);

        // Every third item is the sender's
        vector<vector<uint64_t>> parts = random_parts(params, params.tag_part_count());
        for (size_t i = 0; i < query.items.size(); i += 3) {
            put_item(
                parts,
                params,
                query.items[i],
                query.positions[i],
                tag_of(query.label_keys[i], params),
                {});
        }

        // An item answered with the tag of another
        put_item(
            parts,
            params,
            query.items[1],
            query.positions[1],
            tag_of(query.label_keys[0], params),
            {});

        // And one answered with its own tag but for one of its field elements
        vector<apsi::util::felt_t> almost = tag_of(query.label_keys[2], params);
        almost.back() ^= 1;
        put_item(parts, params, query.items[2], query.positions[2], almost, {});

        // Decrypting a package consumes it, so each call gets its own copy
        auto package = make_package(receiver, 0, 0, parts);
        vector<MatchRecord> part_result =
            receiver.process_result_part(query.label_keys, query.itt, copy_package(*package));
        vector<MatchRecord> result =
            receiver.process_result(query.label_keys, query.itt, one_part(std::move(package)));
        ASSERT_EQ(query.items.size(), part_result.size());
        ASSERT_EQ(query.items.size(), result.size());
        for (size_t i = 0; i < query.items.size(); i++) {
            ASSERT_EQ(i % 3 == 0, part_result[i].found) << "item " << i;
            ASSERT_EQ(i % 3 == 0, result[i].found) << "item " << i;
            ASSERT_FALSE(result[i].label);
        }
    }

    TEST(ReceiverTagTests, MatchesCompareWholeFieldElements)
    {
        // A slot can hold a value of 2^item_bit_count_per_felt or more, which agrees with a tag
        // in its low bits without being the tag. With 13 bits per field element and a plain
        // modulus of 12289, such values are common.
        PSIParams params = make_tag_test_params(4, 2048, 12289);
        ASSERT_EQ(13, params.item_bit_count_per_felt());
        Receiver receiver(params);
        TagQuery query = make_tag_query(receiver, params, 8);

        vector<vector<uint64_t>> parts = random_parts(params, params.tag_part_count());
        vector<bool> expected_found(query.items.size());
        size_t lifted_count = 0;
        for (size_t i = 0; i < query.items.size(); i++) {
            vector<apsi::util::felt_t> tag = tag_of(query.label_keys[i], params);
            bool lifted = false;
            if (i % 2) {
                // Every part of the tag that can be lifted by 2^13 within the plain modulus is
                for (auto &value : tag) {
                    if (value + 8192 < 12289) {
                        value += 8192;
                        lifted = true;
                    }
                }
            }
            expected_found[i] = !lifted;
            lifted_count += lifted ? 1 : 0;
            put_item(parts, params, query.items[i], query.positions[i], tag, {});
        }
        ASSERT_LT(size_t(0), lifted_count);

        vector<MatchRecord> result = receiver.process_result(
            query.label_keys, query.itt, one_part(make_package(receiver, 0, 0, parts)));
        for (size_t i = 0; i < query.items.size(); i++) {
            ASSERT_EQ(expected_found[i], result[i].found) << "item " << i;
        }
    }

    TEST(ReceiverTagTests, LabelsOfMatchesAreDecrypted)
    {
        PSIParams params = make_tag_test_params();
        Receiver receiver(params);
        TagQuery query = make_tag_query(receiver, params, 10);

        // 4 bytes of nonce and 10 of label make 7 parts of 16 bits
        uint32_t label_byte_count = 10;
        uint32_t nonce_byte_count = 4;
        size_t part_count = params.tag_part_count() + 7;
        vector<vector<uint64_t>> parts = random_parts(params, part_count);
        vector<Label> labels;
        for (size_t i = 0; i < query.items.size(); i++) {
            Label label(label_byte_count);
            for (size_t j = 0; j < label.size(); j++) {
                label[j] = static_cast<unsigned char>((i * 16) + j);
            }
            labels.push_back(label);
            if (i % 2 == 0) {
                EncryptedLabel encrypted_label = apsi::util::encrypt_label(
                    label, query.label_keys[i], label_byte_count, nonce_byte_count);
                put_item(
                    parts,
                    params,
                    query.items[i],
                    query.positions[i],
                    tag_of(query.label_keys[i], params),
                    encrypted_label);
            }
        }

        vector<MatchRecord> result = receiver.process_result(
            query.label_keys,
            query.itt,
            one_part(make_package(receiver, label_byte_count, nonce_byte_count, parts)));
        for (size_t i = 0; i < query.items.size(); i++) {
            ASSERT_EQ(i % 2 == 0, result[i].found) << "item " << i;
            if (i % 2 == 0) {
                ASSERT_TRUE(result[i].label);
                ASSERT_EQ(labels[i], result[i].label.value());
            } else {
                ASSERT_FALSE(result[i].label);
            }
        }
    }

    TEST(ReceiverTagTests, EveryPartIsDecryptedWhetherOrNotAnItemMatches)
    {
        // Every ciphertext of a result package is decrypted, whether or not one of the receiver's
        // items is at its bundle index and whether or not one of them matches, so that the time
        // processing takes depends on neither. To see that, parts are left as ciphertexts that
        // cannot be decrypted at all, so that processing fails where they are decrypted.
        PSIParams params = make_tag_test_params();
        Receiver receiver(params);
        TagQuery query = make_tag_query(receiver, params, 5);

        // The label parts of a package in which no tag matches
        vector<vector<uint64_t>> tag_parts = random_parts(params, params.tag_part_count());
        auto no_match = make_package(receiver, 10, 0, tag_parts);
        for (size_t p = 0; p < 5; p++) {
            no_match->label_result.emplace_back(Ciphertext());
        }
        ASSERT_ANY_THROW(
            static_cast<void>(receiver.process_result(
                query.label_keys, query.itt, one_part(copy_package(*no_match)))));
        ASSERT_ANY_THROW(
            static_cast<void>(receiver.process_result_part(
                query.label_keys, query.itt, copy_package(*no_match))));

        // The tag parts of a package at a bundle index that holds none of the receiver's items
        TagQuery empty_query = make_tag_query(receiver, params, 0);
        auto no_items = make_package(receiver, 0, 0, {});
        for (size_t p = 0; p < params.tag_part_count(); p++) {
            no_items->label_result.emplace_back(Ciphertext());
        }
        ASSERT_ANY_THROW(
            static_cast<void>(receiver.process_result(
                empty_query.label_keys, empty_query.itt, one_part(copy_package(*no_items)))));

        // Decryptable parts in the same places are processed as usual
        auto decryptable = make_package(receiver, 0, 0, tag_parts);
        vector<MatchRecord> result;
        ASSERT_NO_THROW(
            result = receiver.process_result(
                empty_query.label_keys, empty_query.itt, one_part(std::move(decryptable))));
        ASSERT_TRUE(result.empty());
    }

    TEST(ReceiverTagTests, MalformedPackagesAbortTheQuery)
    {
        // With match tags, a package that cannot be a result for the query means a part of the
        // answer is missing, and possibly a match with it. Rather than going on without it, as
        // without match tags, the receiver refuses the whole result.
        PSIParams params = make_tag_test_params();
        Receiver receiver(params);
        TagQuery query = make_tag_query(receiver, params, 5);

        // 4 bytes of nonce and 10 of label make 7 parts of 16 bits
        vector<vector<uint64_t>> parts = random_parts(params, params.tag_part_count() + 7);
        put_item(
            parts,
            params,
            query.items[0],
            query.positions[0],
            tag_of(query.label_keys[0], params),
            EncryptedLabel(14));
        auto valid = make_package(receiver, 10, 4, parts);
        ASSERT_TRUE(
            receiver.process_result(query.label_keys, query.itt, one_part(copy_package(*valid)))[0]
                .found);

        vector<pair<string, unique_ptr<ResultPackage>>> malformed;
        auto add_malformed = [&](string name) -> ResultPackage & {
            malformed.emplace_back(std::move(name), copy_package(*valid));
            return *malformed.back().second;
        };
        add_malformed("a PSI result").psi_result = valid->label_result[0];
        add_malformed("a label part too few").label_result.pop_back();
        add_malformed("a label part too many").label_result.push_back(valid->label_result[0]);
        add_malformed("label parts without a label").label_byte_count = 0;
        add_malformed("too large a label_byte_count").label_byte_count = 1025;
        add_malformed("too large a nonce_byte_count").nonce_byte_count = max_nonce_byte_count + 1;
        add_malformed("a bundle index out of range").bundle_idx = params.bundle_idx_count();
        malformed.emplace_back("no package", nullptr);

        for (const auto &[name, package] : malformed) {
            SCOPED_TRACE(name);
            vector<ResultPart> result;
            result.push_back(copy_package(*valid));
            result.push_back(package ? copy_package(*package) : nullptr);
            ASSERT_THROW(
                static_cast<void>(receiver.process_result(query.label_keys, query.itt, result)),
                runtime_error);
            ASSERT_THROW(
                static_cast<void>(
                    receiver.process_result_part(query.label_keys, query.itt, result[1])),
                runtime_error);
        }

        // Without a label there are only the tag parts, and no nonce
        vector<vector<uint64_t>> tag_parts = random_parts(params, params.tag_part_count());
        auto unlabeled = make_package(receiver, 0, 0, tag_parts);
        ASSERT_NO_THROW(
            static_cast<void>(receiver.process_result(
                query.label_keys, query.itt, one_part(copy_package(*unlabeled)))));
        unlabeled->nonce_byte_count = 4;
        ASSERT_THROW(
            static_cast<void>(receiver.process_result(
                query.label_keys, query.itt, one_part(copy_package(*unlabeled)))),
            runtime_error);
        unlabeled->nonce_byte_count = 0;
        unlabeled->label_result.push_back(valid->label_result[0]);
        ASSERT_THROW(
            static_cast<void>(receiver.process_result(
                query.label_keys, query.itt, one_part(std::move(unlabeled)))),
            runtime_error);
    }

    TEST(ReceiverTagTests, LabelKeysAreRequired)
    {
        PSIParams params = make_tag_test_params();
        Receiver receiver(params);
        TagQuery query = make_tag_query(receiver, params, 5);
        vector<vector<uint64_t>> parts = random_parts(params, params.tag_part_count());
        auto package = make_package(receiver, 0, 0, parts);

        ASSERT_THROW(
            static_cast<void>(
                receiver.process_result({}, query.itt, one_part(copy_package(*package)))),
            invalid_argument);
        LabelKeyVector too_few(query.label_keys.begin(), query.label_keys.end() - 1);
        ASSERT_THROW(
            static_cast<void>(receiver.process_result_part(too_few, query.itt, package)),
            invalid_argument);

        // request_query refuses before sending anything
        CapturingChannel chl;
        ASSERT_THROW(
            static_cast<void>(receiver.request_query(query.items, {}, chl)), invalid_argument);
        ASSERT_TRUE(chl.sent_relin_keys.empty());
        ASSERT_NO_THROW(
            static_cast<void>(receiver.request_query(query.items, query.label_keys, chl)));
        ASSERT_EQ(1, chl.sent_relin_keys.size());

        // Without match tags they are needed only for labels, as in APSI 1.x
        Receiver untagged_receiver(make_test_params());
        CapturingChannel untagged_chl;
        ASSERT_NO_THROW(
            static_cast<void>(untagged_receiver.request_query(query.items, {}, untagged_chl)));
    }

    TEST(ReceiverTagTests, ARepeatedMatchKeepsTheFirst)
    {
        // Two packages giving an item its tag, which an honest sender gives only with
        // probability 2^-tag_bit_count: the first match is kept, as without match tags
        PSIParams params = make_tag_test_params();
        Receiver receiver(params);
        TagQuery query = make_tag_query(receiver, params, 3);

        vector<unique_ptr<ResultPackage>> packages;
        for (unsigned char first_byte : array<unsigned char, 2>{ 1, 2 }) {
            vector<vector<uint64_t>> parts = random_parts(params, params.tag_part_count() + 1);
            Label label{ first_byte, 0 };
            put_item(
                parts,
                params,
                query.items[1],
                query.positions[1],
                tag_of(query.label_keys[1], params),
                apsi::util::encrypt_label(label, query.label_keys[1], 2, 0));
            packages.push_back(make_package(receiver, 2, 0, parts));
        }

        for (size_t first : { 0U, 1U }) {
            vector<ResultPart> result;
            result.push_back(copy_package(*packages[first]));
            result.push_back(copy_package(*packages[1 - first]));
            vector<MatchRecord> mrs = receiver.process_result(query.label_keys, query.itt, result);
            ASSERT_FALSE(mrs[0].found);
            ASSERT_TRUE(mrs[1].found);
            ASSERT_FALSE(mrs[2].found);
            ASSERT_EQ(first + 1, mrs[1].label.value()[0]);
        }
    }

    TEST(ReceiverTagTests, PackageWithoutPSIResultAbortsTheQueryWithoutTags)
    {
        // The schema does not require a PSI result, as a result with match tags has none, so
        // without match tags its absence is checked in code. Such a package is refused, as APSI
        // 1.x's schema refuses it, rather than skipped: skipping it would quietly leave out
        // whatever matches it holds.
        PSIParams params = make_test_params();
        Receiver receiver(params);
        vector<HashedItem> items{ make_hashed_item(1, 2), make_hashed_item(3, 4) };
        auto itt = receiver.create_query(items).second;

        vector<vector<uint64_t>> parts = random_parts(params, 1);
        auto package = make_package(receiver, 0, 0, parts);
        ASSERT_THROW(
            static_cast<void>(receiver.process_result_part({}, itt, copy_package(*package))),
            runtime_error);
        ASSERT_THROW(
            static_cast<void>(receiver.process_result({}, itt, one_part(std::move(package)))),
            runtime_error);
    }
} // namespace APSITests
