// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// APSI
#include "apsi/item.h"
#include "apsi/network/result_package.h"
#include "apsi/network/result_package_generated.h"
#include "apsi/network/sender_operation.h"
#include "apsi/network/stream_channel.h"
#include "apsi/oprf/oprf_sender.h"
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
        /**
        Returns parameters with the given hash_func_count, and with match tags if tag_part_count
        is not zero. The number of hash functions enters only the receiver's cuckoo hashing, so
        queries for one of these are valid in every respect but the parameter fingerprint for
        another with the same tag_part_count.
        */
        PSIParams make_test_params(uint32_t hash_func_count = 3, uint32_t tag_part_count = 0)
        {
            PSIParams::ItemParams item_params;
            item_params.felts_per_item = 8;
            item_params.tag_part_count = tag_part_count;

            PSIParams::TableParams table_params;
            table_params.hash_func_count = hash_func_count;
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
        // parameters it reads no longer describe. A query from an APSI 1.x receiver carries no
        // parameter fingerprint, so these checks are all that stop it.
        auto sender_db = make_shared<SenderDB>(make_test_params(), 0);
        QueryRequest request = make_honest_query(sender_db->get_params());
        request->params_fingerprint.reset();
        Query query(std::move(request), sender_db);
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
        // every check on the query data itself, and a query from an APSI 1.x receiver carries no
        // parameter fingerprint, so the DAG must be checked separately: otherwise the powers above
        // the new maximum are written past the end of the vector, and after the QueryResponse has
        // already been sent.
        auto sender_db = make_shared<SenderDB>(make_test_params(), 0);
        QueryRequest request = make_honest_query(sender_db->get_params());
        request->params_fingerprint.reset();
        Query query(std::move(request), sender_db);
        ASSERT_TRUE(query.is_valid());

        auto replacement = SenderDB(make_shallow_params(), 0);
        replacement.insert_or_assign(Item(3, 3));
        *sender_db = std::move(replacement);

        stringstream ss;
        StreamChannel chl(ss);
        ASSERT_THROW(Sender::RunQuery(query, chl), invalid_argument);
        ASSERT_TRUE(ss.str().empty());
    }

    TEST(QueryTests, RunQueryRejectsAQueryWithoutAFingerprintOnceTheSenderDBUsesMatchTags)
    {
        // A query from an APSI 1.x receiver carries no parameter fingerprint, which a SenderDB
        // without match tags accepts. A SenderDB replaced by one with match tags, and the same
        // table and bins, agrees with the query on every other check RunQuery makes, so only the
        // missing fingerprint stops the query from being answered.
        auto sender_db = make_shared<SenderDB>(make_test_params(), 0);
        QueryRequest request = make_honest_query(sender_db->get_params());
        request->params_fingerprint.reset();
        Query query(std::move(request), sender_db);
        ASSERT_TRUE(query.is_valid());

        auto replacement = SenderDB(make_test_params(3, 1), 0);
        replacement.insert_or_assign(Item(3, 3));
        ASSERT_TRUE(replacement.get_params().uses_tags());
        *sender_db = std::move(replacement);

        stringstream ss;
        StreamChannel chl(ss);
        ASSERT_THROW(Sender::RunQuery(query, chl), invalid_argument);
        ASSERT_TRUE(ss.str().empty());
    }

    namespace {
        /**
        Refuses every result package and counts how many it was offered.
        */
        class RefusingChannel : public StreamChannel {
        public:
            explicit RefusingChannel(stringstream &ss) : StreamChannel(ss)
            {}

            void send(unique_ptr<ResultPackage> rp) override
            {
                (void)rp;
                attempts_++;
                throw runtime_error("refused");
            }

            size_t attempts() const noexcept
            {
                return attempts_;
            }

        private:
            atomic<size_t> attempts_{ 0 };
        };
    } // namespace

    TEST(QueryTests, RunQueryStopsSendingAfterAResultPackageFails)
    {
        // A receiver needs every package of a query or none of them, so once one cannot be
        // delivered the rest are worth nothing. They are not free, though: each would wait out
        // the channel's own send timeout, one after another because a channel serializes its
        // sends, so an unreachable receiver would cost that timeout once per package left.
        //
        // The guard has to sit around the send rather than at the start of the work, or a task
        // already running is past it before any failure can happen. This runs on however many
        // workers the pool has, which is the case that distinguishes the two: with a check at
        // the start and a worker for each task, every task is past its check before the first
        // send is even attempted.
        auto sender_db = make_shared<SenderDB>(make_wider_params());
        for (uint64_t i = 0; i < 16; i++) {
            sender_db->insert_or_assign(Item(i, i));
        }

        Query query(make_honest_query(sender_db->get_params()), sender_db);
        ASSERT_TRUE(query.is_valid());

        stringstream ss;
        RefusingChannel chl(ss);

        // Whichever task reaches the channel first is the one that fails, and the others stop
        // rather than reporting that somebody else did. That is what the caller must be told:
        // TaskGroup::join rethrows the first exception by the order tasks were added, not by
        // the order they failed in, so a task that threw on another's behalf would just as
        // often be the one that surfaced, and the reason the query failed would be gone.
        string reported;
        try {
            Sender::RunQuery(query, chl);
            FAIL() << "RunQuery should have thrown";
        } catch (const runtime_error &ex) {
            reported = ex.what();
        }
        ASSERT_EQ(string("refused"), reported);

        // The parameters give two bundle indices, so without the guard there would be two.
        ASSERT_EQ(size_t(1), chl.attempts());
    }

    TEST(QueryFingerprintTests, SenderDBWithTagsRequiresAFingerprint)
    {
        // A query without a fingerprint comes from a receiver before APSI 2.0, which cannot use
        // the answer of a SenderDB with match tags: its schema requires a PSI result, so its query
        // fails at the first result package. The SenderDB refuses the query rather than evaluate
        // it for nothing.
        auto sender_db = make_shared<SenderDB>(make_test_params(3, 1));
        ASSERT_TRUE(sender_db->get_params().uses_tags());

        QueryRequest with_fingerprint = make_honest_query(sender_db->get_params());
        ASSERT_TRUE(Query(std::move(with_fingerprint), sender_db).is_valid());

        QueryRequest without_fingerprint = make_honest_query(sender_db->get_params());
        without_fingerprint->params_fingerprint.reset();
        Query query(std::move(without_fingerprint), sender_db);
        ASSERT_FALSE(query.is_valid());
        ASSERT_FALSE(query.check_params_fingerprint(sender_db->get_params()));
    }

    TEST(QueryFingerprintTests, AcceptsAQueryWithTheMatchingFingerprint)
    {
        auto sender_db = make_shared<SenderDB>(make_test_params());
        QueryRequest request = make_honest_query(sender_db->get_params());
        ASSERT_EQ(sender_db->get_params().fingerprint(), request->params_fingerprint);

        Query query(std::move(request), sender_db);
        ASSERT_TRUE(query.is_valid());
        ASSERT_EQ(sender_db->get_params().fingerprint(), query.params_fingerprint());
        ASSERT_TRUE(query.check_params_fingerprint(sender_db->get_params()));
    }

    TEST(QueryFingerprintTests, AcceptsAQueryWithoutAFingerprint)
    {
        // A receiver before APSI 2.0 sends no fingerprint. Parameters without match tags are the
        // only ones it can use, so a SenderDB with such parameters must still answer it.
        auto sender_db = make_shared<SenderDB>(make_test_params());
        QueryRequest request = make_honest_query(sender_db->get_params());
        request->params_fingerprint.reset();

        Query query(std::move(request), sender_db);
        ASSERT_TRUE(query.is_valid());
        ASSERT_FALSE(query.params_fingerprint());

        stringstream ss;
        StreamChannel chl(ss);
        ASSERT_NO_THROW(Sender::RunQuery(query, chl));
        ASSERT_FALSE(ss.str().empty());
    }

    TEST(QueryFingerprintTests, RejectsAQueryWithAnotherFingerprint)
    {
        // The query agrees with the SenderDB on everything else, so without the fingerprint it
        // would be answered
        auto sender_db = make_shared<SenderDB>(make_test_params(2));
        QueryRequest request = make_honest_query(make_test_params(3));
        ASSERT_NE(sender_db->get_params().fingerprint(), request->params_fingerprint);

        QueryRequest request_without_fingerprint = make_honest_query(make_test_params(3));
        request_without_fingerprint->params_fingerprint.reset();
        ASSERT_TRUE(Query(std::move(request_without_fingerprint), sender_db).is_valid());

        Query query(std::move(request), sender_db);
        ASSERT_FALSE(query.is_valid());

        stringstream ss;
        StreamChannel chl(ss);
        ASSERT_THROW(Sender::RunQuery(query, chl), invalid_argument);
        ASSERT_TRUE(ss.str().empty());
    }

    TEST(QueryFingerprintTests, RejectsAQueryWithAFingerprintDifferingInOneBit)
    {
        auto sender_db = make_shared<SenderDB>(make_test_params());
        for (size_t bit = 0; bit < 8 * PSIParams::fingerprint_byte_count; bit += 37) {
            QueryRequest request = make_honest_query(sender_db->get_params());
            ASSERT_TRUE(request->params_fingerprint.has_value());
            PSIParams::Fingerprint fingerprint =
                request->params_fingerprint.value_or(PSIParams::Fingerprint{});
            fingerprint[bit / 8] ^= static_cast<unsigned char>(1 << (bit % 8));
            request->params_fingerprint = fingerprint;
            ASSERT_FALSE(Query(std::move(request), sender_db).is_valid());
        }
    }

    TEST(QueryFingerprintTests, RunQueryRejectsAQueryWhoseFingerprintNoLongerMatches)
    {
        // RunQuery checks the query against the SenderDB again, since the SenderDB may have been
        // replaced since the Query was created. These parameters pass every other check RunQuery
        // makes, so only the fingerprint stops the query from being answered.
        auto sender_db = make_shared<SenderDB>(make_test_params(3), 0);
        Query query(make_honest_query(sender_db->get_params()), sender_db);
        ASSERT_TRUE(query.is_valid());

        auto replacement = SenderDB(make_test_params(2), 0);
        replacement.insert_or_assign(Item(3, 3));
        *sender_db = std::move(replacement);

        stringstream ss;
        StreamChannel chl(ss);
        ASSERT_THROW(Sender::RunQuery(query, chl), invalid_argument);

        // The rejection comes before the QueryResponse is sent
        ASSERT_TRUE(ss.str().empty());
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

        Label make_label(uint64_t i)
        {
            Label label(16);
            for (size_t j = 0; j < label.size(); j++) {
                label[j] = static_cast<unsigned char>((i * 31) + j);
            }
            return label;
        }
    } // namespace

    TEST(ResponseComprModeTests, SenderAnswersInTheComprModeOfTheQuery)
    {
        PSIParams params = make_test_params();

        // Labeled, so that the result packages hold label ciphertexts as well
        constexpr size_t label_byte_count = 16;
        constexpr size_t nonce_byte_count = 4;
        auto sender_db = make_shared<SenderDB>(params, label_byte_count, nonce_byte_count);
        vector<pair<Item, Label>> sender_data;
        sender_data.reserve(40);
        for (uint64_t i = 0; i < 40; i++) {
            sender_data.emplace_back(Item(i, i + 1), make_label(i));
        }
        sender_db->set_data(sender_data);

        // Three items in the database and two that are not
        vector<Item> items{ Item(0, 1), Item(17, 18), Item(39, 40), Item(7, 7), Item(1000, 1) };
        vector<optional<uint64_t>> expected_index{ 0, 17, 39, nullopt, nullopt };
        vector<HashedItem> hashed_items;
        LabelKeyVector label_keys;
        for (const auto &item : items) {
            auto hash = oprf::OPRFSender::GetItemHash(item, sender_db->get_oprf_key());
            hashed_items.push_back(hash.first);
            label_keys.push_back(hash.second);
        }

        // The number of label ciphertexts in each result package
        size_t label_part_count =
            ((8 * (label_byte_count + nonce_byte_count)) + params.item_bit_count() - 1) /
            params.item_bit_count();

        for (compr_mode_type compr_mode : supported_compr_modes()) {
            SCOPED_TRACE(compr_mode_str(compr_mode));

            Receiver receiver(params);
            receiver.set_compr_mode(compr_mode);
            auto query_and_itt = receiver.create_query(hashed_items);

            // The query reaches the sender as bytes, as it would over a network
            stringstream ss;
            StreamChannel chl(ss);
            chl.send(std::move(query_and_itt.first));
            QueryRequest request =
                to_query_request(chl.receive_operation(sender_db->get_seal_context()));
            ASSERT_NE(nullptr, request);
            ASSERT_EQ(compr_mode, request->compr_mode);

            Query query(std::move(request), sender_db);
            ASSERT_TRUE(query.is_valid());
            ASSERT_EQ(compr_mode, query.compr_mode());

            // Keep each result package as the bytes that would be sent
            mutex saved_packages_mtx;
            vector<string> saved_packages;
            Sender::RunQuery(
                query,
                chl,
                [](Channel &c, Response response) { c.send(std::move(response)); },
                [&](Channel &, ResultPart rp) {
                    stringstream rp_ss;
                    rp->save(rp_ss);
                    lock_guard<mutex> lock(saved_packages_mtx);
                    saved_packages.push_back(rp_ss.str());
                });

            QueryResponse response = to_query_response(chl.receive_response());
            ASSERT_NE(nullptr, response);
            ASSERT_EQ(sender_db->get_bin_bundle_count(), saved_packages.size());
            ASSERT_EQ(response->package_count, saved_packages.size());

            vector<ResultPart> result_parts;
            for (const auto &saved : saved_packages) {
                // Every ciphertext in a result package is saved in the mode of the query. The
                // result ciphertexts are not in NTT form, so in a mode other than bitpack they
                // carry format version 4.0, which Microsoft SEAL 4.0 can load.
                const auto *rp = fbs::GetSizePrefixedResultPackage(saved.data());
                ASSERT_NE(nullptr, rp->label_result());
                ASSERT_EQ(label_part_count, rp->label_result()->size());
                vector<const flatbuffers::Vector<uint8_t> *> cts{ rp->psi_result()->data() };
                for (const auto *ct : *rp->label_result()) {
                    cts.push_back(ct->data());
                }
                for (const auto *ct : cts) {
                    Serialization::SEALHeader header;
                    Serialization::LoadHeader(
                        reinterpret_cast<const seal_byte *>(ct->data()), ct->size(), header, false);
                    ASSERT_EQ(compr_mode, header.compr_mode);
                    ASSERT_EQ(Serialization::format_version_major, header.version_major);
                    ASSERT_EQ(
                        compr_mode == compr_mode_type::bitpack
                            ? Serialization::format_version_minor_bitpack
                            : Serialization::format_version_minor,
                        header.version_minor);
                }

                stringstream rp_ss(saved);
                auto result_part = make_unique<ResultPackage>();
                result_part->load(rp_ss, receiver.get_seal_context());
                result_parts.push_back(std::move(result_part));
            }

            // And the receiver reads the answer correctly
            auto results = receiver.process_result(label_keys, query_and_itt.second, result_parts);
            ASSERT_EQ(items.size(), results.size());
            for (size_t i = 0; i < items.size(); i++) {
                const optional<uint64_t> &index = expected_index[i];
                ASSERT_EQ(index.has_value(), results[i].found);
                if (index) {
                    ASSERT_EQ(make_label(*index), results[i].label.value());
                }
            }
        }
    }
} // namespace APSITests
