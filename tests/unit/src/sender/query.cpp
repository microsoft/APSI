// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// APSI
#include "apsi/item.h"
#include "apsi/log.h"
#include "apsi/network/result_package.h"
#include "apsi/network/result_package_generated.h"
#include "apsi/network/sender_operation.h"
#include "apsi/network/stream_channel.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/psi_params.h"
#include "apsi/query.h"
#include "apsi/receiver.h"
#include "apsi/requests.h"
#include "apsi/responses.h"
#include "apsi/seal_object.h"
#include "apsi/sender.h"
#include "apsi/sender_db.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/evaluator.h"
#include "seal/modulus.h"
#include "seal/serialization.h"

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

        /**
        Returns the query request as a sender receives it: saved, and read back with
        SenderOperationQuery::load, which holds the ciphertexts in serialized form.
        */
        QueryRequest receive(const QueryRequest &request, const shared_ptr<SEALContext> &context)
        {
            stringstream ss;
            request->save(ss);
            auto received = make_unique<SenderOperationQuery>();
            received->load(ss, context);
            return received;
        }

        /**
        Returns the bytes Microsoft SEAL saves the ciphertext as.
        */
        vector<unsigned char> save_ciphertext(const Ciphertext &ct, compr_mode_type compr_mode)
        {
            vector<unsigned char> bytes(static_cast<size_t>(ct.save_size(compr_mode)));
            auto size =
                ct.save(reinterpret_cast<seal_byte *>(bytes.data()), bytes.size(), compr_mode);
            bytes.resize(static_cast<size_t>(size));
            return bytes;
        }

        /**
        Returns a ciphertext held as bytes that are not a ciphertext at all, so that it fails if it
        is ever loaded. They are 4 KiB, more than the 1/64 of what a ciphertext loads to that a
        Query requires a ciphertext held in serialized form to take, so that loading it is tried.
        */
        SEALObject<Ciphertext> not_a_ciphertext()
        {
            SEALObject<Ciphertext> ct;
            ct.set_serialized(vector<unsigned char>(4096, 0x5A));
            return ct;
        }

        /**
        Returns the ciphertexts of the query, as saved without compression, by exponent.
        */
        map<uint32_t, vector<vector<unsigned char>>> saved_ciphertexts(const Query &query)
        {
            map<uint32_t, vector<vector<unsigned char>>> result;
            for (const auto &q : query.data()) {
                for (const auto &ct : q.second) {
                    result[q.first].push_back(save_ciphertext(ct, compr_mode_type::none));
                }
            }
            return result;
        }

        /**
        Returns the relinearization keys of the query, as saved without compression.
        */
        string saved_relin_keys(const Query &query)
        {
            stringstream ss;
            query.relin_keys().save(ss, compr_mode_type::none);
            return ss.str();
        }

        /**
        Runs the query and returns the result packages it is answered with, as the sender writes
        them. They are sorted, since the order they are sent in depends on scheduling.
        */
        vector<vector<unsigned char>> answer(const Query &query)
        {
            stringstream ss;
            StreamChannel chl(ss);
            Sender::RunQuery(query, chl);

            QueryResponse response =
                to_query_response(chl.receive_response(SenderOperationType::sop_query));
            vector<vector<unsigned char>> packages;
            packages.reserve(response->package_count);
            for (uint32_t i = 0; i < response->package_count; i++) {
                packages.push_back(apsi::util::read_from_stream(ss));
            }
            sort(packages.begin(), packages.end());
            return packages;
        }

        /**
        Collects the errors logged while it exists, and restores the global logger and log level
        when it is destroyed.
        */
        class ErrorCapture {
        public:
            ErrorCapture() : saved_level_(GetLogLevel())
            {
                array<Logger::log_handler_t, Logger::level_count> log_handlers{};
                log_handlers[static_cast<size_t>(LogLevel::error)] = [this](const string &msg) {
                    errors_.push_back(msg);
                };
                SetLogger(Logger::Create(std::move(log_handlers), {}, {}));
                SetLogLevel(LogLevel::error);
            }

            ~ErrorCapture()
            {
                CloseLogger();
                SetLogLevel(saved_level_);
            }

            ErrorCapture(const ErrorCapture &) = delete;

            ErrorCapture &operator=(const ErrorCapture &) = delete;

            /**
            Succeeds if exactly one error has been logged, and it contains the given text.
            */
            [[nodiscard]] testing::AssertionResult logged_only(const string &text) const
            {
                return logged_one(
                    text,
                    errors_.size() == 1 && errors_[0].find(text) != string::npos,
                    "containing");
            }

            /**
            Succeeds if exactly one error has been logged, and it is the given text.
            */
            [[nodiscard]] testing::AssertionResult logged_exactly(const string &text) const
            {
                return logged_one(text, errors_.size() == 1 && errors_[0] == text, "equal to");
            }

        private:
            [[nodiscard]] testing::AssertionResult logged_one(
                const string &text, bool success, const string &relation) const
            {
                if (success) {
                    return testing::AssertionSuccess();
                }

                testing::AssertionResult result = testing::AssertionFailure();
                result << "expected exactly one error, " << relation << " \"" << text << "\"; got "
                       << errors_.size();
                for (const auto &error : errors_) {
                    result << "\n  " << error;
                }
                return result;
            }

            LogLevel saved_level_;

            vector<string> errors_;
        };
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

    TEST(QueryTests, AcceptsHonestQueryAsReceived)
    {
        auto sender_db = make_shared<SenderDB>(make_test_params());
        QueryRequest request =
            receive(make_honest_query(sender_db->get_params()), sender_db->get_seal_context());
        for (const auto &q : request->data) {
            for (const auto &ct : q.second) {
                ASSERT_TRUE(ct.is_serialized());
            }
        }

        Query query(std::move(request), sender_db);
        ASSERT_TRUE(query.is_valid());
    }

    TEST(QueryTests, AnswersAQueryAsReceivedAsItAnswersTheQuerySent)
    {
        // The ciphertexts of a received query are loaded only when the Query is created. That
        // must give the Query the very ciphertexts the receiver sent, as loading them on receipt
        // would, and so the very same answer.
        auto sender_db = make_shared<SenderDB>(make_wider_params());
        for (uint64_t i = 0; i < 20; i++) {
            sender_db->insert_or_assign(HashedItem(i, i));
        }
        auto context = sender_db->get_seal_context();

        QueryRequest sent = make_honest_query(sender_db->get_params());
        QueryRequest received = receive(sent, context);

        // The same query with each ciphertext loaded as it is read, rather than held in
        // serialized form
        auto loaded = make_unique<SenderOperationQuery>();
        loaded->compr_mode = received->compr_mode;
        loaded->relin_keys = received->relin_keys;
        loaded->params_fingerprint = received->params_fingerprint;
        for (const auto &q : received->data) {
            for (const auto &ct : q.second) {
                vector<unsigned char> bytes(ct.save_size(compr_mode_type::none));
                bytes.resize(ct.save(bytes, compr_mode_type::none));
                loaded->data[q.first].emplace_back();
                loaded->data[q.first].back().load(context, bytes);
            }
        }

        Query from_sent(std::move(sent), sender_db);
        Query from_received(std::move(received), sender_db);
        Query from_loaded(std::move(loaded), sender_db);
        ASSERT_TRUE(from_sent.is_valid());
        ASSERT_TRUE(from_received.is_valid());
        ASSERT_TRUE(from_loaded.is_valid());

        ASSERT_EQ(saved_ciphertexts(from_sent), saved_ciphertexts(from_received));
        ASSERT_EQ(saved_ciphertexts(from_loaded), saved_ciphertexts(from_received));

        vector<vector<unsigned char>> packages = answer(from_loaded);
        ASSERT_FALSE(packages.empty());
        ASSERT_EQ(packages, answer(from_received));
        ASSERT_EQ(packages, answer(from_sent));
    }

    TEST(QueryTests, DeepCopyOfAValidQueryIsValidAndHasCiphertextsOfItsOwn)
    {
        // A copy of a valid query is valid, holds the same compression mode, relinearization keys,
        // PowersDag, parameter fingerprint and ciphertexts, shares the SenderDB, and is answered
        // exactly as the query is
        auto sender_db = make_shared<SenderDB>(make_test_params());
        for (uint64_t i = 0; i < 20; i++) {
            sender_db->insert_or_assign(HashedItem(i, i));
        }
        Query query(make_honest_query(sender_db->get_params()), sender_db);
        ASSERT_TRUE(query.is_valid());
        ASSERT_LT(size_t(0), query.relin_keys().size());
        ASSERT_TRUE(query.params_fingerprint().has_value());

        Query copy = query.deep_copy();
        ASSERT_TRUE(copy.is_valid());
        ASSERT_EQ(query.compr_mode(), copy.compr_mode());
        ASSERT_EQ(saved_relin_keys(query), saved_relin_keys(copy));
        ASSERT_TRUE(copy.pd().is_configured());
        ASSERT_EQ(query.pd().to_dot(), copy.pd().to_dot());
        ASSERT_EQ(query.params_fingerprint(), copy.params_fingerprint());
        ASSERT_EQ(saved_ciphertexts(query), saved_ciphertexts(copy));
        ASSERT_EQ(query.sender_db(), copy.sender_db());

        vector<vector<unsigned char>> packages = answer(query);
        ASSERT_FALSE(packages.empty());
        ASSERT_EQ(packages, answer(copy));

        // The copy's ciphertexts are its own: changing every one of them leaves the query's as
        // they were. Query gives access to its ciphertexts only for reading, as nothing else
        // changes them, but the copy is not a const object, so a const_cast may change them.
        map<uint32_t, vector<vector<unsigned char>>> saved = saved_ciphertexts(query);
        Evaluator evaluator(*sender_db->get_seal_context());
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        auto &copy_data = const_cast<unordered_map<uint32_t, vector<Ciphertext>> &>(copy.data());
        for (auto &q : copy_data) {
            for (auto &ct : q.second) {
                evaluator.negate_inplace(ct);
            }
        }
        ASSERT_NE(saved, saved_ciphertexts(copy));
        ASSERT_EQ(saved, saved_ciphertexts(query));
    }

    // SEAL compresses what it saves, and a ciphertext whose data is zero compresses so well that a
    // query of a few kilobytes can hold gigabytes of ciphertexts. The ciphertexts of a received
    // query are therefore loaded only once their number is known to be what the parameters call
    // for. In the tests below, the ciphertexts that should never be loaded are bytes that fail to
    // load, so that an error about them would show that they were loaded after all.

    TEST(QueryTests, RefusesTooManyCiphertextsWithoutLoadingThem)
    {
        auto sender_db = make_shared<SenderDB>(make_wider_params());
        auto context = sender_db->get_seal_context();
        size_t bundle_idx_count = sender_db->get_params().bundle_idx_count();
        ASSERT_EQ(size_t(2), bundle_idx_count);

        // Ten times as many ciphertexts for each power as the parameters call for
        QueryRequest request = receive(make_honest_query(sender_db->get_params()), context);
        for (auto &q : request->data) {
            q.second.resize(10 * bundle_idx_count, not_a_ciphertext());
        }

        ErrorCapture errors;
        Query query(std::move(request), sender_db);
        ASSERT_FALSE(query.is_valid());
        ASSERT_TRUE(errors.logged_only(
            "contains 20 ciphertexts which does not match with bundle_idx_count (2)"));
    }

    TEST(QueryTests, RefusesOtherPowersWithoutLoadingThem)
    {
        auto sender_db = make_shared<SenderDB>(make_wider_params());
        auto context = sender_db->get_seal_context();
        vector<SEALObject<Ciphertext>> cts(
            sender_db->get_params().bundle_idx_count(), not_a_ciphertext());

        // A power the parameters do not call for, as well as those they do
        {
            QueryRequest request = receive(make_honest_query(sender_db->get_params()), context);
            ASSERT_EQ(size_t(0), request->data.count(2));
            request->data[2] = cts;

            ErrorCapture errors;
            ASSERT_FALSE(Query(std::move(request), sender_db).is_valid());
            ASSERT_TRUE(errors.logged_only(
                "contains 4 ciphertext powers which does not match with the size of "
                "query_powers (3)"));
        }

        // A power the parameters do not call for, in place of one they do
        {
            QueryRequest request = receive(make_honest_query(sender_db->get_params()), context);
            request->data.erase(5);
            request->data[2] = cts;

            ErrorCapture errors;
            ASSERT_FALSE(Query(std::move(request), sender_db).is_valid());
            ASSERT_TRUE(errors.logged_only("query power 2 does not match with a source node"));
        }

        // Fewer powers than the parameters call for
        {
            QueryRequest request = receive(make_honest_query(sender_db->get_params()), context);
            request->data.erase(5);
            for (auto &q : request->data) {
                q.second = cts;
            }

            ErrorCapture errors;
            ASSERT_FALSE(Query(std::move(request), sender_db).is_valid());
            ASSERT_TRUE(errors.logged_only(
                "contains 2 ciphertext powers which does not match with the size of "
                "query_powers (3)"));
        }
    }

    TEST(QueryTests, RefusesBytesThatAreNotACiphertext)
    {
        // With the right number of ciphertexts, the ciphertexts are loaded, and one that cannot be
        // makes the query invalid rather than throwing
        auto sender_db = make_shared<SenderDB>(make_wider_params());
        auto context = sender_db->get_seal_context();
        QueryRequest request = receive(make_honest_query(sender_db->get_params()), context);
        request->data.at(3).back() = not_a_ciphertext();

        ErrorCapture errors;
        Query query(std::move(request), sender_db);
        ASSERT_FALSE(query.is_valid());

        // Microsoft SEAL reads the bytes as the header of a version it does not know, which shows
        // that loading them was tried rather than refused for their size
        ASSERT_TRUE(errors.logged_exactly(
            "Failed to extract a ciphertext for exponent 3: incompatible version"));
    }

    TEST(QueryTests, LoadsNoCiphertextAfterAnInvalidOne)
    {
        // Each ciphertext is checked as soon as it is loaded, so that an invalid query costs the
        // sender at most one invalid ciphertext. The first ciphertext loaded here is valid for
        // SEAL but has the largest size SEAL allows. Its data is zero, and it is saved without
        // compression, as compressed it would take too few bytes to be loaded at all. Every other
        // is not a ciphertext at all.
        auto sender_db = make_shared<SenderDB>(make_wider_params());
        auto context = sender_db->get_seal_context();
        QueryRequest request = receive(make_honest_query(sender_db->get_params()), context);

        Ciphertext zero(*context);
        zero.resize(SEAL_CIPHERTEXT_SIZE_MAX);
        vector<unsigned char> zero_bytes = save_ciphertext(zero, compr_mode_type::none);

        // Query loads the ciphertexts in the order the query data is iterated in
        bool first = true;
        for (auto &q : request->data) {
            for (auto &ct : q.second) {
                if (first) {
                    ct.set_serialized(zero_bytes);
                    first = false;
                } else {
                    ct = not_a_ciphertext();
                }
            }
        }

        ErrorCapture errors;
        Query query(std::move(request), sender_db);
        ASSERT_FALSE(query.is_valid());
        ASSERT_TRUE(errors.logged_exactly(
            "Extracted ciphertext has size 16; expected a fresh encryption of size 2"));
    }

    TEST(QueryTests, RefusesACiphertextThatTakesTooFewBytes)
    {
        // A ciphertext whose data is zero is valid for SEAL, and compressed it takes almost
        // nothing, so a query of such ciphertexts would load to thousands of times its size. A
        // ciphertext held in serialized form must take at least 1/64 of the bytes it would load
        // to, a fresh encryption of size 2 at the first level of the modulus chain: here 2 * 4096
        // coefficients of two primes, of 8 bytes each. One of zeros is refused before it is
        // loaded, and accepted if saved without compression.
        if (Serialization::compr_mode_default == compr_mode_type::none) {
            GTEST_SKIP() << "Microsoft SEAL is built without compression";
        }

        auto sender_db = make_shared<SenderDB>(make_wider_params());
        auto context = sender_db->get_seal_context();
        Ciphertext zero(*context);
        zero.resize(2);

        auto query_holding = [&](const vector<unsigned char> &bytes) {
            QueryRequest request = receive(make_honest_query(sender_db->get_params()), context);
            request->data.at(3).back().set_serialized(bytes);
            return Query(std::move(request), sender_db);
        };

        ASSERT_TRUE(query_holding(save_ciphertext(zero, compr_mode_type::none)).is_valid());

        vector<unsigned char> compressed = save_ciphertext(zero, Serialization::compr_mode_default);
        ErrorCapture errors;
        ASSERT_FALSE(query_holding(compressed).is_valid());
        ASSERT_TRUE(errors.logged_exactly(
            "Failed to extract a ciphertext for exponent 3: it takes " +
            to_string(compressed.size()) + " bytes, less than 1/64 of the " +
            to_string(2 * 4096 * 2 * 8) + " bytes it would load to"));
    }

    TEST(QueryTests, RejectsTamperedCiphertextsAsReceived)
    {
        // The checks on a ciphertext apply alike to one that is loaded only when the Query is
        // created
        auto sender_db = make_shared<SenderDB>(make_test_params());
        auto context = sender_db->get_seal_context();
        Evaluator evaluator(*context);

        vector<pair<function<void(Ciphertext &)>, string>> tamperings{
            { [&evaluator](Ciphertext &ct) { evaluator.mod_switch_to_next_inplace(ct); },
              "is not at the highest level of the modulus chain" },
            { [&evaluator](Ciphertext &ct) { evaluator.transform_to_ntt_inplace(ct); },
              "is in NTT form" },
            { [&evaluator](Ciphertext &ct) {
                 Ciphertext squared;
                 evaluator.square(ct, squared);
                 ct = std::move(squared);
             },
              "has size 3;" },
        };
        for (const auto &[tamper, error] : tamperings) {
            SCOPED_TRACE(error);

            QueryRequest request = receive(make_honest_query(sender_db->get_params()), context);
            auto &ct = request->data.begin()->second[0];
            Ciphertext tampered = ct.extract(context);
            tamper(tampered);
            ct.set_serialized(save_ciphertext(tampered, Serialization::compr_mode_default));

            ErrorCapture errors;
            ASSERT_FALSE(Query(std::move(request), sender_db).is_valid());
            ASSERT_TRUE(errors.logged_only(error));
        }
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
