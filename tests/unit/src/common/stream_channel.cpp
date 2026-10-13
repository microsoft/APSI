// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstdint>
#include <sstream>
#include <string>
#include <thread>
#include <utility>

// SEAL
#include "seal/keygenerator.h"
#include "seal/publickey.h"

// APSI
#include "apsi/network/stream_channel.h"
#include "apsi/powers.h"
#include "apsi/util/utils.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::network;

namespace APSITests {
    namespace {
        shared_ptr<PSIParams> get_params()
        {
            static shared_ptr<PSIParams> params = nullptr;
            if (!params) {
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
                seal_params.set_coeff_modulus(CoeffModulus::Create(pmd, { 40, 40 }));
                seal_params.set_plain_modulus(65537);

                params =
                    make_shared<PSIParams>(item_params, table_params, query_params, seal_params);
            }

            return params;
        }

        shared_ptr<CryptoContext> get_context()
        {
            static shared_ptr<CryptoContext> context = nullptr;
            if (!context) {
                context = make_shared<CryptoContext>(*get_params());
                KeyGenerator keygen(*context->seal_context());
                context->set_secret(keygen.secret_key());
                RelinKeys rlk;
                keygen.create_relin_keys(rlk);
                context->set_evaluator(std::move(rlk));
            }

            return context;
        }

        /**
        Parameters with match tags and the same encryption parameters as get_params, so that
        get_context can encrypt for them: three tag parts of 16 bits, one field element per item.
        */
        PSIParams get_tag_params()
        {
            PSIParams::ItemParams item_params;
            item_params.felts_per_item = 1;
            item_params.tag_part_count = 3;

            PSIParams::TableParams table_params = get_params()->table_params();
            table_params.table_size = 4096;

            return {
                item_params, table_params, get_params()->query_params(), get_params()->seal_params()
            };
        }

        unique_ptr<ResultPackage> make_package(bool with_psi_result, size_t part_count)
        {
            Ciphertext ct;
            get_context()->encryptor()->encrypt_zero_symmetric(ct);

            auto rp = make_unique<ResultPackage>();
            rp->bundle_idx = 0;
            if (with_psi_result) {
                rp->psi_result = ct;
            }
            for (size_t i = 0; i < part_count; i++) {
                rp->label_result.emplace_back(ct);
            }
            return rp;
        }

        /**
        A channel written outside APSI: it implements receive_result only, here by handing out
        packages it has been given, and inherits receive_result_for.
        */
        class PresetChannel final : public Channel {
        public:
            void send(unique_ptr<SenderOperation>) override
            {}

            unique_ptr<SenderOperation> receive_operation(
                shared_ptr<SEALContext>, SenderOperationType) override
            {
                return nullptr;
            }

            void send(unique_ptr<SenderOperationResponse>) override
            {}

            unique_ptr<SenderOperationResponse> receive_response(SenderOperationType) override
            {
                return nullptr;
            }

            void send(unique_ptr<ResultPackage> rp) override
            {
                packages.push_back(std::move(rp));
            }

            unique_ptr<ResultPackage> receive_result(shared_ptr<SEALContext>) override
            {
                if (packages.empty()) {
                    return nullptr;
                }
                auto rp = std::move(packages.front());
                packages.erase(packages.begin());
                return rp;
            }

            vector<unique_ptr<ResultPackage>> packages;
        };
    } // namespace

    class StreamChannelTests : public ::testing::Test {};

    TEST_F(StreamChannelTests, ReceiveResultForChecksTheStructureOfTagResults)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel svr(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel clt(/* istream */ stream2, /* ostream */ stream1);

        PSIParams tag_params = get_tag_params();

        // A package with the structure the parameters call for is received
        svr.send(make_package(false, 3));
        auto rp = clt.receive_result_for(get_context()->seal_context(), tag_params);
        ASSERT_NE(nullptr, rp);
        ASSERT_EQ(3, rp->label_result.size());
        ASSERT_FALSE(clt.receive_failed());

        // One without it is a failed receive, as an unreadable package is
        svr.send(make_package(true, 3));
        ASSERT_EQ(nullptr, clt.receive_result_for(get_context()->seal_context(), tag_params));
        ASSERT_TRUE(clt.receive_failed());

        // Without match tags, a package is received if it has a PSI result and no more label parts
        // than its label takes: three of 128 bits for a label of 33 bytes, but only two for 32
        StreamChannel clt2(/* istream */ stream2, /* ostream */ stream1);
        auto package_with_label = [](uint32_t label_byte_count) {
            auto package = make_package(true, 3);
            package->label_byte_count = label_byte_count;
            return package;
        };

        svr.send(package_with_label(33));
        rp = clt2.receive_result_for(get_context()->seal_context(), *get_params());
        ASSERT_NE(nullptr, rp);
        ASSERT_EQ(3, rp->label_result.size());
        ASSERT_FALSE(clt2.receive_failed());

        svr.send(package_with_label(32));
        ASSERT_EQ(nullptr, clt2.receive_result_for(get_context()->seal_context(), *get_params()));
        ASSERT_TRUE(clt2.receive_failed());
    }

    TEST_F(StreamChannelTests, ReceiveResultForRequiresPSIResultWithoutTags)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel svr(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel clt(/* istream */ stream2, /* ostream */ stream1);

        // Without match tags every result package has a PSI result, which the schema of APSI 1.x
        // requires. The schema does not, as a result for parameters with match tags has none, so
        // a package without one must fail the receive: Receiver::request_query then aborts the
        // query instead of returning partial results.
        svr.send(make_package(true, 0));
        ASSERT_NE(nullptr, clt.receive_result_for(get_context()->seal_context(), *get_params()));
        ASSERT_FALSE(clt.receive_failed());

        svr.send(make_package(false, 0));
        ASSERT_EQ(nullptr, clt.receive_result_for(get_context()->seal_context(), *get_params()));
        ASSERT_TRUE(clt.receive_failed());

        // The overload of ResultPackage::load with parameters refuses it in the same way, while the
        // one without parameters loads it
        stringstream ss;
        make_package(false, 0)->save(ss);
        string saved = ss.str();

        ResultPackage rp;
        stringstream in1(saved);
        ASSERT_THROW(rp.load(in1, get_context()->seal_context(), *get_params()), runtime_error);
        stringstream in2(saved);
        ASSERT_NO_THROW(rp.load(in2, get_context()->seal_context()));
        ASSERT_FALSE(rp.psi_result);
    }

    TEST_F(StreamChannelTests, DefaultReceiveResultForChecksTheLoadedPackage)
    {
        PSIParams tag_params = get_tag_params();

        PresetChannel chl;
        chl.send(make_package(false, 3));
        chl.send(make_package(false, 2));
        chl.send(make_package(true, 3));

        ASSERT_NE(nullptr, chl.receive_result_for(get_context()->seal_context(), tag_params));
        ASSERT_FALSE(chl.receive_failed());
        ASSERT_EQ(nullptr, chl.receive_result_for(get_context()->seal_context(), tag_params));
        ASSERT_TRUE(chl.receive_failed());

        // Without match tags only the presence of the PSI result is checked
        ASSERT_NE(nullptr, chl.receive_result_for(get_context()->seal_context(), *get_params()));

        // And nothing arriving is still not a failure of its own
        uint64_t failures = chl.receive_failure_count();
        ASSERT_EQ(nullptr, chl.receive_result_for(get_context()->seal_context(), tag_params));
        ASSERT_EQ(failures, chl.receive_failure_count());

        // A package without a PSI result is a failed receive without match tags
        chl.send(make_package(false, 3));
        ASSERT_EQ(nullptr, chl.receive_result_for(get_context()->seal_context(), *get_params()));
        ASSERT_EQ(failures + 1, chl.receive_failure_count());
    }

    TEST_F(StreamChannelTests, SendReceiveParms)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel svr(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel clt(/* istream */ stream2, /* ostream */ stream1);

        unique_ptr<SenderOperation> sop = make_unique<SenderOperationParms>();

        // Send a parms operation
        clt.send(std::move(sop));

        sop = svr.receive_operation(get_context()->seal_context());
        ASSERT_NE(nullptr, sop);
        ASSERT_EQ(SenderOperationType::sop_parms, sop->type());

        // Create a parms response
        auto rsop_parms = make_unique<SenderOperationResponseParms>();
        rsop_parms->params = make_unique<PSIParams>(*get_params());
        unique_ptr<SenderOperationResponse> rsop = std::move(rsop_parms);
        svr.send(std::move(rsop));

        // Receive the parms response
        rsop = clt.receive_response(SenderOperationType::sop_parms);
        rsop_parms.reset(dynamic_cast<SenderOperationResponseParms *>(rsop.release()));

        // We received valid parameters
        ASSERT_EQ(get_params()->item_bit_count(), rsop_parms->params->item_bit_count());

        ASSERT_EQ(svr.bytes_sent(), clt.bytes_received());
        ASSERT_EQ(svr.bytes_received(), clt.bytes_sent());
    }

    TEST_F(StreamChannelTests, SendReceiveOPRFTest)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel svr(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel clt(/* istream */ stream2, /* ostream */ stream1);

        // Fill a data buffer
        vector<unsigned char> oprf_data(256);
        for (size_t i = 0; i < oprf_data.size(); i++) {
            oprf_data[i] = static_cast<unsigned char>(i);
        }

        auto sop_oprf = make_unique<SenderOperationOPRF>();
        sop_oprf->data = oprf_data;
        unique_ptr<SenderOperation> sop = std::move(sop_oprf);

        // Send an OPRF operation
        clt.send(std::move(sop));

        // Receive the operation
        sop = svr.receive_operation(get_context()->seal_context());
        ASSERT_EQ(SenderOperationType::sop_oprf, sop->type());
        sop_oprf.reset(dynamic_cast<SenderOperationOPRF *>(sop.release()));

        // Validate the data
        ASSERT_EQ(256, sop_oprf->data.size());
        for (size_t i = 0; i < sop_oprf->data.size(); i++) {
            ASSERT_EQ(static_cast<char>(sop_oprf->data[i]), static_cast<char>(i));
        }

        // Create an OPRF response
        auto rsop_oprf = make_unique<SenderOperationResponseOPRF>();
        rsop_oprf->data = oprf_data;
        unique_ptr<SenderOperationResponse> rsop = std::move(rsop_oprf);
        svr.send(std::move(rsop));

        // Receive the OPRF response
        rsop = clt.receive_response(SenderOperationType::sop_oprf);
        rsop_oprf.reset(dynamic_cast<SenderOperationResponseOPRF *>(rsop.release()));

        // Validate the data
        ASSERT_EQ(256, rsop_oprf->data.size());
        for (size_t i = 0; i < rsop_oprf->data.size(); i++) {
            ASSERT_EQ(static_cast<char>(rsop_oprf->data[i]), static_cast<char>(i));
        }

        ASSERT_EQ(svr.bytes_sent(), clt.bytes_received());
        ASSERT_EQ(svr.bytes_received(), clt.bytes_sent());
    }

    TEST_F(StreamChannelTests, SendReceiveQuery)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel svr(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel clt(/* istream */ stream2, /* ostream */ stream1);

        auto sop_query = make_unique<SenderOperationQuery>();
        sop_query->relin_keys = *get_context()->relin_keys();
        sop_query->data[0].emplace_back(get_context()->encryptor()->encrypt_zero_symmetric());
        sop_query->data[123].emplace_back(get_context()->encryptor()->encrypt_zero_symmetric());
        unique_ptr<SenderOperation> sop = std::move(sop_query);

        // Send a query operation
        clt.send(std::move(sop));

        // Receive the operation
        sop = svr.receive_operation(get_context()->seal_context());
        ASSERT_EQ(SenderOperationType::sop_query, sop->type());
        sop_query.reset(dynamic_cast<SenderOperationQuery *>(sop.release()));

        // Are we able to extract the relinearization keys?
        ASSERT_NO_THROW(auto rlk = sop_query->relin_keys.extract_if_local());

        // Check for query ciphertexts. They are received in serialized form, and loaded only when
        // they are extracted.
        ASSERT_EQ(2, sop_query->data.size());

        ASSERT_FALSE(sop_query->data.at(0).empty());
        ASSERT_EQ(1, sop_query->data[0].size());
        ASSERT_TRUE(sop_query->data[0][0].is_serialized());
        auto query_ct0 = sop_query->data[0][0].extract(get_context()->seal_context());

        ASSERT_FALSE(sop_query->data.at(123).empty());
        ASSERT_EQ(1, sop_query->data[123].size());
        ASSERT_TRUE(sop_query->data[123][0].is_serialized());
        auto query_ct123 = sop_query->data[123][0].extract(get_context()->seal_context());

        // Create a query response
        auto rsop_query = make_unique<SenderOperationResponseQuery>();
        rsop_query->package_count = 2;
        unique_ptr<SenderOperationResponse> rsop = std::move(rsop_query);
        svr.send(std::move(rsop));

        // Receive the query response
        rsop = clt.receive_response(SenderOperationType::sop_query);
        rsop_query.reset(dynamic_cast<SenderOperationResponseQuery *>(rsop.release()));

        // Validate the data
        ASSERT_EQ(2, rsop_query->package_count);

        // Send two ResultPackages
        auto rp = make_unique<ResultPackage>();
        rp->bundle_idx = 0;
        rp->label_byte_count = 0;
        rp->nonce_byte_count = 0;
        rp->psi_result = query_ct0;
        svr.send(std::move(rp));

        rp = make_unique<ResultPackage>();
        rp->bundle_idx = 123;
        rp->label_byte_count = 80;
        rp->nonce_byte_count = 4;
        rp->psi_result = query_ct123;
        rp->label_result.emplace_back(query_ct123);
        svr.send(std::move(rp));

        // Receive two packages
        rp = clt.receive_result(get_context()->seal_context());
        ASSERT_EQ(0, rp->bundle_idx);
        ASSERT_EQ(0, rp->label_byte_count);
        ASSERT_EQ(0, rp->bundle_idx);
        ASSERT_TRUE(rp->label_result.empty());

        rp = clt.receive_result(get_context()->seal_context());
        ASSERT_EQ(123, rp->bundle_idx);
        ASSERT_EQ(80, rp->label_byte_count);
        ASSERT_EQ(4, rp->nonce_byte_count);
        ASSERT_EQ(1, rp->label_result.size());

        ASSERT_EQ(svr.bytes_sent(), clt.bytes_received());
        ASSERT_EQ(svr.bytes_received(), clt.bytes_sent());
    }

    // The tests below pin down what a null return from a receive means. A caller that waits
    // for a message loops until it gets one, so it needs to know whether waiting longer can
    // possibly help. receive_failed answers that: it is set exactly when the channel has taken
    // input off the wire that it could not turn into an object, or has been asked for
    // something it can never produce. In both cases the awaited message will never arrive, and
    // a caller that keeps waiting waits forever.

    TEST_F(StreamChannelTests, ReceiveFailedStaysClearThroughAHealthyExchange)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel svr(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel clt(/* istream */ stream2, /* ostream */ stream1);

        clt.send(unique_ptr<SenderOperation>(make_unique<SenderOperationParms>()));
        ASSERT_NE(nullptr, svr.receive_operation(get_context()->seal_context()));

        auto rsop_parms = make_unique<SenderOperationResponseParms>();
        rsop_parms->params = make_unique<PSIParams>(*get_params());
        svr.send(unique_ptr<SenderOperationResponse>(std::move(rsop_parms)));
        ASSERT_NE(nullptr, clt.receive_response(SenderOperationType::sop_parms));

        ASSERT_FALSE(svr.receive_failed());
        ASSERT_FALSE(clt.receive_failed());
    }

    TEST_F(StreamChannelTests, UnreadableResponseIsReportedAsFailure)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel svr(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel clt(/* istream */ stream2, /* ostream */ stream1);

        // Bytes that are not a serialized header at all
        stream2 << "not a serialized message";

        ASSERT_EQ(nullptr, clt.receive_response());
        ASSERT_TRUE(clt.receive_failed());
    }

    TEST_F(StreamChannelTests, ResponseOfTheWrongTypeIsReportedAsFailure)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel svr(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel clt(/* istream */ stream2, /* ostream */ stream1);

        auto rsop_parms = make_unique<SenderOperationResponseParms>();
        rsop_parms->params = make_unique<PSIParams>(*get_params());
        svr.send(unique_ptr<SenderOperationResponse>(std::move(rsop_parms)));

        // Naming an expected type is what lets the channel reject this. The header is consumed
        // and the body is left in the stream, so a caller that asked for sop_oprf will never see
        // this message and cannot read anything after it either; it must be told to stop waiting
        // rather than left to ask again.
        ASSERT_EQ(nullptr, clt.receive_response(SenderOperationType::sop_oprf));
        ASSERT_TRUE(clt.receive_failed());
    }

    TEST_F(StreamChannelTests, UnreadableResultPackageIsReportedAsFailure)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel svr(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel clt(/* istream */ stream2, /* ostream */ stream1);

        stream2 << "not a serialized result package";

        ASSERT_EQ(nullptr, clt.receive_result(get_context()->seal_context()));
        ASSERT_TRUE(clt.receive_failed());
    }

    TEST_F(StreamChannelTests, ResultPackageWithoutAContextIsReportedAsFailure)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel svr(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel clt(/* istream */ stream2, /* ostream */ stream1);

        // A result package can never be decoded without a SEALContext, so no amount of waiting
        // will make this call succeed.
        ASSERT_EQ(nullptr, clt.receive_result(nullptr));
        ASSERT_TRUE(clt.receive_failed());
    }

    TEST_F(StreamChannelTests, StreamThatHasEndedIsReportedAsFailure)
    {
        // Every message begins with a size prefix. A stream that ends before one has been read in
        // full holds no message, even if the bytes it does hold would read as a size of zero, and
        // a stream does not resume once it has ended. Every receive returns nullptr and records a
        // failure, every time it is called.
        for (const string &data : { string(), string(2, '\0'), string(3, '\x7F') }) {
            SCOPED_TRACE(data.size());

            auto expect_failure = [](Channel &chl, const auto &receive) {
                for (int attempt = 0; attempt < 2; attempt++) {
                    uint64_t failures = chl.receive_failure_count();
                    ASSERT_EQ(nullptr, receive());
                    ASSERT_EQ(failures + 1, chl.receive_failure_count());
                }
            };

            stringstream in(data);
            stringstream out;
            StreamChannel chl(in, out);
            ASSERT_NO_FATAL_FAILURE(expect_failure(
                chl, [&] { return chl.receive_operation(get_context()->seal_context()); }));

            in.clear();
            in.str(data);
            ASSERT_NO_FATAL_FAILURE(expect_failure(chl, [&] { return chl.receive_response(); }));

            in.clear();
            in.str(data);
            ASSERT_NO_FATAL_FAILURE(expect_failure(
                chl, [&] { return chl.receive_result(get_context()->seal_context()); }));

            in.clear();
            in.str(data);
            ASSERT_NO_FATAL_FAILURE(expect_failure(chl, [&] {
                return chl.receive_result_for(get_context()->seal_context(), *get_params());
            }));

            ASSERT_TRUE(out.str().empty());
        }
    }

    TEST_F(StreamChannelTests, SendingToAStreamThatCannotTakeItFails)
    {
        // The save functions return the number of bytes they meant to write, and an ostream
        // that cannot take them says nothing, so a send has to ask the stream rather than trust
        // the count. A sender tells a receiver how many result packages to expect and then
        // writes them; one that went nowhere leaves the receiver waiting for it, and the sender
        // recording a query it answered in full.
        stringstream in;
        stringstream out;
        StreamChannel svr(in, out);

        out.setstate(ios_base::badbit);

        auto sop_response = make_unique<SenderOperationResponseParms>();
        sop_response->params = make_unique<PSIParams>(*get_params());
        ASSERT_THROW(
            svr.send(unique_ptr<SenderOperationResponse>(std::move(sop_response))), runtime_error);

        auto rp = make_unique<ResultPackage>();
        rp->bundle_idx = 0;
        rp->label_byte_count = 0;
        rp->nonce_byte_count = 0;
        Ciphertext ct;
        get_context()->encryptor()->encrypt_zero_symmetric(ct);
        rp->psi_result = std::move(ct);
        ASSERT_THROW(svr.send(std::move(rp)), runtime_error);

        auto sop = make_unique<SenderOperationParms>();
        ASSERT_THROW(svr.send(unique_ptr<SenderOperation>(std::move(sop))), runtime_error);
    }

    namespace {
        /**
        A stream buffer large enough to hold a whole message, whose sink always refuses. This is
        what an ordinary buffered stream over a failing sink looks like: writes land in the
        buffer and the sink is not consulted until something flushes.
        */
        class RefusingBuf : public streambuf {
        public:
            RefusingBuf() : buffer_(std::size_t{ 1 } << 20U)
            {
                setp(buffer_.data(), buffer_.data() + buffer_.size());
            }

            [[nodiscard]] size_t sync_calls() const noexcept
            {
                return sync_calls_;
            }

            [[nodiscard]] size_t overflow_calls() const noexcept
            {
                return overflow_calls_;
            }

        protected:
            int overflow(int) override
            {
                overflow_calls_++;
                return traits_type::eof();
            }

            int sync() override
            {
                sync_calls_++;
                return -1;
            }

        private:
            vector<char> buffer_;
            size_t sync_calls_ = 0;
            size_t overflow_calls_ = 0;
        };
    } // namespace

    TEST_F(StreamChannelTests, SendingToABufferedStreamWhoseSinkRefusesFails)
    {
        // A buffered stream takes a whole message without consulting its sink, so asking the
        // stream how it is directly after writing tells you nothing. A sender writes a fixed
        // number of result packages and then stops, so were the failure left to surface at some
        // later write, the last package of every query would be lost with nobody the wiser: the
        // receiver waits for a package it was promised, and the sender records a query it
        // answered in full.
        stringstream in;
        RefusingBuf buf;
        ostream out(&buf);
        StreamChannel svr(in, out);

        auto rp = make_unique<ResultPackage>();
        rp->bundle_idx = 0;
        rp->label_byte_count = 0;
        rp->nonce_byte_count = 0;
        Ciphertext ct;
        get_context()->encryptor()->encrypt_zero_symmetric(ct);
        rp->psi_result = std::move(ct);

        ASSERT_THROW(svr.send(std::move(rp)), runtime_error);

        // The sink was asked because the message was flushed, not because it outgrew the
        // buffer. Counted separately so that a larger message later cannot quietly turn this
        // into a test of something else.
        ASSERT_EQ(size_t(0), buf.overflow_calls());
        ASSERT_LT(size_t(0), buf.sync_calls());

        // Nothing reached the peer, so nothing is counted as having been sent.
        ASSERT_EQ(size_t(0), svr.bytes_sent());
    }
} // namespace APSITests
