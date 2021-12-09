// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <iterator>
#include <sstream>
#include <stdexcept>

// APSI
#include "apsi/network/sender_operation.h"
#include "apsi/network/sop_generated.h"
#include "apsi/network/sop_header_generated.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/serialization.h"
#include "seal/util/common.h"
#include "seal/util/streambuf.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi {
    using namespace util;

    namespace network {
        const char *sender_operation_type_str(SenderOperationType sop_type)
        {
            switch (sop_type) {
            case SenderOperationType::sop_unknown:
                return "sop_unknown";

            case SenderOperationType::sop_parms:
                return "sop_parms";

            case SenderOperationType::sop_oprf:
                return "sop_oprf";

            case SenderOperationType::sop_query:
                return "sop_query";

            default:
                return "sop_invalid";
            }
        }

        size_t SenderOperationHeader::save(ostream &out) const
        {
            flatbuffers::FlatBufferBuilder fbs_builder(128);

            fbs::SenderOperationHeaderBuilder sop_header_builder(fbs_builder);
            sop_header_builder.add_version(version);
            sop_header_builder.add_type(static_cast<fbs::SenderOperationType>(type));
            auto sop_header = sop_header_builder.Finish();
            fbs_builder.FinishSizePrefixed(sop_header);

            out.write(
                reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t SenderOperationHeader::load(istream &in)
        {
            vector<unsigned char> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(
                reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderOperationHeaderBuffer(verifier);
            if (!safe) {
                throw runtime_error("failed to load SenderOperationHeader: invalid buffer");
            }

            auto sop_header = fbs::GetSizePrefixedSenderOperationHeader(in_data.data());

            // Read the serialization version number
            version = sop_header->version();

            // Read the operation type
            type = static_cast<SenderOperationType>(sop_header->type());

            return in_data.size();
        }

        size_t SenderOperationParms::save(ostream &out) const
        {
            flatbuffers::FlatBufferBuilder fbs_builder(1024);

            auto parms_request = fbs::CreateParmsRequest(fbs_builder);

            fbs::SenderOperationBuilder sop_builder(fbs_builder);
            sop_builder.add_request_type(fbs::Request_ParmsRequest);
            sop_builder.add_request(parms_request.Union());
            auto sop = sop_builder.Finish();
            fbs_builder.FinishSizePrefixed(sop);

            out.write(
                reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t SenderOperationParms::load(istream &in, shared_ptr<SEALContext> context)
        {
            // The context cannot be set for this operation
            if (context) {
                throw invalid_argument("context must be null");
            }

            vector<unsigned char> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(
                reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderOperationBuffer(verifier);
            if (!safe) {
                throw runtime_error("failed to load SenderOperation: invalid buffer");
            }

            auto sop = fbs::GetSizePrefixedSenderOperation(in_data.data());

            // Need to check that the operation is of the right type
            if (sop->request_type() != fbs::Request_ParmsRequest) {
                throw runtime_error("unexpected operation type");
            }

            return in_data.size();
        }

        size_t SenderOperationOPRF::save(ostream &out) const
        {
            flatbuffers::FlatBufferBuilder fbs_builder(1024);

            auto oprf_data = fbs_builder.CreateVector(
                reinterpret_cast<const uint8_t *>(data.data()), data.size());
            auto req = fbs::CreateOPRFRequest(fbs_builder, oprf_data);

            fbs::SenderOperationBuilder sop_builder(fbs_builder);
            sop_builder.add_request_type(fbs::Request_OPRFRequest);
            sop_builder.add_request(req.Union());
            auto sop = sop_builder.Finish();
            fbs_builder.FinishSizePrefixed(sop);

            out.write(
                reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t SenderOperationOPRF::load(istream &in, shared_ptr<SEALContext> context)
        {
            // The context cannot be set for this operation
            if (context) {
                throw invalid_argument("context must be null");
            }

            // Clear the current data
            data.clear();

            vector<unsigned char> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(
                reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderOperationBuffer(verifier);
            if (!safe) {
                throw runtime_error("failed to load SenderOperation: invalid buffer");
            }

            auto sop = fbs::GetSizePrefixedSenderOperation(in_data.data());

            // Need to check that the operation is of the right type
            if (sop->request_type() != fbs::Request_OPRFRequest) {
                throw runtime_error("unexpected operation type");
            }

            // Load the OPRF request; this is a required field so we can always dereference
            const auto &oprf_data = *sop->request_as_OPRFRequest()->data();
            data.resize(oprf_data.size());
            copy_bytes(oprf_data.data(), oprf_data.size(), data.data());

            return in_data.size();
        }

        size_t SenderOperationQuery::save(ostream &out) const
        {
            flatbuffers::FlatBufferBuilder fbs_builder(1024);

            vector<unsigned char> temp;
            temp.resize(relin_keys.save_size(compr_mode));
            auto size = relin_keys.save(temp, compr_mode);
            auto relin_keys_data =
                fbs_builder.CreateVector(reinterpret_cast<const uint8_t *>(temp.data()), size);

            // This is a little tricky; each QueryRequestPart consists of an exponent and a vector
            // of Ciphertexts. For convenience, we create vectors in immediately-invoked lambdas and
            // pass them to the CreateVector function. In the outer lambda, we populate a vector of
            // QueryRequestParts, creating a new builder class for each of them. In the inner lambda
            // we build the QueryRequestPart data by creating multiple Ciphertexts.
            auto query_request_parts = fbs_builder.CreateVector([&]() {
                // The QueryRequestPart vector is populated with an immediately-invoked lambda
                vector<flatbuffers::Offset<fbs::QueryRequestPart>> ret;
                for (const auto &q : data) {
                    // Then the vector of Ciphertexts
                    auto cts = fbs_builder.CreateVector([&]() {
                        // The Ciphertext vector is populated with an immediately-invoked lambda
                        vector<flatbuffers::Offset<fbs::Ciphertext>> ret_inner;
                        for (const auto &ct : q.second) {
                            // Save each SEALObject<seal::Ciphertext>
                            temp.resize(ct.save_size(compr_mode));
                            size = ct.save(temp, compr_mode);
                            auto ct_data = fbs_builder.CreateVector(
                                reinterpret_cast<const uint8_t *>(temp.data()), size);

                            // Add to the Ciphertext vector
                            ret_inner.push_back(fbs::CreateCiphertext(fbs_builder, ct_data));
                        }
                        return ret_inner;
                    }());

                    // For each exponent, create a QueryRequestPart
                    auto query_req_part = fbs::CreateQueryRequestPart(fbs_builder, q.first, cts);
                    ret.push_back(query_req_part);
                }
                return ret;
            }());

            auto req = fbs::CreateQueryRequest(
                fbs_builder,
                static_cast<uint8_t>(compr_mode),
                relin_keys_data,
                query_request_parts);

            fbs::SenderOperationBuilder sop_builder(fbs_builder);
            sop_builder.add_request_type(fbs::Request_QueryRequest);
            sop_builder.add_request(req.Union());
            auto sop = sop_builder.Finish();
            fbs_builder.FinishSizePrefixed(sop);

            out.write(
                reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t SenderOperationQuery::load(istream &in, shared_ptr<SEALContext> context)
        {
            // The context must be set and valid for this operation
            if (!context) {
                throw invalid_argument("context cannot be null");
            }
            if (!context->parameters_set()) {
                throw invalid_argument("context is invalid");
            }

            // Clear the current data
            data.clear();

            vector<unsigned char> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(
                reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderOperationBuffer(verifier);
            if (!safe) {
                throw runtime_error("failed to load SenderOperation: invalid buffer");
            }

            auto sop = fbs::GetSizePrefixedSenderOperation(in_data.data());

            // Need to check that the operation is of the right type
            if (sop->request_type() != fbs::Request_QueryRequest) {
                throw runtime_error("unexpected operation type");
            }

            const auto &req = *sop->request_as_QueryRequest();

            // Check the request's compression mode is supported
            if (!Serialization::IsSupportedComprMode(req.compression_type())) {
                throw runtime_error("unsupported compression mode");
            }

            compr_mode = static_cast<compr_mode_type>(req.compression_type());

            // Load relin_keys if they are needed in this case
            if (context->using_keyswitching()) {
                // This is NOT a required field; check if it is present
                if (!req.relin_keys()) {
                    throw runtime_error("realinearization keys data is missing");
                }

                const auto &relin_keys_data = *req.relin_keys();
                gsl::span<const unsigned char> relin_keys_data_span(
                    reinterpret_cast<const unsigned char *>(relin_keys_data.data()),
                    relin_keys_data.size());
                try {
                    relin_keys.load(context, relin_keys_data_span);
                } catch (const logic_error &ex) {
                    stringstream ss;
                    ss << "failed to load relinearization keys: ";
                    ss << ex.what();
                    throw runtime_error(ss.str());
                } catch (const runtime_error &ex) {
                    stringstream ss;
                    ss << "failed to load relinearization keys: ";
                    ss << ex.what();
                    throw runtime_error(ss.str());
                }
            }

            // Load the query data; this is a required field so we can always dereference
            const auto &query = *req.query();
            for (const auto query_part : query) {
                uint32_t exponent = query_part->exponent();
                if (data.count(exponent)) {
                    throw runtime_error("invalid query data");
                }

                // Load the ciphertext data; this is a required field so we can always dereference
                const auto &cts = *query_part->cts();
                vector<SEALObject<Ciphertext>> cts_vec;
                cts_vec.reserve(cts.size());
                for (const auto ct : cts) {
                    gsl::span<const unsigned char> ct_span(
                        reinterpret_cast<const unsigned char *>(ct->data()->data()),
                        ct->data()->size());
                    SEALObject<Ciphertext> temp;
                    try {
                        temp.load(context, ct_span);
                    } catch (const logic_error &ex) {
                        stringstream ss;
                        ss << "failed to load query ciphertext: ";
                        ss << ex.what();
                        throw runtime_error(ss.str());
                    } catch (const runtime_error &ex) {
                        stringstream ss;
                        ss << "failed to load query ciphertext: ";
                        ss << ex.what();
                        throw runtime_error(ss.str());
                    }
                    cts_vec.emplace_back(move(temp));
                }

                data.emplace(exponent, move(cts_vec));
            }

            return in_data.size();
        }
    } // namespace network
} // namespace apsi
