// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstring>
#include <sstream>
#include <stdexcept>

// APSI
#include "apsi/network/sender_operation.h"
#include "apsi/network/sop_header_generated.h"
#include "apsi/network/sop_generated.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    namespace network
    {
        size_t SenderOperationHeader::save(ostream &out) const
        {
            flatbuffers::FlatBufferBuilder fbs_builder(128);
            fbs::SenderOperationHeaderBuilder sop_header_builder(fbs_builder);

            // Write the version number
            sop_header_builder.add_version(version);

            // Write the operation type
            sop_header_builder.add_type(static_cast<fbs::SenderOperationType>(type));

            auto sop_header = sop_header_builder.Finish();
            fbs_builder.FinishSizePrefixed(sop_header);

            out.write(
                reinterpret_cast<const char*>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t SenderOperationHeader::load(istream &in)
        {
            vector<SEAL_BYTE> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(reinterpret_cast<const uint8_t*>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderOperationHeaderBuffer(verifier);
            if (!safe)
            {
                throw runtime_error("failed to load SenderOperationHeader: invalid buffer");
            }

            auto sop_header = fbs::GetSizePrefixedSenderOperationHeader(in_data.data());

            // Read the version number
            version = sop_header->version();

            // Read the operation type
            type = static_cast<SenderOperationType>(sop_header->type());

            return in_data.size();
        }

        size_t SenderOperationParms::save(ostream &out) const
        {
            flatbuffers::FlatBufferBuilder fbs_builder(1024);
            fbs::SenderOperationBuilder sop_builder(fbs_builder);

            sop_builder.add_request_type(fbs::Request_ParmsRequest);
            auto parms_request = fbs::CreateParmsRequest(fbs_builder);
            sop_builder.add_request(parms_request.Union());

            auto sop = sop_builder.Finish();
            fbs_builder.FinishSizePrefixed(sop);

            out.write(
                reinterpret_cast<const char*>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t SenderOperationParms::load(istream &in, shared_ptr<SEALContext> context)
        {
            // The context cannot be set for this operation
            if (context)
            {
                throw invalid_argument("context must be null");
            }

            vector<SEAL_BYTE> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(reinterpret_cast<const uint8_t*>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderOperationBuffer(verifier);
            if (!safe)
            {
                throw runtime_error("failed to load SenderOperation: invalid buffer");
            }

            auto sop = fbs::GetSizePrefixedSenderOperation(in_data.data());

            // Need to check that the operation is of the right type
            if (sop->request_type() != fbs::Request_ParmsRequest)
            {
                throw runtime_error("unexpected operation type");
            }

            return in_data.size();
        }

        size_t SenderOperationOPRF::save(ostream &out) const
        {
            if (data.empty())
            {
                logic_error("OPRF request data is not set");
            }

            flatbuffers::FlatBufferBuilder fbs_builder(1024);
            fbs::SenderOperationBuilder sop_builder(fbs_builder);

            sop_builder.add_request_type(fbs::Request_OPRFRequest);
            fbs::OPRFRequestBuilder oprf_request(fbs_builder);
            auto oprf_data = fbs_builder.CreateVector(reinterpret_cast<const uint8_t*>(data.data()), data.size());
            oprf_request.add_data(oprf_data);
            auto req = oprf_request.Finish();
            sop_builder.add_request(req.Union());

            auto sop = sop_builder.Finish();
            fbs_builder.FinishSizePrefixed(sop);

            out.write(
                reinterpret_cast<const char*>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t SenderOperationOPRF::load(istream &in, shared_ptr<SEALContext> context)
        {
            // The context cannot be set for this operation
            if (context)
            {
                throw invalid_argument("context must be null");
            }

            // Clear the current data
            data.clear();

            vector<SEAL_BYTE> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(reinterpret_cast<const uint8_t*>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderOperationBuffer(verifier);
            if (!safe)
            {
                throw runtime_error("failed to load SenderOperation: invalid buffer");
            }

            auto sop = fbs::GetSizePrefixedSenderOperation(in_data.data());

            // Need to check that the operation is of the right type
            if (sop->request_type() != fbs::Request_OPRFRequest)
            {
                throw runtime_error("unexpected operation type");
            }

            // Load the OPRF request
            const auto &oprf_data = *sop->request_as_OPRFRequest()->data();
            data.resize(oprf_data.size());
            memcpy(data.data(), oprf_data.data(), oprf_data.size());

            return in_data.size();
        }

        size_t SenderOperationQuery::save(ostream &out) const
        {
            if (data.empty())
            {
                logic_error("query data is not set");
            }

            flatbuffers::FlatBufferBuilder fbs_builder(1024);
            fbs::SenderOperationBuilder sop_builder(fbs_builder);

            sop_builder.add_request_type(fbs::Request_QueryRequest);
            fbs::QueryRequestBuilder query_request(fbs_builder);

            vector<SEAL_BYTE> temp;
            temp.resize(relin_keys.save_size(compr_mode_type::deflate));
            auto size = relin_keys.save(temp.data(), temp.size(), compr_mode_type::deflate);
            auto relin_keys_data = fbs_builder.CreateVector(reinterpret_cast<uint8_t*>(temp.data()), size);
            query_request.add_relin_keys(relin_keys_data);

            // This is a little tricky; each QueryRequestPart consists of an exponent and a vector of Ciphertexts. For
            // convenience, we create vectors in immediately-invoked lambdas and pass them to the CreateVector function.
            // In the outer lambda, we populate a vector of QueryRequestParts, creating a new builder class for each of
            // them. In the inner lambda we build the QueryRequestPart data by creating multiple Ciphertexts.
            auto query_request_parts = fbs_builder.CreateVector([&]() {
                // The QueryRequestPart vector is populated with an immediately-invoked lambda
                vector<flatbuffers::Offset<fbs::QueryRequestPart>> ret;
                for (const auto &q : data)
                {
                    // For each exponent, create a QueryRequestPart with a builder instance
                    fbs::QueryRequestPartBuilder query_req_part_builder(fbs_builder);

                    // First add the exponent
                    query_req_part_builder.add_exponent(q.first);

                    // Then add a vector of Ciphertexts
                    auto cts = fbs_builder.CreateVector([&]() {
                        // The Ciphertext vector is populated with an immediately-invoked lambda
                        vector<flatbuffers::Offset<fbs::Ciphertext>> ret_inner;
                        for (const auto &ct : q.second)
                        {
                            // Save each SEALObject<seal::Ciphertext>
                            temp.resize(ct.save_size(compr_mode_type::deflate));
                            size = ct.save(temp.data(), temp.size(), compr_mode_type::deflate);
                            auto ct_data = fbs_builder.CreateVector(reinterpret_cast<uint8_t*>(temp.data()), size);

                            // Add to the Ciphertext vector
                            ret_inner.push_back(fbs::CreateCiphertext(fbs_builder, ct_data));
                        }
                        return ret_inner;
                    }());

                    // Add the Ciphertexts to the QueryRequestPart
                    query_req_part_builder.add_cts(cts);
                    
                    // Finish the QueryRequestPart and add to QueryRequestPart vector
                    ret.push_back(query_req_part_builder.Finish());
                }
                return ret;
            }());

            // Add the QueryRequestParts to QueryRequest
            query_request.add_query(query_request_parts);

            // Finish the QueryRequest and add to SenderOperation
            auto req = query_request.Finish();
            sop_builder.add_request(req.Union());

            // Finish everything 
            auto sop = sop_builder.Finish();
            fbs_builder.FinishSizePrefixed(sop);

            out.write(
                reinterpret_cast<const char*>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t SenderOperationQuery::load(istream &in, shared_ptr<SEALContext> context)
        {
            // The context must be set and valid for this operation
            if (!context)
            {
                throw invalid_argument("context cannot be null");
            }
            if (!context->parameters_set())
            {
                throw invalid_argument("context is invalid");
            }

            // Clear the current data
            data.clear();

            vector<SEAL_BYTE> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(reinterpret_cast<const uint8_t*>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderOperationBuffer(verifier);
            if (!safe)
            {
                throw runtime_error("failed to load SenderOperation: invalid buffer");
            }

            auto sop = fbs::GetSizePrefixedSenderOperation(in_data.data());

            // Need to check that the operation is of the right type
            if (sop->request_type() != fbs::Request_QueryRequest)
            {
                throw runtime_error("unexpected operation type");
            }

            const auto &req = *sop->request_as_QueryRequest();

            // Load relin_keys
            const auto &relin_keys_data = *req.relin_keys();
            try
            {
                relin_keys.load(
                    context,
                    reinterpret_cast<const SEAL_BYTE*>(relin_keys_data.data()), relin_keys_data.size());
            }
            catch (const logic_error &ex)
            {
                stringstream ss;
                ss << "failed to load relinearization keys: ";
                ss << ex.what();
                throw runtime_error(ss.str());
            }
            catch (const runtime_error &ex)
            {
                stringstream ss;
                ss << "failed to load relinearization keys: ";
                ss << ex.what();
                throw runtime_error(ss.str());
            }

            // Load the query data
            auto &query = *req.query();
            for (const auto &query_part : query)
            {
                uint32_t exponent = query_part->exponent();
                if (data.count(exponent))
                {
                    throw runtime_error("invalid query data");
                }

                const auto &cts = *query_part->cts();
                vector<SEALObject<Ciphertext>> cts_vec;
                cts_vec.reserve(cts.size());
                for (const auto &ct : cts)
                {
                    Ciphertext temp(context);
                    try
                    {
                        temp.load(
                            context,
                            reinterpret_cast<const SEAL_BYTE*>(ct->data()->data()), ct->data()->size());
                    }
                    catch (const logic_error &ex)
                    {
                        stringstream ss;
                        ss << "failed to load query ciphertext: ";
                        ss << ex.what();
                        throw runtime_error(ss.str());
                    }
                    catch (const runtime_error &ex)
                    {
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
    }
}
