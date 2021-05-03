// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <iterator>
#include <sstream>
#include <stdexcept>

// APSI
#include "apsi/network/sender_operation_response.h"
#include "apsi/network/sop_response_generated.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/common.h"
#include "seal/util/streambuf.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi {
    using namespace util;

    namespace network {
        size_t SenderOperationResponseParms::save(ostream &out) const
        {
            if (!params) {
                throw logic_error("parameters are not set");
            }

            flatbuffers::FlatBufferBuilder fbs_builder(128);

            // Save the parameters into a temporary string
            stringstream ss;
            params->save(ss);
            string params_str = ss.str();

            // Set up a vector to hold the parameter data
            auto params_data = fbs_builder.CreateVector(
                reinterpret_cast<const uint8_t *>(&params_str[0]), params_str.size());

            auto resp = fbs::CreateParmsResponse(fbs_builder, params_data);

            fbs::SenderOperationResponseBuilder sop_response_builder(fbs_builder);
            sop_response_builder.add_response_type(fbs::Response_ParmsResponse);
            sop_response_builder.add_response(resp.Union());
            auto sop_response = sop_response_builder.Finish();
            fbs_builder.FinishSizePrefixed(sop_response);

            out.write(
                reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t SenderOperationResponseParms::load(istream &in)
        {
            // Release the current parameters
            params.reset();

            vector<unsigned char> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(
                reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderOperationResponseBuffer(verifier);
            if (!safe) {
                throw runtime_error("failed to load SenderOperationResponse: invalid buffer");
            }

            auto sop_response = fbs::GetSizePrefixedSenderOperationResponse(in_data.data());

            // Need to check that the operation is of the right type
            if (sop_response->response_type() != fbs::Response_ParmsResponse) {
                throw runtime_error("unexpected operation type");
            }

            // Load the PSIParams response
            const auto &params_data = *sop_response->response_as_ParmsResponse()->data();
            ArrayGetBuffer agbuf(
                reinterpret_cast<const char *>(params_data.data()),
                static_cast<streamsize>(params_data.size()));
            istream params_stream(&agbuf);
            params = make_unique<PSIParams>(PSIParams::Load(params_stream).first);

            return in_data.size();
        }

        size_t SenderOperationResponseOPRF::save(ostream &out) const
        {
            flatbuffers::FlatBufferBuilder fbs_builder(1024);

            // Set up a vector to hold the response data
            auto oprf_data = fbs_builder.CreateVector(
                reinterpret_cast<const uint8_t *>(data.data()), data.size());
            auto resp = fbs::CreateOPRFResponse(fbs_builder, oprf_data);

            fbs::SenderOperationResponseBuilder sop_response_builder(fbs_builder);
            sop_response_builder.add_response_type(fbs::Response_OPRFResponse);
            sop_response_builder.add_response(resp.Union());
            auto sop_response = sop_response_builder.Finish();
            fbs_builder.FinishSizePrefixed(sop_response);

            out.write(
                reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t SenderOperationResponseOPRF::load(istream &in)
        {
            // Clear the current data
            data.clear();

            vector<unsigned char> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(
                reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderOperationResponseBuffer(verifier);
            if (!safe) {
                throw runtime_error("failed to load SenderOperationResponse: invalid buffer");
            }

            auto sop_response = fbs::GetSizePrefixedSenderOperationResponse(in_data.data());

            // Need to check that the operation is of the right type
            if (sop_response->response_type() != fbs::Response_OPRFResponse) {
                throw runtime_error("unexpected operation type");
            }

            // This will be non-null
            auto oprf_response = sop_response->response_as_OPRFResponse();

            // Load the OPRF response; this is a required field so we can always dereference
            const auto &oprf_data = *oprf_response->data();
            data.resize(oprf_data.size());
            copy_bytes(oprf_data.data(), oprf_data.size(), data.data());

            return in_data.size();
        }

        size_t SenderOperationResponseQuery::save(ostream &out) const
        {
            flatbuffers::FlatBufferBuilder fbs_builder(128);

            auto resp = fbs::CreateQueryResponse(fbs_builder, package_count);

            fbs::SenderOperationResponseBuilder sop_response_builder(fbs_builder);
            sop_response_builder.add_response_type(fbs::Response_QueryResponse);
            sop_response_builder.add_response(resp.Union());
            auto sop_response = sop_response_builder.Finish();
            fbs_builder.FinishSizePrefixed(sop_response);

            out.write(
                reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t SenderOperationResponseQuery::load(istream &in)
        {
            vector<unsigned char> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(
                reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderOperationResponseBuffer(verifier);
            if (!safe) {
                throw runtime_error("failed to load SenderOperationResponse: invalid buffer");
            }

            auto sop_response = fbs::GetSizePrefixedSenderOperationResponse(in_data.data());

            // Need to check that the operation is of the right type
            if (sop_response->response_type() != fbs::Response_QueryResponse) {
                throw runtime_error("unexpected operation type");
            }

            // Load the query response
            package_count = sop_response->response_as_QueryResponse()->package_count();

            return in_data.size();
        }
    } // namespace network
} // namespace apsi
