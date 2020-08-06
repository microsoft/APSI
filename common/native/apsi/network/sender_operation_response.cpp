// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstring>
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

namespace apsi
{
    namespace network
    {
        size_t SenderOperationResponseParms::save(ostream &out) const
        {
            if (!params)
            {
                logic_error("parameters are not set");
            }

            flatbuffers::FlatBufferBuilder fbs_builder(128);
            fbs::SenderOperationResponseBuilder sop_response_builder(fbs_builder);

            sop_response_builder.add_response_type(fbs::Response_ParmsResponse);
            fbs::ParmsResponseBuilder parms_response(fbs_builder);

            // Save the parameters into a temporary string
            stringstream ss;
            auto size = SaveParams(*params, ss);
            string params_str = ss.str();

            // Set up a vector to hold the parameter data
            auto params_data = fbs_builder.CreateVector(
                reinterpret_cast<uint8_t*>(params_str.data()), params_str.size());
            parms_response.add_data(params_data);

            auto resp = parms_response.Finish();
            sop_response_builder.add_response(resp.Union());

            auto sop_response = sop_response_builder.Finish();
            fbs_builder.FinishSizePrefixed(sop_response);

            out.write(
                reinterpret_cast<const char*>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t SenderOperationResponseParms::load(istream &in)
        {
            // Release the current parameters
            params.reset();

            vector<SEAL_BYTE> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(reinterpret_cast<const uint8_t*>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderOperationResponseBuffer(verifier);
            if (!safe)
            {
                throw runtime_error("failed to load SenderOperationResponse: invalid buffer");
            }

            auto sop_response = fbs::GetSizePrefixedSenderOperationResponse(in_data.data());

            // Need to check that the operation is of the right type
            if (sop_response->response_type() != fbs::Response_ParmsResponse)
            {
                throw runtime_error("unexpected operation type");
            }

            // Load the PSIParams response 
            const auto &params_data = *sop_response->response_as_ParmsResponse()->data();
            ArrayGetBuffer agbuf(
                reinterpret_cast<const char *>(params_data.data()),
                static_cast<streamsize>(params_data.size()));
            istream params_stream(&agbuf);
            params = make_unique<PSIParams>(LoadParams(params_stream).first);

            return in_data.size();
        }

        size_t SenderOperationResponseOPRF::save(ostream &out) const
        {
            if (data.empty())
            {
                logic_error("OPRF response data is not set");
            }

            flatbuffers::FlatBufferBuilder fbs_builder(1024);
            fbs::SenderOperationResponseBuilder sop_response_builder(fbs_builder);

            sop_response_builder.add_response_type(fbs::Response_OPRFResponse);
            fbs::OPRFResponseBuilder oprf_response(fbs_builder);

            // Set up a vector to hold the response data
            auto oprf_data = fbs_builder.CreateVector(reinterpret_cast<const uint8_t*>(data.data()), data.size());
            oprf_response.add_data(oprf_data);

            auto resp = oprf_response.Finish();
            sop_response_builder.add_response(resp.Union());

            auto sop_response = sop_response_builder.Finish();
            fbs_builder.FinishSizePrefixed(sop_response);

            out.write(
                reinterpret_cast<const char*>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t SenderOperationResponseOPRF::load(istream &in)
        {
            // Clear the current data
            data.clear();

            vector<SEAL_BYTE> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(reinterpret_cast<const uint8_t*>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderOperationResponseBuffer(verifier);
            if (!safe)
            {
                throw runtime_error("failed to load SenderOperationResponse: invalid buffer");
            }

            auto sop_response = fbs::GetSizePrefixedSenderOperationResponse(in_data.data());

            // Need to check that the operation is of the right type
            if (sop_response->response_type() != fbs::Response_OPRFResponse)
            {
                throw runtime_error("unexpected operation type");
            }

            // Load the OPRF response 
            const auto &oprf_data = *sop_response->response_as_OPRFResponse()->data();
            data.resize(oprf_data.size());
            memcpy(data.data(), oprf_data.data(), oprf_data.size());

            return in_data.size();
        }

        size_t SenderOperationResponseQuery::save(ostream &out) const
        {
            flatbuffers::FlatBufferBuilder fbs_builder(128);
            fbs::SenderOperationResponseBuilder sop_response_builder(fbs_builder);

            sop_response_builder.add_response_type(fbs::Response_QueryResponse);
            auto resp = fbs::CreateQueryResponse(fbs_builder, package_count);
            sop_response_builder.add_response(resp.Union());

            auto sop_response = sop_response_builder.Finish();
            fbs_builder.FinishSizePrefixed(sop_response);

            out.write(
                reinterpret_cast<const char*>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t SenderOperationResponseQuery::load(istream &in)
        {
            vector<SEAL_BYTE> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(reinterpret_cast<const uint8_t*>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderOperationResponseBuffer(verifier);
            if (!safe)
            {
                throw runtime_error("failed to load SenderOperationResponse: invalid buffer");
            }

            auto sop_response = fbs::GetSizePrefixedSenderOperationResponse(in_data.data());

            // Need to check that the operation is of the right type
            if (sop_response->response_type() != fbs::Response_QueryResponse)
            {
                throw runtime_error("unexpected operation type");
            }

            // Load the query response 
            package_count = sop_response->response_as_QueryResponse()->package_count();

            return in_data.size();
        }
    }
}
