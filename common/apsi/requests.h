// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <utility>

// APSI
#include "apsi/network/sender_operation.h"
#include "apsi/util/utils.h"

namespace apsi {
    /**
    A type representing a parameter, an OPRF, or a query request message to be sent.
    */
    using Request = std::unique_ptr<network::SenderOperation>;

    /**
    A type representing a request to a parameter request.
    */
    using ParamsRequest = std::unique_ptr<network::SenderOperationParms>;

    /**
    A type representing a request to an OPRF request.
    */
    using OPRFRequest = std::unique_ptr<network::SenderOperationOPRF>;

    /**
    A type representing a request to a query request.
    */
    using QueryRequest = std::unique_ptr<network::SenderOperationQuery>;

    inline ParamsRequest to_params_request(Request &request)
    {
        if (request == nullptr || request->type() != apsi::network::SenderOperationType::sop_parms)
            return nullptr;
        return ParamsRequest(static_cast<apsi::network::SenderOperationParms *>(request.release()));
    }

    inline ParamsRequest to_params_request(Request &&request)
    {
        if (request == nullptr || request->type() != apsi::network::SenderOperationType::sop_parms)
            return nullptr;
        return ParamsRequest(static_cast<apsi::network::SenderOperationParms *>(request.release()));
    }

    inline OPRFRequest to_oprf_request(Request &request)
    {
        if (request == nullptr || request->type() != apsi::network::SenderOperationType::sop_oprf)
            return nullptr;
        return OPRFRequest(static_cast<apsi::network::SenderOperationOPRF *>(request.release()));
    }

    inline OPRFRequest to_oprf_request(Request &&request)
    {
        if (request == nullptr || request->type() != apsi::network::SenderOperationType::sop_oprf)
            return nullptr;
        return OPRFRequest(static_cast<apsi::network::SenderOperationOPRF *>(request.release()));
    }

    inline QueryRequest to_query_request(Request &request)
    {
        if (request == nullptr || request->type() != apsi::network::SenderOperationType::sop_query)
            return nullptr;
        return QueryRequest(static_cast<apsi::network::SenderOperationQuery *>(request.release()));
    }

    inline QueryRequest to_query_request(Request &&request)
    {
        if (request == nullptr || request->type() != apsi::network::SenderOperationType::sop_query)
            return nullptr;
        return QueryRequest(static_cast<apsi::network::SenderOperationQuery *>(request.release()));
    }

    inline Request to_request(ParamsRequest &params_request)
    {
        return Request(params_request.release());
    }

    inline Request to_request(ParamsRequest &&params_request)
    {
        return Request(params_request.release());
    }

    inline Request to_request(OPRFRequest &oprf_request)
    {
        return Request(oprf_request.release());
    }

    inline Request to_request(OPRFRequest &&oprf_request)
    {
        return Request(oprf_request.release());
    }

    inline Request to_request(QueryRequest &query_request)
    {
        return Request(query_request.release());
    }

    inline Request to_request(QueryRequest &&query_request)
    {
        return Request(query_request.release());
    }
} // namespace apsi
