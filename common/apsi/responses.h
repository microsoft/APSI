// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <utility>

// APSI
#include "apsi/network/sender_operation_response.h"
#include "apsi/util/utils.h"

namespace apsi {
    /**
    A type representing a response to any response.
    */
    using Response = std::unique_ptr<network::SenderOperationResponse>;

    /**
    A type representing a response to a parameter response.
    */
    using ParamsResponse = std::unique_ptr<network::SenderOperationResponseParms>;

    /**
    A type representing a response to an OPRF response.
    */
    using OPRFResponse = std::unique_ptr<network::SenderOperationResponseOPRF>;

    /**
    A type representing a response to a query response.
    */
    using QueryResponse = std::unique_ptr<network::SenderOperationResponseQuery>;

    inline ParamsResponse to_params_response(Response &response)
    {
        if (nullptr == response ||
            response->type() != apsi::network::SenderOperationType::sop_parms)
            return nullptr;
        return ParamsResponse(
            static_cast<apsi::network::SenderOperationResponseParms *>(response.release()));
    }

    inline ParamsResponse to_params_response(Response &&response)
    {
        if (nullptr == response ||
            response->type() != apsi::network::SenderOperationType::sop_parms)
            return nullptr;
        return ParamsResponse(
            static_cast<apsi::network::SenderOperationResponseParms *>(response.release()));
    }

    inline OPRFResponse to_oprf_response(Response &response)
    {
        if (nullptr == response || response->type() != apsi::network::SenderOperationType::sop_oprf)
            return nullptr;
        return OPRFResponse(
            static_cast<apsi::network::SenderOperationResponseOPRF *>(response.release()));
    }

    inline OPRFResponse to_oprf_response(Response &&response)
    {
        if (nullptr == response || response->type() != apsi::network::SenderOperationType::sop_oprf)
            return nullptr;
        return OPRFResponse(
            static_cast<apsi::network::SenderOperationResponseOPRF *>(response.release()));
    }

    inline QueryResponse to_query_response(Response &response)
    {
        if (nullptr == response ||
            response->type() != apsi::network::SenderOperationType::sop_query)
            return nullptr;
        return QueryResponse(
            static_cast<apsi::network::SenderOperationResponseQuery *>(response.release()));
    }

    inline QueryResponse to_query_response(Response &&response)
    {
        if (nullptr == response ||
            response->type() != apsi::network::SenderOperationType::sop_query)
            return nullptr;
        return QueryResponse(
            static_cast<apsi::network::SenderOperationResponseQuery *>(response.release()));
    }

    inline Response to_response(ParamsResponse &params_response)
    {
        return Response(params_response.release());
    }

    inline Response to_response(ParamsResponse &&params_response)
    {
        return Response(params_response.release());
    }

    inline Response to_response(OPRFResponse &oprf_response)
    {
        return Response(oprf_response.release());
    }

    inline Response to_response(OPRFResponse &&oprf_response)
    {
        return Response(oprf_response.release());
    }

    inline Response to_response(QueryResponse &query_response)
    {
        return Response(query_response.release());
    }

    inline Response to_response(QueryResponse &&query_response)
    {
        return Response(query_response.release());
    }

    /**
    A type representing a partial query result.
    */
    using ResultPart = std::unique_ptr<network::ResultPackage>;
} // namespace apsi
