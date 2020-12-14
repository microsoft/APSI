// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <utility>

// APSI
#include "apsi/network/sender_operation_response.h"
#include "apsi/util/utils.h"

namespace apsi
{
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
        return util::unique_ptr_cast<network::SenderOperationResponseParms, network::SenderOperationResponse>(response);
    }

    inline ParamsResponse to_params_response(Response &&response)
    {
        return util::unique_ptr_cast<network::SenderOperationResponseParms, network::SenderOperationResponse>(std::move(response));
    }

    inline OPRFResponse to_oprf_response(Response &response)
    {
        return util::unique_ptr_cast<network::SenderOperationResponseOPRF, network::SenderOperationResponse>(response);
    }

    inline OPRFResponse to_oprf_response(Response &&response)
    {
        return util::unique_ptr_cast<network::SenderOperationResponseOPRF, network::SenderOperationResponse>(std::move(response));
    }

    inline QueryResponse to_query_response(Response &response)
    {
        return util::unique_ptr_cast<network::SenderOperationResponseQuery, network::SenderOperationResponse>(response);
    }

    inline QueryResponse to_query_response(Response &&response)
    {
        return util::unique_ptr_cast<network::SenderOperationResponseQuery, network::SenderOperationResponse>(std::move(response));
    }

    inline Response to_response(ParamsResponse &params_response)
    {
        return util::unique_ptr_cast<network::SenderOperationResponse, network::SenderOperationResponseParms>(params_response);
    }

    inline Response to_response(ParamsResponse &&params_response)
    {
        return util::unique_ptr_cast<network::SenderOperationResponse, network::SenderOperationResponseParms>(std::move(params_response));
    }

    inline Response to_response(OPRFResponse &oprf_response)
    {
        return util::unique_ptr_cast<network::SenderOperationResponse, network::SenderOperationResponseOPRF>(oprf_response);
    }

    inline Response to_response(OPRFResponse &&oprf_response)
    {
        return util::unique_ptr_cast<network::SenderOperationResponse, network::SenderOperationResponseOPRF>(std::move(oprf_response));
    }

    inline Response to_response(QueryResponse &query_response)
    {
        return util::unique_ptr_cast<network::SenderOperationResponse, network::SenderOperationResponseQuery>(query_response);
    }

    inline Response to_response(QueryResponse &&query_response)
    {
        return util::unique_ptr_cast<network::SenderOperationResponse, network::SenderOperationResponseQuery>(std::move(query_response));
    }

    /**
    A type representing a partial query result.
    */
    using ResultPart = std::unique_ptr<network::ResultPackage>;
}