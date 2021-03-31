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
        return util::unique_ptr_cast<network::SenderOperationParms, network::SenderOperation>(
            request);
    }

    inline ParamsRequest to_params_request(Request &&request)
    {
        return util::unique_ptr_cast<network::SenderOperationParms, network::SenderOperation>(
            std::move(request));
    }

    inline OPRFRequest to_oprf_request(Request &request)
    {
        return util::unique_ptr_cast<network::SenderOperationOPRF, network::SenderOperation>(
            request);
    }

    inline OPRFRequest to_oprf_request(Request &&request)
    {
        return util::unique_ptr_cast<network::SenderOperationOPRF, network::SenderOperation>(
            std::move(request));
    }

    inline QueryRequest to_query_request(Request &request)
    {
        return util::unique_ptr_cast<network::SenderOperationQuery, network::SenderOperation>(
            request);
    }

    inline QueryRequest to_query_request(Request &&request)
    {
        return util::unique_ptr_cast<network::SenderOperationQuery, network::SenderOperation>(
            std::move(request));
    }

    inline Request to_request(ParamsRequest &params_request)
    {
        return util::unique_ptr_cast<network::SenderOperation, network::SenderOperationParms>(
            params_request);
    }

    inline Request to_request(ParamsRequest &&params_request)
    {
        return util::unique_ptr_cast<network::SenderOperation, network::SenderOperationParms>(
            std::move(params_request));
    }

    inline Request to_request(OPRFRequest &oprf_request)
    {
        return util::unique_ptr_cast<network::SenderOperation, network::SenderOperationOPRF>(
            oprf_request);
    }

    inline Request to_request(OPRFRequest &&oprf_request)
    {
        return util::unique_ptr_cast<network::SenderOperation, network::SenderOperationOPRF>(
            std::move(oprf_request));
    }

    inline Request to_request(QueryRequest &query_request)
    {
        return util::unique_ptr_cast<network::SenderOperation, network::SenderOperationQuery>(
            query_request);
    }

    inline Request to_request(QueryRequest &&query_request)
    {
        return util::unique_ptr_cast<network::SenderOperation, network::SenderOperationQuery>(
            std::move(query_request));
    }
} // namespace apsi
