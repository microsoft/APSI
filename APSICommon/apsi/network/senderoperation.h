// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <vector>
#include <map>
#include <algorithm>

// APSI
#include "apsi/apsidefines.h"

// SEAL
#include "seal/publickey.h"
#include "seal/relinkeys.h"
#include "seal/ciphertext.h"


namespace apsi
{
    namespace network
    {
        enum SenderOperationType
        {
            SOP_get_parameters = 1,
            SOP_preprocess = 2,
            SOP_query = 3
        };

        /**
        Generic Sender Operation
        */
        class SenderOperation
        {
        public:
            SenderOperation() = delete;
            SenderOperation(SenderOperationType type)
                : type(type)
            {}
            SenderOperation(SenderOperationType type, std::vector<apsi::u8>&& clt_id)
                : type(type),
                  client_id(clt_id)
            {}

            virtual ~SenderOperation() = default;

            /**
            Operation type
            */
            SenderOperationType type;

            /**
            Client ID
            */
            std::vector<apsi::u8> client_id;
        };

        /**
        Sender Operation: Get Parameters
        */
        class SenderOperationGetParameters : public SenderOperation
        {
        public:
            SenderOperationGetParameters()
                : SenderOperation(SOP_get_parameters)
            {}
            SenderOperationGetParameters(std::vector<apsi::u8>&& client_id)
                : SenderOperation(SOP_get_parameters, std::move(client_id))
            {}

            virtual ~SenderOperationGetParameters() = default;
        };

        /**
        Sender Operation: Preprocess
        */
        class SenderOperationPreprocess : public SenderOperation
        {
        public:
            SenderOperationPreprocess() = delete;
            SenderOperationPreprocess(std::vector<apsi::u8>&& buff)
                : SenderOperation(SOP_preprocess),
                  buffer(buff)
            {}
            SenderOperationPreprocess(std::vector<apsi::u8>&& client_id, std::vector<apsi::u8>&& buff)
                : SenderOperation(SOP_preprocess, std::move(client_id)),
                  buffer(buff)
            {}

            virtual ~SenderOperationPreprocess() = default;

            /**
            Items to preprocess
            */
            std::vector<apsi::u8> buffer;
        };

        /**
        Sender Operation: Query
        */
        class SenderOperationQuery : public SenderOperation
        {
        public:
            SenderOperationQuery() = delete;
            SenderOperationQuery(const std::string& relin, std::map<apsi::u64, std::vector<std::string>>&& queryp)
                : SenderOperation(SOP_query),
                  relin_keys(relin),
                  query(std::move(queryp))
            {}

            SenderOperationQuery(std::vector<apsi::u8>&& client_id, const std::string& relin, std::map<apsi::u64, std::vector<std::string>>&& queryp)
                : SenderOperation(SOP_query, std::move(client_id)),
                  relin_keys(relin),
                  query(std::move(queryp))
            {}

            virtual ~SenderOperationQuery() = default;

            // std::string public_key;
            std::string relin_keys;
            std::map<apsi::u64, std::vector<std::string>> query;
        };
    }
}
