// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <algorithm>
#include <map>
#include <seal/ciphertext.h>
#include <seal/publickey.h>
#include <seal/relinkeys.h>
#include <vector>

namespace apsi
{
    namespace network
    {
        enum SenderOperationType
        {
            SOP_get_parameters = 1,
            SOP_preprocess = 2,
            SOP_query = 3
        }; // enum SenderOperationType

        /**
        Generic Sender Operation
        */
        class SenderOperation
        {
        public:
            SenderOperation() = delete;
            SenderOperation(SenderOperationType type) : type(type)
            {}
            SenderOperation(SenderOperationType type, std::vector<seal::SEAL_BYTE> &&clt_id)
                : type(type), client_id(clt_id)
            {}

            virtual ~SenderOperation() = default;

            /**
            Operation type
            */
            SenderOperationType type;

            /**
            Client ID
            */
            std::vector<seal::SEAL_BYTE> client_id;
        }; // class SenderOperation

        /**
        Sender Operation: Get Parameters
        */
        class SenderOperationGetParameters : public SenderOperation
        {
        public:
            SenderOperationGetParameters() : SenderOperation(SOP_get_parameters)
            {}
            SenderOperationGetParameters(std::vector<seal::SEAL_BYTE> &&client_id)
                : SenderOperation(SOP_get_parameters, std::move(client_id))
            {}

            virtual ~SenderOperationGetParameters() = default;
        }; // class SenderOperationGetParameters

        /**
        Sender Operation: Preprocess
        */
        class SenderOperationPreprocess : public SenderOperation
        {
        public:
            SenderOperationPreprocess() = delete;
            SenderOperationPreprocess(std::vector<seal::SEAL_BYTE> &&buff)
                : SenderOperation(SOP_preprocess), buffer(buff)
            {}
            SenderOperationPreprocess(std::vector<seal::SEAL_BYTE> &&client_id, std::vector<seal::SEAL_BYTE> &&buff)
                : SenderOperation(SOP_preprocess, std::move(client_id)), buffer(buff)
            {}

            virtual ~SenderOperationPreprocess() = default;

            /**
            Items to preprocess
            */
            std::vector<seal::SEAL_BYTE> buffer;
        }; // class SenderOperationPreprocess

        /**
        Sender Operation: Query
        */
        class SenderOperationQuery : public SenderOperation
        {
        public:
            SenderOperationQuery() = delete;
            SenderOperationQuery(const std::string &relin, std::map<std::uint64_t, std::vector<std::string>> &&queryp)
                : SenderOperation(SOP_query), relin_keys(relin), query(std::move(queryp))
            {}

            SenderOperationQuery(
                std::vector<seal::SEAL_BYTE> &&client_id, const std::string &relin,
                std::map<std::uint64_t, std::vector<std::string>> &&queryp)
                : SenderOperation(SOP_query, std::move(client_id)), relin_keys(relin), query(std::move(queryp))
            {}

            virtual ~SenderOperationQuery() = default;

            // std::string public_key;
            std::string relin_keys;
            std::map<std::uint64_t, std::vector<std::string>> query;
        }; // class SenderOperationQuery
    }      // namespace network
} // namespace apsi
