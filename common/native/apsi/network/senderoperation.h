// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <string>
#include <map>
#include <vector>
#include <utility>

// SEAL
#include <seal/util/defines.h>


namespace apsi
{
    namespace network
    {
        enum class SenderOperationType : std::uint32_t
        {
            // Receiver sent a request for PSI parameters
            SOP_PARMS = 1,

            // Receiver sent an OPRF query
            SOP_OPRF = 2,

            // Receiver sent an encrypted APSI query
            SOP_QUERY = 3
        }; // enum class SenderOperationType

        /**
        An abstract base class representing a Sender operation. This class holds two member
        variables representing the type of the operation and a client ID.
        */
        class SenderOperation
        {
        public:
            SenderOperation() = delete;

            /**
            Creates a SenderOperation of a given type.
            */
            SenderOperation(SenderOperationType type) : type(type)
            {}

            /**
            Create a SenderOperation of a given type with and given client ID.
            */
            SenderOperation(SenderOperationType type, std::vector<seal::SEAL_BYTE> client_id)
                : type(type), client_id(client_id)
            {}

            /**
            Destroys the SenderOperation.
            */
            virtual ~SenderOperation() = default;

            /**
            Holds the type of this SenderOperation.
            */
            SenderOperationType type;

            /**
            Holds the client ID of this SenderOperation.
            */
            std::vector<seal::SEAL_BYTE> client_id;
        }; // class SenderOperation

        /**
        A kind of SenderOperation for representing a parameter request from the receiver.
        */
        class SenderOperationParms : public SenderOperation
        {
        public:
            SenderOperationParms() : SenderOperation(SenderOperationType::SOP_PARMS)
            {}

            SenderOperationParms(std::vector<seal::SEAL_BYTE> client_id)
                : SenderOperation(SenderOperationType::SOP_PARMS, std::move(client_id))
            {}

            virtual ~SenderOperationParms() = default;
        }; // class SenderOperationParms

        /**
        A kind of SenderOperation for representing an OPRF query from the receiver.
        */
        class SenderOperationOPRF : public SenderOperation
        {
        public:
            SenderOperationOPRF(std::vector<seal::SEAL_BYTE> &&data)
                : SenderOperation(SenderOperationType::SOP_OPRF), data(std::move(data))
            {}

            SenderOperationOPRF(std::vector<seal::SEAL_BYTE> client_id, std::vector<seal::SEAL_BYTE> data)
                : SenderOperation(SenderOperationType::SOP_OPRF, std::move(client_id)), data(std::move(data))
            {}

            virtual ~SenderOperationOPRF() = default;

            /**
            Holds the OPRF query data.
            */
            std::vector<seal::SEAL_BYTE> data;
        }; // class SenderOperationOPRF

        /**
        A kind of SenderOperation for representing a PSI or labeled PSI query from the receiver.
        */
        class SenderOperationQuery : public SenderOperation
        {
        public:
            SenderOperationQuery(std::string relin_keys,
                std::map<std::uint64_t, std::vector<std::string>> data) :
                SenderOperation(SenderOperationType::SOP_QUERY),
                relin_keys(std::move(relin_keys)),
                data(std::move(data))
            {}

            SenderOperationQuery(
                std::vector<seal::SEAL_BYTE> client_id, std::string relin_keys,
                std::map<std::uint64_t, std::vector<std::string>> data) :
                SenderOperation(SenderOperationType::SOP_QUERY, std::move(client_id)),
                relin_keys(std::move(relin_keys)),
                data(std::move(data))
            {}

            virtual ~SenderOperationQuery() = default;

            std::string relin_keys;

            /**
            Holds the encrypted query data. In the map the key labels the power of the query
            ciphertext and the vector holds the ciphertext strings for different bundle indices.
            */
            std::map<std::uint64_t, std::vector<std::string>> data;
        }; // class SenderOperationQuery
    }      // namespace network
} // namespace apsi
