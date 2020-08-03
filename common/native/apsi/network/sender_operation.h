// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <map>
#include <iostream>
#include <vector>
#include <utility>
#include <memory>

// APSI
#include "apsi/sealobject.h"

// SEAL
#include "seal/util/defines.h"
#include "seal/util/common.h"
#include "seal/relinkeys.h"
#include "seal/ciphertext.h"

namespace apsi
{
    namespace network
    {
        enum class SenderOperationType : std::uint32_t
        {
            SOP_UNKNOWN = 0,

            SOP_PARMS = 1,

            SOP_OPRF = 2,

            SOP_QUERY = 3
        };

        /**
        A class describing the type of a SenderOperation object and an optional member to identify the client.
        */
        class SenderOperationHeader
        {
        public:
            std::size_t save(std::ostream &out) const;

            std::size_t load(std::istream &in);

            std::vector<seal::SEAL_BYTE> client_id = {};

            SenderOperationType type = SenderOperationType::SOP_UNKNOWN;
        };

        /**
        An abstract base class representing a sender operation. This class optionally holds an optional member
        variable identifying the client (client_id).
        */
        class SenderOperation
        {
        public:
            SenderOperation() = default;

            SenderOperation(std::vector<seal::SEAL_BYTE> client_id) : client_id(std::move(client_id))
            {}

            /**
            Destroys the SenderOperation.
            */
            virtual ~SenderOperation() = default;

            /**
            Writes the SenderOperation to a stream.
            */
            virtual std::size_t save(std::ostream &out) const = 0;

            /**
            Reads the SenderOperation from a stream.
            */
            virtual std::size_t load(std::istream &in, std::shared_ptr<seal::SEALContext> context = nullptr) = 0;

            /**
            Returns the type of the SenderOperation.
            */
            virtual SenderOperationType type() const noexcept = 0;

            std::vector<seal::SEAL_BYTE> client_id;
        }; // class SenderOperation

        /**
        A kind of SenderOperation for representing a parameter request from the receiver.
        */
        class SenderOperationParms final : public SenderOperation
        {
        public:
            SenderOperationParms(std::vector<seal::SEAL_BYTE> client_id) : SenderOperation(std::move(client_id))
            {}

            SenderOperationParms() = default;

            ~SenderOperationParms() = default;

            std::size_t save(std::ostream &out) const override;

            std::size_t load(std::istream &in, std::shared_ptr<seal::SEALContext> context) override;

            SenderOperationType type() const noexcept override
            {
                return SenderOperationType::SOP_PARMS;
            }
        }; // class SenderOperationParms

        /**
        A kind of SenderOperation for representing an OPRF query from the receiver.
        */
        class SenderOperationOPRF final : public SenderOperation
        {
        public:
            SenderOperationOPRF(std::vector<seal::SEAL_BYTE> data) : data(std::move(data)), SenderOperation()
            {}

            SenderOperationOPRF(std::vector<seal::SEAL_BYTE> data, std::vector<seal::SEAL_BYTE> client_id) :
                data(std::move(data)), SenderOperation(std::move(client_id))
            {}

            ~SenderOperationOPRF() = default;

            std::size_t save(std::ostream &out) const override;

            std::size_t load(std::istream &in, std::shared_ptr<seal::SEALContext> context) override;

            SenderOperationType type() const noexcept override
            {
                return SenderOperationType::SOP_OPRF;
            }

            /**
            Holds the OPRF query data.
            */
            std::vector<seal::SEAL_BYTE> data;
        }; // class SenderOperationOPRF

        /**
        A kind of SenderOperation for representing a PSI or labeled PSI query from the receiver.
        */
        class SenderOperationQuery final : public SenderOperation
        {
        public:
            SenderOperationQuery(
                SEALObject<seal::RelinKeys> relin_keys,
                std::map<std::uint64_t, std::vector<SEALObject<seal::Ciphertext>>> data) :
                relin_keys(std::move(relin_keys)),
                data(std::move(data)),
                SenderOperation()
            {}

            SenderOperationQuery(
                SEALObject<seal::RelinKeys> relin_keys,
                std::map<std::uint64_t, std::vector<SEALObject<seal::Ciphertext>>> data,
                std::vector<seal::SEAL_BYTE> client_id) :
                relin_keys(std::move(relin_keys)),
                data(std::move(data)),
                SenderOperation(std::move(client_id))
            {}

            ~SenderOperationQuery() = default;

            std::size_t save(std::ostream &out) const override;

            std::size_t load(std::istream &in, std::shared_ptr<seal::SEALContext> context) override;

            SenderOperationType type() const noexcept override
            {
                return SenderOperationType::SOP_QUERY;
            }

            SEALObject<seal::RelinKeys> relin_keys;

            /**
            Holds the encrypted query data. In the map the key labels the power of the query
            ciphertext and the vector holds the ciphertext data for different bundle indices.
            */
            std::map<std::uint64_t, std::vector<SEALObject<seal::Ciphertext>>> data;
        }; // class SenderOperationQuery
    }      // namespace network
} // namespace apsi
