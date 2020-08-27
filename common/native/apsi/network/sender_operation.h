// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <unordered_map>
#include <iostream>
#include <vector>
#include <utility>
#include <memory>

// APSI
#include "apsi/sealobject.h"
#include "apsi/version.h"
#include "apsi/powers.h"

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

            std::uint32_t version = apsi_version;

            SenderOperationType type = SenderOperationType::SOP_UNKNOWN;
        };

        /**
        An abstract base class representing a sender operation.
        */
        class SenderOperation
        {
        public:
            SenderOperation() = default;

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
        }; // class SenderOperation

        /**
        A kind of SenderOperation for representing a parameter request from the receiver.
        */
        class SenderOperationParms final : public SenderOperation
        {
        public:
            std::size_t save(std::ostream &out) const override;

            std::size_t load(std::istream &in, std::shared_ptr<seal::SEALContext> context = nullptr) override;

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
            std::size_t save(std::ostream &out) const override;

            std::size_t load(std::istream &in, std::shared_ptr<seal::SEALContext> context = nullptr) override;

            SenderOperationType type() const noexcept override
            {
                return SenderOperationType::SOP_OPRF;
            }

            /**
            Holds the OPRF query data.
            */
            std::vector<seal::seal_byte> data;
        }; // class SenderOperationOPRF

        /**
        A kind of SenderOperation for representing a PSI or labeled PSI query from the receiver.
        */
        class SenderOperationQuery final : public SenderOperation
        {
        public:
            std::size_t save(std::ostream &out) const override;

            std::size_t load(std::istream &in, std::shared_ptr<seal::SEALContext> context) override;

            SenderOperationType type() const noexcept override
            {
                return SenderOperationType::SOP_QUERY;
            }

            SEALObject<seal::RelinKeys> relin_keys;

            /**
            Holds the encrypted query data. In the map the key labels the exponent of the query
            ciphertext and the vector holds the ciphertext data for different bundle indices.
            */
            std::unordered_map<std::uint32_t, std::vector<SEALObject<seal::Ciphertext>>> data;

            /**
            Holds the execution graph for computing all powers from what is sent in the data field.
            */
            PowersDag pd;
        }; // class SenderOperationQuery
    }      // namespace network
} // namespace apsi
