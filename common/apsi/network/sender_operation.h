// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

// APSI
#include "apsi/seal_object.h"
#include "apsi/version.h"

// SEAL
#include "seal/ciphertext.h"
#include "seal/relinkeys.h"
#include "seal/util/common.h"

namespace apsi {
    namespace network {
        enum class SenderOperationType : std::uint32_t {
            sop_unknown = 0,

            sop_parms = 1,

            sop_oprf = 2,

            sop_query = 3
        };

        const char *sender_operation_type_str(SenderOperationType sop_type);

        /**
        A class describing the type of a SenderOperation object and an optional member to identify
        the client.
        */
        class SenderOperationHeader {
        public:
            std::size_t save(std::ostream &out) const;

            std::size_t load(std::istream &in);

            std::uint32_t version = apsi_serialization_version;

            SenderOperationType type = SenderOperationType::sop_unknown;
        };

        /**
        An abstract base class representing a sender operation.
        */
        class SenderOperation {
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
            virtual std::size_t load(
                std::istream &in, std::shared_ptr<seal::SEALContext> context = nullptr) = 0;

            /**
            Returns the type of the SenderOperation.
            */
            virtual SenderOperationType type() const noexcept = 0;
        }; // class SenderOperation

        /**
        A kind of SenderOperation for representing a parameter request from the receiver.
        */
        class SenderOperationParms final : public SenderOperation {
        public:
            std::size_t save(std::ostream &out) const override;

            std::size_t load(
                std::istream &in, std::shared_ptr<seal::SEALContext> context = nullptr) override;

            SenderOperationType type() const noexcept override
            {
                return SenderOperationType::sop_parms;
            }
        }; // class SenderOperationParms

        /**
        A kind of SenderOperation for representing an OPRF query from the receiver.
        */
        class SenderOperationOPRF final : public SenderOperation {
        public:
            std::size_t save(std::ostream &out) const override;

            std::size_t load(
                std::istream &in, std::shared_ptr<seal::SEALContext> context = nullptr) override;

            SenderOperationType type() const noexcept override
            {
                return SenderOperationType::sop_oprf;
            }

            /**
            Holds the OPRF query data.
            */
            std::vector<unsigned char> data;
        }; // class SenderOperationOPRF

        /**
        A kind of SenderOperation for representing a PSI or labeled PSI query from the receiver.
        */
        class SenderOperationQuery final : public SenderOperation {
        public:
            std::size_t save(std::ostream &out) const override;

            std::size_t load(std::istream &in, std::shared_ptr<seal::SEALContext> context) override;

            SenderOperationType type() const noexcept override
            {
                return SenderOperationType::sop_query;
            }

            seal::compr_mode_type compr_mode = seal::Serialization::compr_mode_default;

            SEALObject<seal::RelinKeys> relin_keys;

            /**
            Holds the encrypted query data. In the map the key labels the exponent of the query
            ciphertext and the vector holds the ciphertext data for different bundle indices.
            */
            std::unordered_map<std::uint32_t, std::vector<SEALObject<seal::Ciphertext>>> data;
        }; // class SenderOperationQuery
    }      // namespace network
} // namespace apsi
