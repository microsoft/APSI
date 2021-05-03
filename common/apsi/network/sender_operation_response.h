// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <vector>

// APSI
#include "apsi/network/result_package.h"
#include "apsi/network/sender_operation.h"
#include "apsi/psi_params.h"

namespace apsi {
    namespace network {
        /**
        An abstract base class representing a response to a sender operation.
        */
        class SenderOperationResponse {
        public:
            SenderOperationResponse() = default;

            /**
            Destroys the SenderOperationResponse.
            */
            virtual ~SenderOperationResponse() = default;

            /**
            Writes the SenderOperationResponse to a stream.
            */
            virtual std::size_t save(std::ostream &out) const = 0;

            /**
            Reads the SenderOperationResponse from a stream.
            */
            virtual std::size_t load(std::istream &in) = 0;

            /**
            Returns the type of the SenderOperation for which this is a response.
            */
            virtual SenderOperationType type() const noexcept = 0;
        }; // class SenderOperationResponse

        /**
        A kind of SenderOperationResponse for representing a response to a parameter request.
        */
        class SenderOperationResponseParms final : public SenderOperationResponse {
        public:
            SenderOperationResponseParms() = default;

            ~SenderOperationResponseParms() = default;

            std::size_t save(std::ostream &out) const override;

            std::size_t load(std::istream &in) override;

            SenderOperationType type() const noexcept override
            {
                return SenderOperationType::sop_parms;
            }

            /**
            Holds the parameters returned to the receiver.
            */
            std::unique_ptr<PSIParams> params;
        }; // class SenderOperationResponseParms

        /**
        A kind of SenderOperationResponse for representing a response to an OPRF query.
        */
        class SenderOperationResponseOPRF final : public SenderOperationResponse {
        public:
            SenderOperationResponseOPRF() = default;

            ~SenderOperationResponseOPRF() = default;

            std::size_t save(std::ostream &out) const override;

            std::size_t load(std::istream &in) override;

            SenderOperationType type() const noexcept override
            {
                return SenderOperationType::sop_oprf;
            }

            /**
            Holds the OPRF query data.
            */
            std::vector<unsigned char> data;
        }; // class SenderOperationResponseOPRF

        /**
        A kind of SenderOperationResponse for representing a response to a PSI or labeled PSI query.
        */
        class SenderOperationResponseQuery final : public SenderOperationResponse {
        public:
            SenderOperationResponseQuery() = default;

            ~SenderOperationResponseQuery() = default;

            std::size_t save(std::ostream &out) const override;

            std::size_t load(std::istream &in) override;

            SenderOperationType type() const noexcept override
            {
                return SenderOperationType::sop_query;
            }

            /**
            Holds the number of ResultPackage objects the sender is expected to send back to the
            receiver.
            */
            std::uint32_t package_count;
        }; // class SenderOperationResponseQuery
    }      // namespace network
} // namespace apsi
