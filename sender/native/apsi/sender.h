// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iostream>
#include <unordered_map>
#include <memory>
#include <utility>
#include <vector>

// APSI
#include "apsi/crypto_context.h"
#include "apsi/item.h"
#include "apsi/network/channel.h"
#include "apsi/network/sender_operation.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/powers.h"
#include "apsi/psi_params.h"
#include "apsi/query.h"
#include "apsi/requests.h"
#include "apsi/responses.h"
#include "apsi/seal_object.h"
#include "apsi/sender_db.h"

// SEAL
#include "seal/relinkeys.h"
#include "seal/ciphertext.h"
#include "seal/util/defines.h"

namespace apsi
{
    namespace sender
    {
        class ParmsRequest
        {
        friend class Sender;

        public:
            ParmsRequest(std::unique_ptr<network::SenderOperation> sop);

            ParmsRequest deep_copy() const
            {
                // No data to copy
                return ParmsRequest();
            }

            ParmsRequest(const ParmsRequest &source) = delete;

            ParmsRequest(ParmsRequest &&source) = default;

            ParmsRequest &operator =(const ParmsRequest &source) = delete;

            ParmsRequest &operator =(ParmsRequest &&source) = default;

        private:
            ParmsRequest() = default;
        };

        class OPRFRequest
        {
        friend class Sender;

        public:
            OPRFRequest(std::unique_ptr<network::SenderOperation> sop);

            OPRFRequest deep_copy() const
            {
                OPRFRequest result;
                result.data_ = data_;
                return std::move(result);
            }

            OPRFRequest(const OPRFRequest &source) = delete;

            OPRFRequest(OPRFRequest &&source) = default;

            OPRFRequest &operator =(const OPRFRequest &source) = delete;

            OPRFRequest &operator =(OPRFRequest &&source) = default;

        private:
            OPRFRequest() = default;

            std::vector<seal::seal_byte> data_;
        };

        // An alias to denote the powers of a receiver's ciphertext. At index i, holds Cⁱ, where C is the ciphertext..
        // The 0th index is always a dummy value.
        using CiphertextPowers = std::vector<seal::Ciphertext>;

        class Sender
        {
        public:
            Sender() = delete;

            /**
            Generate and send a response to a parameter request.
            */
            static void RunParms(
                ParmsRequest &&parms_request,
                std::shared_ptr<SenderDB> sender_db,
                network::Channel &chl,
                std::function<void(network::Channel &, std::unique_ptr<network::SenderOperationResponse>)> send_fun
                    = BasicSend<network::SenderOperationResponse>);

            /**
            Generate and send a response to an OPRF request.
            */
            static void RunOPRF(
                OPRFRequest &&oprf_request,
                const oprf::OPRFKey &key,
                network::Channel &chl,
                std::function<void(network::Channel &, std::unique_ptr<network::SenderOperationResponse>)> send_fun
                    = BasicSend<network::SenderOperationResponse>);

            /**
            Generate and send a response to a query.
            */
            static void RunQuery(
                const Query &query,
                network::Channel &chl,
                std::size_t thread_count = 0,
                std::function<void(network::Channel &, std::unique_ptr<network::SenderOperationResponse>)> send_fun
                    = BasicSend<network::SenderOperationResponse>,
                std::function<void(network::Channel &, std::unique_ptr<network::ResultPackage>)> send_rp_fun
                    = BasicSend<network::ResultPackage>);

        private:
            template<typename T>
            static void BasicSend(network::Channel &chl, std::unique_ptr<T> pkg)
            {
                chl.send(std::move(pkg));
            }

            /**
            Method that handles the work of a single thread that computes the response to a query.
            */
            static void QueryWorker(
                const std::shared_ptr<SenderDB> &sender_db,
                CryptoContext crypto_context,
                std::pair<std::uint32_t, std::uint32_t> work_range,
                std::vector<std::vector<seal::Ciphertext>> &powers,
                const PowersDag &pd,
                network::Channel &chl,
                std::function<void(network::Channel &, std::unique_ptr<network::ResultPackage>)> send_rp_fun);
        }; // class Sender
    }      // namespace sender
} // namespace apsi
