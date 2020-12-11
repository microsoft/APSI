// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <cstddef>
#include <vector>
#include <unordered_map>
#include <memory>
#include <utility>
#include <atomic>
#include <type_traits>
#include <stdexcept>

// APSI
#include "apsi/crypto_context.h"
#include "apsi/item.h"
#include "apsi/network/channel.h"
#include "apsi/network/network_channel.h"
#include "apsi/network/result_package.h"
#include "apsi/oprf/oprf_receiver.h"
#include "apsi/powers.h"
#include "apsi/psi_params.h"
#include "apsi/seal_object.h"
#include "apsi/util/db_encoding.h"

// GSL
#include "gsl/span"

// SEAL
#include "seal/util/defines.h"

namespace apsi
{
    namespace receiver
    {
        class Receiver;

        class LabelData
        {
        public:
            LabelData() = default;

            LabelData(std::unique_ptr<Bitstring> label) : label_(std::move(label))
            {}

            void set(std::unique_ptr<Bitstring> label)
            {
                label_ = std::move(label);
            }

            template<typename T, typename = std::enable_if_t<std::is_standard_layout<T>::value>>
            gsl::span<std::add_const_t<T>> get_as() const
            {
                return { reinterpret_cast<std::add_const_t<T>*>(label_->data().data()), 
                    label_->data().size() / sizeof(T) };
            }

            template<typename CharT = char>
            std::basic_string<CharT> to_string() const
            {
                auto string_data = get_as<CharT>();
                return { string_data.data(), string_data.size() };
            }

            explicit operator bool() const noexcept
            {
                return !!label_;
            }

        private:
            std::unique_ptr<Bitstring> label_ = nullptr;
        };

        class MatchRecord 
        {
        public:
            bool found = false;

            LabelData label;

            explicit operator bool() const noexcept
            {
                return found;
            }
        };

        class Query
        {
        friend class Receiver;

        public:
            Query deep_copy() const;

            Query(Query &&source) = default;

            Query(const Query &source) = delete;

            Query &operator =(Query &&source) = default;

            Query &operator =(const Query &source) = delete;

            const network::SenderOperationQuery &request_data() const;

            const std::unordered_map<std::size_t, std::size_t> &table_idx_to_item_idx() const noexcept
            {
                return table_idx_to_item_idx_;
            }

            const std::size_t item_count() const noexcept
            {
                return item_count_;
            }

            std::unique_ptr<network::SenderOperation> extract_request();

            bool has_request() const noexcept;

        private:
            Query() = default;

            std::unique_ptr<network::SenderOperation> sop_ = nullptr;

            std::unordered_map<std::size_t, std::size_t> table_idx_to_item_idx_;

            std::size_t item_count_ = 0;
        };

        using ParamsResponse = std::unique_ptr<network::SenderOperationResponseParms>;

        using OPRFResponse = std::unique_ptr<network::SenderOperationResponseOPRF>;

        using QueryResponse = std::unique_ptr<network::SenderOperationResponseQuery>;

        class Receiver
        {
        public:
            static constexpr std::uint64_t cuckoo_table_insert_attempts = 500;

            /**
            Constructs a new receiver with parameters specified. In this case the receiver has specified the parameters
            and expects the sender to use the same set.
            */
            Receiver(PSIParams params, std::size_t thread_count = 0);

            /**
            Generates a new set of keys to use for queries.
            */
            void reset_keys();

            /**
            Returns the current CryptoContext.
            */
            std::shared_ptr<const CryptoContext> crypto_context() const
            {
                return crypto_context_;
            }

            static std::unique_ptr<network::SenderOperation> CreateParamsRequest();
            
            static bool SendRequest(std::unique_ptr<network::SenderOperation> sop, network::Channel &chl);

            static ParamsResponse ReceiveParamsResponse(network::Channel &chl);

            /**
            Performs a parameter request and returns the received parameters.
            */
            static PSIParams RequestParams(network::NetworkChannel &chl);

            /**
            Obfuscates the items and initializes the given vector with the buffer that must be sent to a sender for
            sender-side obfuscation (OPRF hash).
            */
            static oprf::OPRFReceiver CreateOPRFReceiver(const std::vector<Item> &items);

            /**
            Removes receiver-side obfuscation from items received after an OPRF query from a sender so that only the
            sender's obfuscation (OPRF hash) remains.
            */
            static std::vector<HashedItem> ExtractHashes(
                const OPRFResponse &oprf_response,
                const oprf::OPRFReceiver &oprf_receiver);

            static std::unique_ptr<network::SenderOperation> CreateOPRFRequest(
                const std::vector<Item> &items,
                const oprf::OPRFReceiver &oprf_receiver);

            static OPRFResponse ReceiveOPRFResponse(network::Channel &chl);

            /**
            Performs an OPRF query and returns a vector of hashed items.
            */
            static std::vector<HashedItem> RequestOPRF(const std::vector<Item> &items, network::NetworkChannel &chl);

            /**
            Creates a query request.
            */
            Query create_query(const std::vector<HashedItem> &items);

            static QueryResponse ReceiveQueryResponse(network::Channel &chl);

            /**
            Performs a PSI or labeled PSI (depending on the sender) query. The query is a vector of items, and the
            result is a same-size vector of MatchRecord objects. If an item is in the intersection, the corresponding
            MatchRecord indicates it in the `found` field, and the `label` field may contain the corresponding label if 
            a sender included it. The query is left in an unusable state and a deep copy must explicitly be made if the
            query is to be used again.
            */
            std::vector<MatchRecord> request_query(const std::vector<HashedItem> &items, network::NetworkChannel &chl);

        private:
            void result_package_worker(
                std::atomic<std::int32_t> &package_count,
                std::vector<MatchRecord> &mrs,
                const std::unordered_map<std::size_t, std::size_t> &table_idx_to_item_idx,
                network::Channel &chl) const;

            void initialize();

            std::size_t thread_count_;

            PSIParams params_;

            std::shared_ptr<CryptoContext> crypto_context_;

            PowersDag pd_;

            SEALObject<seal::RelinKeys> relin_keys_;
        }; // class Receiver
    }      // namespace receiver
} // namespace apsi
