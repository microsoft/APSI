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
            Query deep_copy() const
            {
                Query result;
                result.item_count_ = item_count_;
                result.table_idx_to_item_idx_ = table_idx_to_item_idx_;
                auto sop_query = std::make_unique<network::SenderOperationQuery>();
                auto this_query = dynamic_cast<const network::SenderOperationQuery*>(sop_.get());
                sop_query->relin_keys = this_query->relin_keys;
                sop_query->data = this_query->data;
                result.sop_ = std::move(sop_query);

                return std::move(result);
            }

            Query(Query &&source) = default;

            Query(const Query &source) = delete;

            Query &operator =(Query &&source) = default;

            Query &operator =(const Query &source) = delete;

            const network::SenderOperationQuery &data() const
            {
                const network::SenderOperationQuery *sop_query
                    = dynamic_cast<const network::SenderOperationQuery*>(sop_.get());
                if (!sop_query)
                {
                    throw std::logic_error("query data is invalid");
                }
                return *sop_query;
            }

            const std::unordered_map<std::size_t, std::size_t> &table_idx_to_item_idx() const
            {
                return table_idx_to_item_idx_;
            }

            const std::size_t item_count() const
            {
                return item_count_;
            }

        private:
            Query() = default;

            std::unique_ptr<network::SenderOperation> sop_ = nullptr;

            std::unordered_map<std::size_t, std::size_t> table_idx_to_item_idx_;

            std::size_t item_count_ = 0;
        };

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

            /**
            Performs a parameter request and returns the received parameters.
            */
            static PSIParams RequestParams(network::Channel &chl);

            /**
            Performs an OPRF query and returns a vector of hashed items.
            */
            std::vector<HashedItem> request_oprf(const std::vector<Item> &items, network::Channel &chl);

            /**
            Creates a query.
            */
            Query create_query(const std::vector<HashedItem> &items);

            /**
            Performs a PSI or labeled PSI (depending on the sender) query. The query is a vector of items, and the
            result is a same-size vector of MatchRecord objects. If an item is in the intersection, the corresponding
            MatchRecord indicates it in the `found` field, and the `label` field may contain the corresponding label if 
            a sender included it. The query is left in an unusable state and a deep copy must explicitly be made if the
            query is to be used again.
            */
            std::vector<MatchRecord> request_query(Query &&query, network::Channel &chl);

        private:
            /**
            Obfuscates the items and initializes the given vector with the buffer that must be sent to a sender for
            sender-side obfuscation (OPRF).
            */
            std::vector<seal::seal_byte> obfuscate_items(
                const std::vector<Item> &items,
                std::unique_ptr<oprf::OPRFReceiver> &oprf_receiver);

            /**
            Removes receiver-side obfuscation from items received after an OPRF query from a sender so that only the
            sender's obfuscation (OPRF) remains.
            */
            std::vector<HashedItem> deobfuscate_items(
                const std::vector<seal::seal_byte> &oprf_response,
                std::unique_ptr<oprf::OPRFReceiver> &oprf_receiver);

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
