// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <cstddef>
#include <map>
#include <vector>
#include <unordered_map>
#include <memory>
#include <utility>
#include <atomic>
#include <type_traits>

// APSI
#include "apsi/cryptocontext.h"
#include "apsi/item.h"
#include "apsi/network/channel.h"
#include "apsi/network/result_package.h"
#include "apsi/oprf/oprf_receiver.h"
#include "apsi/psiparams.h"
#include "apsi/sealobject.h"
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

        class Receiver
        {
        public:
            static constexpr std::uint64_t cuckoo_table_insert_attempts = 500;

            /**
            Constructs a new receiver with parameters specified. In this case the receiver has specified the parameters
            and expects the sender to use the same set.
            */
            Receiver(PSIParams params, std::size_t thread_count);

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
            Performs a parameter request and returns the receiver parameters.
            */
            static PSIParams request_params(network::Channel &chl);

            /**
            Performs a PSI or labeled PSI (depending on the sender) query. The query is a vector of items, and the
            result is a same-size vector of MatchRecord objects. If an item is in the intersection, the corresponding
            MatchRecord indicates it in the `found` field, and the `label` field may contain the corresponding label if 
            a sender included it.
            */
            std::vector<MatchRecord> query(const std::vector<Item> &items, network::Channel &chl);

        private:
            /**
            Obfuscates the items and initializes the given vector with the buffer that must be sent to a sender for
            sender-side obfuscation (OPRF).
            */
            std::vector<seal::SEAL_BYTE> obfuscate_items(const std::vector<Item> &items);

            /**
            Removes receiver-side obfuscation from items received after an OPRF query from a sender so that only the
            sender's obfuscation (OPRF) remains.
            */
            std::vector<Item> deobfuscate_items(const std::vector<seal::SEAL_BYTE> &oprf_response);

            std::unique_ptr<network::SenderOperation> create_query(
                const std::vector<Item> &items,
                std::unordered_map<std::size_t, std::size_t> &table_idx_to_item_idx);

            void result_package_worker(
                std::atomic<std::int32_t> &package_count,
                std::vector<MatchRecord> &mrs,
                const std::unordered_map<std::size_t, std::size_t> &table_idx_to_item_idx,
                network::Channel &chl) const;

            void initialize();

            std::size_t thread_count_;

            std::uint64_t cuckoo_table_insert_attempts_;

            std::unique_ptr<PSIParams> params_;

            std::shared_ptr<CryptoContext> crypto_context_;

            SEALObject<seal::RelinKeys> relin_keys_;

            std::unique_ptr<oprf::OPRFReceiver> oprf_receiver_;
        }; // class Receiver
    }      // namespace receiver
} // namespace apsi
