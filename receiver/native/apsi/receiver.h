// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <map>
#include <vector>
#include <unordered_map>
#include <memory>
#include <utility>
#include <mutex>
#include <atomic>
#include <type_traits>

// APSI
#include "apsi/item.h"
#include "apsi/network/channel.h"
#include "apsi/psiparams.h"
#include "apsi/util/db_encoding.h"
#include "apsi/cryptocontext.h"
#include "apsi/sealobject.h"
#include "apsi/network/result_package.h"

// Kuku
#include "kuku/kuku.h"

// SEAL
#include "seal/util/defines.h"
#include "gsl/span"

namespace apsi
{
    namespace oprf
    {
        class OPRFReceiver;
    }

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
                return { reinterpret_cast<std::add_const_t<T>*>(label_->data().data(), 
                    label_->data().size() / sizeof(T)) };
            }

            template<typename CharT = char>
            std::basic_string<CharT> to_string() const
            {
                auto string_data = get_as<CharT>();
                return { string_data.data(), string_data.size() };
            }

            explicit operator bool() const noexcept
            {
                return !label_;
            }

        private:
            std::unique_ptr<Bitstring> label_;
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
            Constructs a new receiver without parameters specified. In this case the receiver expects to get
            the parameters from the sender in the beginning of a query.
            */
            Receiver(std::size_t thread_count);

            /**
            Constructs a new receiver with parameters specified. In this case the receiver has specified the
            parameters and expects the sender to use the same set.
            */
            Receiver(PSIParams params, std::size_t thread_count);

            /**
            Generates a new set of keys to use for queries.
            */
            void reset_keys();

            bool is_initialized() const
            {
                return params_ && crypto_context_;
            }

            /************************************************************************************************************************************
            Perform a full query.
            The query is a vector of items, and the result is a same-size vector of bool values. If an item is in the
            intersection, the corresponding bool value is true on the same position in the result vector.
            *************************************************************************************************************************************/
            std::vector<MatchRecord> query(const std::vector<Item> &items, network::Channel &chl);

            /************************************************************************************************************************************
            The following methods are the individual parts that when put together form a full Query to a Sender.
            *************************************************************************************************************************************/

            /**
            Get the query that should be sent to a remote sender, and get the intersection result. The query is a vector
            of items, and the result is a same-size vector of bool values. If an item is in the intersection, the
            corresponding bool value is true on the same position in the result vector .
            */
            network::SenderOperationQuery create_query(
                const std::vector<Item> &items,
                std::unordered_map<std::size_t, std::size_t> &table_idx_to_item_idx);

            /**
            Obfuscates the items and initializes the given vector with the buffer that must be sent to the Sender for
            OPRF processing.
            */
            std::vector<seal::SEAL_BYTE> obfuscate_items(const std::vector<Item> &items);

            /**
            Process obfuscated items received from Sender.
            Remove the Receiver obfuscation so only the Sender obfuscation remains.
            */
            std::vector<Item> deobfuscate_items(const std::vector<seal::SEAL_BYTE> &oprf_response);

            /**
            Perform a handshake between the Sender and this Receiver.
            Sender will send configuration parameters that the Receiver will use to configure itself.
            A handshake needs to be performed before any full query call. Otherwise, default parameters will be used.
            */
            void handshake(network::Channel &channel);

        private:
            /**
            Preprocesses the PSI items. Returns the power map of the items, and the indices of them in the hash table.
            */
            std::pair<std::map<std::uint64_t, std::vector<std::string>>, std::unique_ptr<kuku::KukuTable>> preprocess(
                std::vector<Item> &items);

            /**
            Hash all items in the input vector into a cuckoo hashing table.
            */
            std::unique_ptr<kuku::KukuTable> cuckoo_hashing(const std::vector<Item> &items);

            /**
            Returns a map: table index -> input index.
            */
            std::vector<std::size_t> cuckoo_indices(const std::vector<Item> &items, kuku::KukuTable &cuckoo);

            /**
            Encodes items in the cuckoo hashing table into FField elements.
            */
            void ffield_encoding(kuku::KukuTable &cuckoo, FFieldArray &ret);

            /**
            Generates powers y^k, where y is an element in the input vector, k = i*2^{jw}, (i = 1, 2, ..., 2^w - 1),
            (j = 0, 1, ..., bound - 1), (w is the window size in PSIParams), (bound is the number of segments when
            we break the bits of sender's split_size into segment of window size).
            The return result is a map from k to y^k.
            */
            void generate_powers(const FFieldArray &ffield_items, std::map<std::uint64_t, FFieldArray> &ret);

            /**
            Encrypts every vector of elements in the input map to a corresponding vector of SEAL Ciphertext, using
            generalized batching. The number of ciphertexts in a vector depends on the slot count in generalized
            batching. For example, if an input vector has size 1024, the slot count is 256, then there are 1024/256 = 4
            ciphertext in the Ciphertext vector.
            */
            void encrypt(
                std::map<std::uint64_t, FFieldArray> &input,
                std::map<std::uint64_t, std::vector<std::string>> &destination);

            /**
            Encrypts a vector of elements to a corresponding vector of SEAL Ciphertext, using generalized batching. The
            number of ciphertexts in the vector depends on the slot count in generalized batching. For example, if an
            input vector has size 1024, the slot count is 256, then there are 1024/256 = 4 ciphertext in the Ciphertext
            vector.
            */
            void encrypt(const FFieldArray &input, std::vector<std::string> &destination);

            /**
            Stream decryption of ciphers from the sender. Ciphertext will be acquired from the sender in a streaming
            fashion one by one in this function.

            One ciphertext will be decrypted into multiple elements. For example, if the slot count in generalized
            batching is 256, then a ciphertext is decrypted into 256 elements.

            @result Matrix of size (#splits x table_size_ceiling). Here table_size_ceiling is defined as (#batches x
            batch_size), which might be larger than table_size.
            */
            std::pair<std::vector<bool>, Matrix<unsigned char>> stream_decrypt(
                network::Channel &channel, const std::vector<std::size_t> &table_to_input_map,
                const std::vector<Item> &items);

            /**
            Work to be done in a single thread for stream_decrypt
            */
            void result_package_worker(
                std::atomic<std::uint32_t> &package_count,
                std::vector<MatchRecord> &mrs,
                const std::unordered_map<std::size_t, std::size_t> &table_idx_to_item_idx,
                network::Channel &chl) const;

            //std::shared_ptr<FField> field() const
            //{
                //return field_;
            //}

            //const seal::PublicKey &public_key() const
            //{
                //return public_key_;
            //}

            //const seal::SecretKey &secret_key() const
            //{
                //return secret_key_;
            //}

            // Data for a currently executing query 
            std::unique_ptr<
                std::pair<std::map<std::uint64_t, std::vector<std::string>>, std::unique_ptr<kuku::KukuTable>>>
                query_data_;

            void initialize();

            std::size_t thread_count_;

            std::uint64_t cuckoo_table_insert_attempts_;

            std::unique_ptr<PSIParams> params_;

            std::unique_ptr<CryptoContext> crypto_context_;

            SEALObject<seal::RelinKeys> relin_keys_;

            std::unique_ptr<oprf::OPRFReceiver> oprf_receiver_;

            //seal::SecretKey secret_key_;

            //std::unique_ptr<seal::Encryptor> encryptor_;

            //std::unique_ptr<seal::Decryptor> decryptor_;

            //std::unique_ptr<seal::BatchEncoder> encoder_;

            //std::size_t slot_count_;

        }; // class Receiver
    }      // namespace receiver
} // namespace apsi
