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
#include "apsi/requests.h"
#include "apsi/responses.h"
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

        class IndexTranslationTable
        {
        friend class Receiver;

        public:
            /**
            Translates a cuckoo table index to an index of the vector of items that were used to create this query. If
            the given table index was not populated, i.e., there is no translation, then this function returns the
            number of items encoded by this query.
            */
            std::size_t find_item_idx(std::size_t table_idx) const noexcept;

            /**
            Returns the number of items encoded by this query. This function returns 0 if the query does not contain an
            index translation table, e.g., when the sender has received the query.
            */
            const std::size_t item_count() const noexcept
            {
                return item_count_;
            }

        private:
            IndexTranslationTable() = default;

            std::unordered_map<std::size_t, std::size_t> table_idx_to_item_idx_;

            std::size_t item_count_;
        };

        /**
        A LabelData object contains the data for an arbitrary size label returned from a query. Member functions allow
        the label to be read as a string or as an array of (standard layout) objects of a desired type. There is usually
        no reason for a normal user to create LabelData objects. These are used as a part of a MatchRecord object and
        created by the query response processing API.
        */
        class LabelData
        {
        public:
            /**
            Creates an empty LabelData object.
            */
            LabelData() = default;

            /**
            Creates a LabelData object holding a given bit string.
            */ 
            LabelData(std::unique_ptr<Bitstring> label) : label_(std::move(label))
            {}

            /**
            Sets the current label data to a given bit string.
            */ 
            void set(std::unique_ptr<Bitstring> label)
            {
                label_ = std::move(label);
            }

            /**
            Returns a span of a desired (standard layout) type to the label data.
            */ 
            template<typename T, typename = std::enable_if_t<std::is_standard_layout<T>::value>>
            gsl::span<std::add_const_t<T>> get_as() const
            {
                return { reinterpret_cast<std::add_const_t<T>*>(label_->data().data()), 
                    label_->data().size() / sizeof(T) };
            }

            /**
            Returns a string containing the label data.
            */ 
            template<typename CharT = char>
            std::basic_string<CharT> to_string() const
            {
                auto string_data = get_as<CharT>();
                return { string_data.data(), string_data.size() };
            }

            /**
            Returns whether the LabelData object holds any any data.
            */
            bool has_data() const noexcept
            {
                return !!label_;
            }

            /**
            Returns whether the LabelData object holds any any data.
            */
            explicit operator bool() const noexcept
            {
                return has_data();
            }

        private:
            std::unique_ptr<Bitstring> label_ = nullptr;
        };

        /**
        A MatchRecord object is a simple structure holding two values: a bool indicating a match found in a query and
        a LabelData object holding the corresponding label data, if such was retrieved. There is usually no reason for
        a normal user to create MatchRecord objects. These are created by the query response processing API.
        */
        class MatchRecord 
        {
        public:
            /**
            Indicates whether this MatchRecord signals a match found in a query.
            */
            bool found = false;

            /**
            Holds the label data for the match indicated by this MatchRecord, if the sender returned any.
            */
            LabelData label;

            /**
            Returns whether this MatchRecord signals a match found in a query.
            */
            explicit operator bool() const noexcept
            {
                return found;
            }
        };

        /**
        The Receiver class implements all necessary functions to create and send parameter, OPRF, and PSI or labeled PSI
        queries (depending on the sender), and process any responses received. Most of the member functions are static,
        but a few (related to query request) require a cryptographic context held by an instance of the class.

        The class includes two versions of an API to performs the necessary operations. The "simple" API consists of
        three functions: Receiver::RequestParams, Receiver::RequestOPRF, and Receiver::request_query. However, these
        functions only support network::NetworkChannel, such as network::ZMQChannel, for the communication. Other
        channels, such as network::StreamChannel, are only supported by the "advanced" API.

        The advanced API is requires many more steps:

        (1) Receiver::CreateParamsRequest must be used to create a parameter request and Receiver::SendRequest must be
        used to send it on a network::Channel. The response must be received with Receiver::ReceiveParamsResponse.
        The PSIParams object can be extracted from the response and a Receiver object can be created.

        (2) Receiver::CreateOPRFReceiver must be used to process the input vector of items and return an associated
        oprf::OPRFReceiver object. Next, Receiver::CreateOPRFRequest must be used to create an OPRF request from the
        oprf::OPRFReceiver, which can subsequently be sent to the sender with Receiver::SendRequest. The response must
        be received with Receiver::ReceiveOPRFResponse. Finally, Receiver::ExtractHashes is used to obtain the OPRF
        hashed items from the OPRF response with the help of the oprf::OPRFReceiver object.

        (3) Receiver::create_query must be used to create a Query object from the vector of OPRF hashed items received
        in the previous step. The query request must be extracted from the Query object with Query::extract_request and
        subsequently be sent to the sender with Receiver::SendRequest; the same Query object can no longer be used for
        performing another query. Another way is to use Receiver:::SendQuery that makes a deep copy of the Query and
        calls Receiver::SendRequest with the request extracted from the copy. Next, the response must be received with
        Receiver::ReceiveQueryResponse. From the response one can read the package_count member variable that tells
        how many ResultPart objects can be expected to be received.

        (4) Receiver::receive_result must be called repeatedly to receive all ResultParts. For each received ResultPart
        Receiver::process_result_part must be called to find a std::vector<MatchRecord> representing the match data
        associated to that ResultPart. Alternatively, one can first retrieve all ResultParts, collect them into
        a std::vector<ResultPart>, and use Receiver::process_result to find the complete result -- just like what the
        simple API returns.
        */
        class Receiver
        {
        public:
            /**
            Indicates the number of random-walk steps used by the Kuku library to insert items into the cuckoo hash
            table. Increasing this number can yield better packing rates in cuckoo hashing.
            */
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
            Returns a reference to the CryptoContext for this Receiver.
            */
            const CryptoContext &get_crypto_context() const
            {
                return crypto_context_;
            }
            
            /**
            Returns a reference to the SEALContext for this SenderDB.
            */
            std::shared_ptr<seal::SEALContext> get_seal_context() const
            {
                return crypto_context_.seal_context();
            }

            /**
            Performs a parameter request and returns the received PSIParams object.
            */
            static PSIParams RequestParams(network::NetworkChannel &chl);

            /**
            Performs an OPRF request on a vector of items through a given channel and returns a vector of OPRF hashed
            items of the same size as the input vector.
            */
            static std::vector<HashedItem> RequestOPRF(const std::vector<Item> &items, network::NetworkChannel &chl);

            /**
            Performs a PSI or labeled PSI (depending on the sender) query. The query is a vector of items, and the
            result is a same-size vector of MatchRecord objects. If an item is in the intersection, the corresponding
            MatchRecord indicates it in the `found` field, and the `label` field may contain the corresponding label if 
            a sender's data included it.
            */
            std::vector<MatchRecord> request_query(const std::vector<HashedItem> &items, network::NetworkChannel &chl);

            /**
            Creates and returns a parameter request that can be sent to the sender with the Receiver::SendRequest
            function.
            */
            static Request CreateParamsRequest();

            /**
            Creates and returns an oprf::OPRFReceiver object for the given items.
            */
            static oprf::OPRFReceiver CreateOPRFReceiver(const std::vector<Item> &items);

            /**
            Creates an OPRF request that can be sent to the sender with the Receiver::SendRequest function. 
            */
            static Request CreateOPRFRequest(const oprf::OPRFReceiver &oprf_receiver);

            /**
            Extracts a vector of OPRF hashed items from an OPRFResponse and the corresponding oprf::OPRFReceiver.
            */
            static std::vector<HashedItem> ExtractHashes(
                const OPRFResponse &oprf_response,
                const oprf::OPRFReceiver &oprf_receiver);

            /**
            Creates a Query object from a vector of OPRF hashed items. The query contains the query request that can be
            extracted with the Query::extract_request function and sent to the sender with Receiver::SendRequest. It
            also contains an index translation table that keeps track of the order of the hashed items vector, and is
            used internally by the Receiver::process_result_part function to sort the results in the correct order.
            */
            std::pair<Request, IndexTranslationTable> create_query(const std::vector<HashedItem> &items);

            /**
            Processes a ResultPart object and returns a vector of MatchRecords in the same order as the original vector
            of OPRF hashed items used to create the query. The return value includes matches only for those items whose
            results happened to be in this particular result part. Thus, to determine whether there was a match with the
            sender's data, the results for each received ResultPart must be checked.
            */
            std::vector<MatchRecord> process_result_part(const IndexTranslationTable &itt, const ResultPart &result_part) const;

            /**
            This function does multiple calls to Receiver::process_result_part, once for each ResultPart in the given
            vector. The results are collected together so that the returned vector of MatchRecords reflects the logical
            OR of the results from each ResultPart.
            */
            std::vector<MatchRecord> process_result(const IndexTranslationTable &itt, const std::vector<ResultPart> &result) const;

        private:
            void process_result_worker(
                std::atomic<std::int32_t> &package_count,
                std::vector<MatchRecord> &mrs,
                const IndexTranslationTable &itt,
                network::Channel &chl) const;

            void initialize();

            std::size_t thread_count_;

            PSIParams params_;

            CryptoContext crypto_context_;

            PowersDag pd_;

            SEALObject<seal::RelinKeys> relin_keys_;
        }; // class Receiver
    }      // namespace receiver
} // namespace apsi
