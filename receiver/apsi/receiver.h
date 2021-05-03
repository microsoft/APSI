// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <set>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

// APSI
#include "apsi/crypto_context.h"
#include "apsi/item.h"
#include "apsi/itt.h"
#include "apsi/match_record.h"
#include "apsi/network/channel.h"
#include "apsi/network/network_channel.h"
#include "apsi/oprf/oprf_receiver.h"
#include "apsi/powers.h"
#include "apsi/psi_params.h"
#include "apsi/requests.h"
#include "apsi/responses.h"
#include "apsi/seal_object.h"

namespace apsi {
    namespace receiver {
        /**
        The Receiver class implements all necessary functions to create and send parameter, OPRF,
        and PSI or labeled PSI queries (depending on the sender), and process any responses
        received. Most of the member functions are static, but a few (related to creating and
        processing the query itself) require an instance of the class to be created.

        The class includes two versions of an API to performs the necessary operations. The "simple"
        API consists of three functions: Receiver::RequestParams, Receiver::RequestOPRF, and
        Receiver::request_query. However, these functions only support network::NetworkChannel, such
        as network::ZMQChannel, for the communication. Other channels, such as
        network::StreamChannel, are only supported by the "advanced" API.

        The advanced API requires many more steps. The full process is as follows:

        (0 -- optional) Receiver::CreateParamsRequest must be used to create a parameter request.
        The request must be sent to the sender on a channel with network::Channel::send. The sender
        must respond to the request and the response must be received on the channel with
        network::Channel::receive_response. The received Response object must be converted to the
        right type (ParamsResponse) with the to_params_response function. This function will return
        nullptr if the received response was not of the right type. A PSIParams object can be
        extracted from the response.

        (1) A Receiver object must be created from a PSIParams object. The PSIParams must match what
        the sender uses.

        (2) Receiver::CreateOPRFReceiver must be used to process the input vector of items and
        return an associated oprf::OPRFReceiver object. Next, Receiver::CreateOPRFRequest must be
        used to create an OPRF request from the oprf::OPRFReceiver, which can subsequently be sent
        to the sender with network::Channel::send. The sender must respond to the request and the
        response must be received on the channel with network::Channel::receive_response. The
        received Response object must be converted to the right type (OPRFResponse) with the
        to_oprf_response function. This function will return nullptr if the received response was
        not of the right type. Finally, Receiver::ExtractHashes must be called with the
        OPRFResponse and the oprf::OPRFReceiver object. This function returns
        std::pair<std::vector<HashedItem>, std::vector<LabelKey>>, containing the OPRF hashed items
        and the label encryption keys. Both vectors in this pair must be kept for the next steps.

        (3) Receiver::create_query (non-static member function) must then be used to create the
        query itself. The function returns std::pair<Request, IndexTranslationTable>, where the
        Request object contains the query itself to be send to the sender, and the
        IndexTranslationTable is an object associated to this query describing how the internal data
        structures of the query maps to the vector of OPRF hashed items given to
        Receiver::create_query. The IndexTranslationTable object is needed later to process the
        responses from the sender. The Request object must be sent to the sender with
        network::Channel::send. The received Response object must be converted to the right type
        (QueryResponse) with the to_query_response function. This function will return nullptr if
        the received response was not of the right type. The QueryResponse contains only one
        important piece of data: the number of ResultPart objects the receiver should expect to
        receive from the sender in the next step.

        (4) network::Channel::receive_result must be called repeatedly to receive all ResultParts.
        For each received ResultPart Receiver::process_result_part must be called to find a
        std::vector<MatchRecord> representing the match data associated to that ResultPart.
        Alternatively, one can first retrieve all ResultParts, collect them into a
        std::vector<ResultPart>, and use Receiver::process_result to find the complete result --
        just like what the simple API returns. Both Receiver::process_result_part and
        Receiver::process_result require the IndexTranslationTable and the std::vector<LabelKey>
        objects created in the previous steps.
        */
        class Receiver {
        public:
            /**
            Indicates the number of random-walk steps used by the Kuku library to insert items into
            the cuckoo hash table. Increasing this number can yield better packing rates in cuckoo
            hashing.
            */
            static constexpr std::uint64_t cuckoo_table_insert_attempts = 500;

            /**
            Creates a new receiver with parameters specified. In this case the receiver has
            specified the parameters and expects the sender to use the same set.
            */
            Receiver(PSIParams params);

            /**
            Generates a new set of keys to use for queries.
            */
            void reset_keys();

            /**
            Returns a reference to the PowersDag configured for this Receiver.
            */
            const PowersDag &get_powers_dag() const
            {
                return pd_;
            }

            /**
            Returns a reference to the CryptoContext for this Receiver.
            */
            const CryptoContext &get_crypto_context() const
            {
                return crypto_context_;
            }

            /**
            Returns a reference to the SEALContext for this Receiver.
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
            Performs an OPRF request on a vector of items through a given channel and returns a
            vector of OPRF hashed items of the same size as the input vector.
            */
            static std::pair<std::vector<HashedItem>, std::vector<LabelKey>> RequestOPRF(
                const std::vector<Item> &items, network::NetworkChannel &chl);

            /**
            Performs a PSI or labeled PSI (depending on the sender) query. The query is a vector of
            items, and the result is a same-size vector of MatchRecord objects. If an item is in the
            intersection, the corresponding MatchRecord indicates it in the `found` field, and the
            `label` field may contain the corresponding label if a sender's data included it.
            */
            std::vector<MatchRecord> request_query(
                const std::vector<HashedItem> &items,
                const std::vector<LabelKey> &label_keys,
                network::NetworkChannel &chl);

            /**
            Creates and returns a parameter request that can be sent to the sender with the
            Receiver::SendRequest function.
            */
            static Request CreateParamsRequest();

            /**
            Creates and returns an oprf::OPRFReceiver object for the given items.
            */
            static oprf::OPRFReceiver CreateOPRFReceiver(const std::vector<Item> &items);

            /**
            Creates an OPRF request that can be sent to the sender with the Receiver::SendRequest
            function.
            */
            static Request CreateOPRFRequest(const oprf::OPRFReceiver &oprf_receiver);

            /**
            Extracts a vector of OPRF hashed items from an OPRFResponse and the corresponding
            oprf::OPRFReceiver.
            */
            static std::pair<std::vector<HashedItem>, std::vector<LabelKey>> ExtractHashes(
                const OPRFResponse &oprf_response, const oprf::OPRFReceiver &oprf_receiver);

            /**
            Creates a Query object from a vector of OPRF hashed items. The query contains the query
            request that can be extracted with the Query::extract_request function and sent to the
            sender with Receiver::SendRequest. It also contains an index translation table that
            keeps track of the order of the hashed items vector, and is used internally by the
            Receiver::process_result_part function to sort the results in the correct order.
            */
            std::pair<Request, IndexTranslationTable> create_query(
                const std::vector<HashedItem> &items);

            /**
            Processes a ResultPart object and returns a vector of MatchRecords in the same order as
            the original vector of OPRF hashed items used to create the query. The return value
            includes matches only for those items whose results happened to be in this particular
            result part. Thus, to determine whether there was a match with the sender's data, the
            results for each received ResultPart must be checked.
            */
            std::vector<MatchRecord> process_result_part(
                const std::vector<LabelKey> &label_keys,
                const IndexTranslationTable &itt,
                const ResultPart &result_part) const;

            /**
            This function does multiple calls to Receiver::process_result_part, once for each
            ResultPart in the given vector. The results are collected together so that the returned
            vector of MatchRecords reflects the logical OR of the results from each ResultPart.
            */
            std::vector<MatchRecord> process_result(
                const std::vector<LabelKey> &label_keys,
                const IndexTranslationTable &itt,
                const std::vector<ResultPart> &result) const;

        private:
            /**
            Recomputes the PowersDag. The function returns the depth of the PowersDag. In some cases
            the receiver may want to ensure that the depth of the powers computation will be as
            expected (PowersDag::depth), and otherwise attempt to reconfigure the PowersDag.
            */
            std::uint32_t reset_powers_dag(const std::set<std::uint32_t> &source_powers);

            void process_result_worker(
                std::atomic<std::uint32_t> &package_count,
                std::vector<MatchRecord> &mrs,
                const std::vector<LabelKey> &label_keys,
                const IndexTranslationTable &itt,
                network::Channel &chl) const;

            void initialize();

            PSIParams params_;

            CryptoContext crypto_context_;

            PowersDag pd_;

            SEALObject<seal::RelinKeys> relin_keys_;
        }; // class Receiver
    }      // namespace receiver
} // namespace apsi
