// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <thread>

// APSI
#include "apsi/logging/log.h"
#include "apsi/network/channel.h"
#include "apsi/receiver.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/defines.h"
#include "seal/encryptionparams.h"
#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/plaintext.h"
#include "seal/ciphertext.h"
#include "seal/util/iterator.h"
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace kuku;

namespace apsi
{
    using namespace util;
    using namespace network;
    using namespace oprf;

    namespace
    {
        class PlaintextPowers
        {
        public:
            PlaintextPowers(vector<uint64_t> values, const PSIParams &params, const PowersDag &pd) :
                mod_(params.seal_params().plain_modulus())
            {
                compute_powers(move(values), pd);
            }

            unordered_map<uint32_t, SEALObject<Ciphertext>> encrypt(const CryptoContext &crypto_context)
            {
                if (!crypto_context.encryptor())
                {
                    throw invalid_argument("encryptor is not set in crypto_context");
                }

                unordered_map<uint32_t, SEALObject<Ciphertext>> result;
                for (auto &p : powers_)
                {
                    Plaintext pt;
                    crypto_context.encoder()->encode(p.second, pt);
                    result.emplace(make_pair(p.first, crypto_context.encryptor()->encrypt_symmetric(pt)));
                }

                return result;
            }

        private:
            Modulus mod_;

            unordered_map<uint32_t, vector<uint64_t>> powers_;

            void square_array(gsl::span<uint64_t> in) const
            {
                transform(in.begin(), in.end(), in.begin(),
                    [this](auto val) { return multiply_uint_mod(val, val, mod_); });
            }

            void multiply_array(gsl::span<uint64_t> in1, gsl::span<uint64_t> in2, gsl::span<uint64_t> out) const
            {
                transform(in1.begin(), in1.end(), in2.begin(), out.begin(),
                    [this](auto val1, auto val2) { return multiply_uint_mod(val1, val2, mod_); });
            }

            vector<uint64_t> exponentiate_array(vector<uint64_t> values, uint32_t exponent)
            {
                if (!exponent)
                {
                    throw invalid_argument("exponent cannot be zero");
                }

                vector<uint64_t> result(values.size(), 1);
                while (exponent)
                {
                    if (exponent & 1)
                    {
                        multiply_array(values, result, result);
                    }
                    square_array(values);
                    exponent >>= 1;
                }

                return result;
            }

            void compute_powers(vector<uint64_t> values, const PowersDag &pd)
            {
                auto source_powers = pd.source_nodes();

                for (auto &s : source_powers)
                {
                    powers_[s.power] = exponentiate_array(values, s.power);
                }

                APSI_LOG_DEBUG("Plaintext powers computed: " << [&]() {
                        stringstream ss;
                        ss << "[";
                        for (auto &a : powers_)
                        {
                            ss << " " << a.first;
                        }
                        ss << " ]";
                        return ss.str();
                    }());
            }
        };

        template<typename To, typename From>
        unique_ptr<To> downcast_ptr(unique_ptr<From> from)
        {
            auto ptr = dynamic_cast<To *>(from.get());
            if (!ptr)
            {
                return nullptr;
            }
            return unique_ptr<To>{ static_cast<To *>(from.release()) };
        }
    }

    namespace receiver
    {
        bool Query::has_request() const noexcept
        {
            return dynamic_cast<const SenderOperationQuery*>(sop_.get());
        }

        const SenderOperationQuery &Query::request_data() const
        {
            if (!has_request())
            {
                throw logic_error("query data is invalid");
            }

            return *static_cast<const SenderOperationQuery*>(sop_.get());
        }

        Query Query::deep_copy() const
        {
            Query result;
            result.item_count_ = item_count_;
            result.table_idx_to_item_idx_ = table_idx_to_item_idx_;

            const SenderOperationQuery *this_query = dynamic_cast<const SenderOperationQuery*>(sop_.get());
            if (this_query)
            {
                auto sop_query = make_unique<SenderOperationQuery>();
                sop_query->relin_keys = this_query->relin_keys;
                sop_query->data = this_query->data;
                result.sop_ = move(sop_query);
            }

            return result;
        }

        unique_ptr<SenderOperation> Query::extract_request()
        {
            if (!has_request())
            {
                return nullptr;
            }

            return std::move(sop_);
        }

        Receiver::Receiver(PSIParams params, size_t thread_count) : params_(move(params))
        {
            thread_count_ = thread_count < 1 ? thread::hardware_concurrency() : thread_count;

            initialize();
        }

        void Receiver::reset_keys()
        {
            // Generate new keys
            KeyGenerator generator(*crypto_context_->seal_context());

            // Set the symmetric key, encryptor, and decryptor
            crypto_context_->set_secret(generator.secret_key());

            // Create Serializable<RelinKeys> and move to relin_keys_ for storage
            Serializable<RelinKeys> relin_keys(generator.create_relin_keys());
            relin_keys_.set(move(relin_keys));
        }

        void Receiver::initialize()
        {
            APSI_LOG_INFO("Initializing Receiver with " << thread_count_ << " threads");
            APSI_LOG_DEBUG("PSI parameters set to: " << params_.to_string());
            APSI_LOG_DEBUG("Derived parameters: "
                << "item_bit_count_per_felt: " << params_.item_bit_count_per_felt()
                << "; item_bit_count: " << params_.item_bit_count()
                << "; bins_per_bundle: " << params_.bins_per_bundle()
                << "; bundle_idx_count: " << params_.bundle_idx_count());

            STOPWATCH(recv_stopwatch, "Receiver::initialize");

            // Initialize the CryptoContext with a new SEALContext
            crypto_context_ = make_shared<CryptoContext>(params_.seal_params());
            if (!crypto_context_->seal_context()->parameters_set())
            {
                APSI_LOG_ERROR("Given SEALParams are invalid: "
                    << crypto_context_->seal_context()->parameter_error_message());
                throw logic_error("SEALParams are invalid");
            }
            if (!crypto_context_->seal_context()->first_context_data()->qualifiers().using_batching)
            {
                APSI_LOG_ERROR("Given SEALParams do not support batching");
                throw logic_error("given SEALParams do not support batching");
            }

            // Set up the PowersDag
            pd_ = optimal_powers(params_.table_params().max_items_per_bin, params_.query_params().query_powers_count);
            APSI_LOG_INFO("Found a powers configuration with depth: " << pd_.depth());

            // Create new keys
            reset_keys();
        }

        unique_ptr<SenderOperation> Receiver::CreateParamsRequest()
        {
            auto sop = make_unique<SenderOperationParms>();
            APSI_LOG_INFO("Created parameter request");

            return sop;
        }

        bool Receiver::SendRequest(unique_ptr<SenderOperation> sop, Channel &chl)
        {
            STOPWATCH(recv_stopwatch, "Receiver::SendRequest");

            if (!sop)
            {
                APSI_LOG_ERROR("Failed to send request: operation is null");
                return false;
            }

            const char *sop_str = sender_operation_type_str(sop->type());
            APSI_LOG_INFO("Sending request of type: " << sop_str);

            try
            {
                auto bytes_sent = chl.bytes_sent();
                chl.send(move(sop));
                bytes_sent = chl.bytes_sent() - bytes_sent;
                APSI_LOG_INFO("Sent " << bytes_sent << " B");
                APSI_LOG_INFO("Finished sending request of type: " << sop_str);
            }
            catch (const exception &ex)
            {
                APSI_LOG_ERROR("Sending request caused channel to throw an exception: " << ex.what());
                return false;
            }
            return true;
        }

        ParamsResponse Receiver::ReceiveParamsResponse(Channel &chl)
        {
            STOPWATCH(recv_stopwatch, "Receiver::ReceiveParamsResponse");

            auto bytes_received = chl.bytes_received();
            auto sop_response = chl.receive_response(SenderOperationType::sop_parms);
            bytes_received = chl.bytes_received() - bytes_received;
            APSI_LOG_INFO("Received " << bytes_received << " B");

            if (!sop_response)
            {
                APSI_LOG_ERROR("Failed to receive response to parameter request");
                return nullptr;
            }

            // The response type must be SenderOperationType::sop_parms
            ParamsResponse response = downcast_ptr<SenderOperationResponseParms, SenderOperationResponse>(move(sop_response));
            if (!response->params)
            {
                APSI_LOG_ERROR("Missing data from response to parameter request");
                return nullptr;
            }

            // Extract the parameters from the response object
            if (logging::Log::get_log_level() <= logging::Log::Level::debug)
            {
                APSI_LOG_DEBUG("Received valid parameters: " << endl << response->params->to_string());
            }
            else
            {
                APSI_LOG_INFO("Received valid parameters");
            }

            return response;
        }

        PSIParams Receiver::RequestParams(NetworkChannel &chl)
        {
            // Create parameter request and send to Sender
            auto sop_parms = CreateParamsRequest();
            if (!SendRequest(move(sop_parms), chl))
            {
                throw runtime_error("failed to send parameter request");
            }

            // Wait for a valid message of the correct type
            ParamsResponse response;
            while (!(response = ReceiveParamsResponse(chl)));

            return *response->params;
        }

        OPRFReceiver Receiver::CreateOPRFReceiver(const vector<Item> &items)
        {
            STOPWATCH(recv_stopwatch, "Receiver::CreateOPRFReceiver");

            OPRFReceiver oprf_receiver(items);
            APSI_LOG_INFO("Created OPRFReceiver for " << oprf_receiver.item_count() << " items");

            return oprf_receiver;
        }

        vector<HashedItem> Receiver::ExtractHashes(
            const OPRFResponse &oprf_response,
            const OPRFReceiver &oprf_receiver)
        {
            STOPWATCH(recv_stopwatch, "Receiver::ExtractHashes");

            if (!oprf_response)
            {
                APSI_LOG_ERROR("Failed to extract OPRF hashes for items: OPRF response is null");
                return {};
            }
            
            auto response_size = oprf_response->data.size();
            size_t oprf_response_item_count = response_size / oprf_response_size;
            if ((response_size % oprf_response_size) || (oprf_response_item_count != oprf_receiver.item_count()))
            {
                APSI_LOG_ERROR("Failed to extract OPRF hashes for items: unexpected OPRF response size (" << response_size << " B)");
                return {};
            }

            vector<HashedItem> items(oprf_receiver.item_count());
            oprf_receiver.process_responses(oprf_response->data, items);
            APSI_LOG_INFO("Extracted OPRF hashes for " << oprf_response_item_count << " items");

            return items;
        }

        unique_ptr<SenderOperation> Receiver::CreateOPRFRequest(const vector<Item> &items, const OPRFReceiver &oprf_receiver)
        {
            auto sop = make_unique<SenderOperationOPRF>();
            sop->data = oprf_receiver.query_data();
            APSI_LOG_INFO("Created OPRF request");

            return sop;
        }

        OPRFResponse Receiver::ReceiveOPRFResponse(Channel &chl)
        {
            STOPWATCH(recv_stopwatch, "Receiver::ReceiveOPRFResponse");

            auto bytes_received = chl.bytes_received();
            auto sop_response = chl.receive_response(SenderOperationType::sop_oprf);
            bytes_received = chl.bytes_received() - bytes_received;
            APSI_LOG_INFO("Received " << bytes_received << " B");

            if (!sop_response)
            {
                APSI_LOG_ERROR("Failed to receive OPRF response");
                return nullptr;
            }

            // The response type must be SenderOperationType::sop_oprf
            OPRFResponse response = downcast_ptr<SenderOperationResponseOPRF>(move(sop_response));

            auto response_size = response->data.size();
            if (response_size % oprf_response_size)
            {
                APSI_LOG_ERROR("Failed to process OPRF response: data has invalid size (" << response_size << " B)");
                return nullptr;
            }
            APSI_LOG_INFO("Received OPRF response for " << response_size / oprf_response_size << " items");

            return response;
        }

        vector<HashedItem> Receiver::RequestOPRF(const vector<Item> &items, NetworkChannel &chl)
        {
            auto oprf_receiver = CreateOPRFReceiver(items);

            // Create OPRF request and send to Sender
            auto sop_oprf = CreateOPRFRequest(items, oprf_receiver);
            if (!SendRequest(move(sop_oprf), chl))
            {
                throw runtime_error("failed to send OPRF request");
            }

            // Wait for a valid message of the correct type
            OPRFResponse response;
            while (!(response = ReceiveOPRFResponse(chl)));

            // Extract the OPRF hashed items
            vector<HashedItem> oprf_items = ExtractHashes(response, oprf_receiver);

            return oprf_items;
        }

        Query Receiver::create_query(const vector<HashedItem> &items)
        {
            APSI_LOG_INFO("Creating encrypted query for " << items.size() << " items");
            STOPWATCH(recv_stopwatch, "Receiver::create_query");

            Query query;
            query.item_count_ = items.size();

            // Create the cuckoo table
            KukuTable cuckoo(
                params_.table_params().table_size,      // Size of the hash table
                0,                                       // Not using a stash
                params_.table_params().hash_func_count, // Number of hash functions
                { 0, 0 },                                // Hardcoded { 0, 0 } as the seed
                cuckoo_table_insert_attempts,            // The number of insertion attempts 
                { 0, 0 });                               // The empty element can be set to anything

            // Hash the data into a cuckoo hash table
            // cuckoo_hashing
            {
                STOPWATCH(recv_stopwatch, "Receiver::create_query::cuckoo_hashing");
                APSI_LOG_DEBUG("Inserting " << items.size()
                    << " items into cuckoo table of size " << cuckoo.table_size()
                    << " with " << cuckoo.loc_func_count() << " hash functions");
                for (size_t item_idx = 0; item_idx < items.size(); item_idx++)
                {
                    auto &item = items[item_idx];
                    if (!cuckoo.insert(items[item_idx].value()))
                    {
                        // Insertion can fail for two reasons:
                        //
                        //     (1) The item was already in the table, in which case the "leftover item" is empty;
                        //     (2) Cuckoo hashing failed due to too small table or too few hash functions.
                        //
                        // In case (1) simply move on to the next item and log this issue. Case (2) is a critical issue
                        // so we throw and exception.
                        if (cuckoo.is_empty_item(cuckoo.leftover_item()))
                        {
                            APSI_LOG_INFO(
                                "Skipping repeated insertion of items[" << item_idx << "]: " << item.to_string());
                        }
                        else
                        {
                            APSI_LOG_ERROR("Failed to insert items[" << item_idx << "]: " << item.to_string()
                                << "; cuckoo table fill-rate: " << cuckoo.fill_rate());
                            throw runtime_error("failed to insert item into cuckoo table");
                        }
                    }
                }
                APSI_LOG_DEBUG("Finished inserting items with " << cuckoo.loc_func_count()
                    << " hash functions; cuckoo table fill-rate: " << cuckoo.fill_rate());
            }

            // Once the table is filled, fill the table_idx_to_item_idx map
            for (size_t item_idx = 0; item_idx < items.size(); item_idx++)
            {
                auto item_loc = cuckoo.query(items[item_idx].value());
                query.table_idx_to_item_idx_[item_loc.location()] = item_idx;
            }

            // Set up unencrypted query data
            vector<PlaintextPowers> plain_powers;

            // prepate_data
            {
                STOPWATCH(recv_stopwatch, "Receiver::create_query::prepare_data");
                for (uint32_t bundle_idx = 0; bundle_idx < params_.bundle_idx_count(); bundle_idx++)
                {
                    APSI_LOG_DEBUG("Preparing data for bundle index " << bundle_idx);

                    // First, find the items for this bundle index
                    gsl::span<const item_type> bundle_items(
                        cuckoo.table().data() + bundle_idx * params_.items_per_bundle(),
                        params_.items_per_bundle());

                    vector<uint64_t> alg_items;
                    for (auto &item : bundle_items)
                    {
                        // Now set up a BitstringView to this item    
                        gsl::span<const seal_byte> item_bytes(
                            reinterpret_cast<const seal_byte*>(item.data()), sizeof(item));
                        BitstringView<const seal_byte> item_bits(item_bytes, params_.item_bit_count());

                        // Create an algebraic item by breaking up the item into modulo plain_modulus parts
                        vector<uint64_t> alg_item = bits_to_field_elts(item_bits, params_.seal_params().plain_modulus());
                        copy(alg_item.cbegin(), alg_item.cend(), back_inserter(alg_items));
                    }

                    // Now that we have the algebraized items for this bundle index, we create a PlaintextPowers object that
                    // computes all necessary powers of the algebraized items.
                    plain_powers.emplace_back(move(alg_items), params_, pd_);
                }
            }

            // The very last thing to do is encrypt the plain_powers and consolidate the matching powers for different
            // bundle indices
            unordered_map<uint32_t, vector<SEALObject<Ciphertext>>> encrypted_powers;

            // encrypt_data
            {
                STOPWATCH(recv_stopwatch, "Receiver::create_query::encrypt_data");
                for (uint32_t bundle_idx = 0; bundle_idx < params_.bundle_idx_count(); bundle_idx++)
                {
                    APSI_LOG_DEBUG("Encoding and encrypting data for bundle index " << bundle_idx);

                    // Encrypt the data for this power
                    auto encrypted_power(plain_powers[bundle_idx].encrypt(*crypto_context_));

                    // Move the encrypted data to encrypted_powers
                    for (auto &e : encrypted_power)
                    {
                        encrypted_powers[e.first].emplace_back(move(e.second));
                    }
                }
            }

            // Set up the return value
            auto sop_query = make_unique<SenderOperationQuery>();
            sop_query->relin_keys = relin_keys_;
            sop_query->data = move(encrypted_powers);
            sop_query->pd = pd_;
            query.sop_ = move(sop_query);

            APSI_LOG_INFO("Finished creating encrypted query");

            return query;
        }

        QueryResponse Receiver::ReceiveQueryResponse(Channel &chl)
        {
            STOPWATCH(recv_stopwatch, "Receiver::ReceiveQueryResponse");

            auto bytes_received = chl.bytes_received();
            auto sop_response = chl.receive_response(SenderOperationType::sop_query);
            bytes_received = chl.bytes_received() - bytes_received;
            APSI_LOG_INFO("Received " << bytes_received << " B");

            if (!sop_response)
            {
                APSI_LOG_ERROR("Failed to receive response to query request");
                return nullptr;
            }

            // The response type must be SenderOperationType::sop_query
            QueryResponse response = downcast_ptr<SenderOperationResponseQuery>(move(sop_response));
            APSI_LOG_INFO("Received query response: expecting " << response->package_count << " result packages");

            return response;
        }

        vector<MatchRecord> Receiver::request_query(const vector<HashedItem> &items, NetworkChannel &chl)
        {
            // Create query and send to Sender
            auto query = create_query(items);
            if (!SendRequest(query.extract_request(), chl))
            {
                throw runtime_error("failed to send query request");
            }

            // Wait for query response
            QueryResponse response;
            while (!(response = ReceiveQueryResponse(chl)));

            // Set up the result
            vector<MatchRecord> mrs(query.item_count_);

            // Get the number of ResultPackages we expect to receive
            atomic<int32_t> package_count{ safe_cast<int32_t>(response->package_count) };

            // Launch threads to receive ResultPackages and decrypt results
            vector<thread> threads;
            for (size_t t = 0; t < thread_count_; t++)
            {
                threads.emplace_back([&, t]() {
                    result_package_worker(package_count, mrs, query.table_idx_to_item_idx_, chl);
                });
            }

            for (auto &t : threads)
            {
                t.join();
            }

            APSI_LOG_INFO("Found " << accumulate(mrs.begin(), mrs.end(), 0,
                [](auto acc, auto &curr) { return acc + curr.found; }) << " matches");

            return mrs;
        }

        void Receiver::result_package_worker(
            atomic<int32_t> &package_count,
            vector<MatchRecord> &mrs,
            const unordered_map<size_t, size_t> &table_idx_to_item_idx,
            Channel &chl) const
        {
            stringstream sw_ss;
            sw_ss << "Receiver::result_package_worker [" << this_thread::get_id() << "]";
            STOPWATCH(recv_stopwatch, sw_ss.str());

            APSI_LOG_INFO("Result worker [" << this_thread::get_id() << "]: starting");

            while (true)
            {
                // Return if all packages have been claimed
                package_count--;
                if (package_count < 0)
                {
                    APSI_LOG_INFO("Result worker [" << this_thread::get_id() << "]: all packages claimed; exiting");
                    return;
                }

                // Wait for a valid ResultPackage
                unique_ptr<ResultPackage> rp;
                while (!(rp = chl.receive_result_package(crypto_context_->seal_context())));
                APSI_LOG_DEBUG("Result worker [" << this_thread::get_id() << "]: "
                    "result package received for bundle index " << rp->bundle_idx);

                // Decrypt and decode the result; the result vector will have full batch size
                PlainResultPackage plain_rp = rp->extract(*crypto_context_);

                // Iterate over the decoded data to find consecutive zeros indicating a match
                StrideIter<const uint64_t *> plain_rp_iter(
                    plain_rp.psi_result.data(), params_.item_params().felts_per_item);
                size_t felts_per_item = safe_cast<size_t>(params_.item_params().felts_per_item);
                size_t bundle_start = safe_cast<size_t>(mul_safe(plain_rp.bundle_idx, params_.items_per_bundle()));
                SEAL_ITERATE(iter(plain_rp_iter, size_t(0)), params_.items_per_bundle(), [&](auto I) {
                    // Find felts_per_item consecutive zeros
                    bool match = all_of(get<0>(I), get<0>(I) + felts_per_item, [](auto felt) { return felt == 0; });
                    if (!match)
                    {
                        return;
                    }

                    // Compute the cuckoo table index for this item 
                    size_t table_idx = add_safe(get<1>(I), bundle_start);

                    // Next find the corresponding index in the input items vector
                    auto item_idx_iter = table_idx_to_item_idx.find(table_idx);

                    // If this table_idx doesn't match any item_idx, ignore the result no matter what it is
                    if (item_idx_iter == table_idx_to_item_idx.cend())
                    {
                        return;
                    }

                    size_t item_idx = item_idx_iter->second;
                    APSI_LOG_DEBUG("Result worker [" << this_thread::get_id() << "]: "
                        "match found for items[" << item_idx << "] at cuckoo table index " << table_idx);
                    if (mrs[item_idx])
                    {
                        // If a positive MatchRecord is already present, then something is seriously wrong
                        APSI_LOG_ERROR("Result worker [" << this_thread::get_id() << "]: "
                            "found a match for cuckoo table index " << table_idx <<
                            " but an existing match for this location was already found before");

                        throw runtime_error("found a pre-existing positive match in the location for this match");
                    }

                    // Create a new MatchRecord
                    MatchRecord mr;
                    mr.found = true;

                    // Next, extract the label result(s), if any
                    if (!plain_rp.label_result.empty())
                    {
                        APSI_LOG_DEBUG("Result worker [" << this_thread::get_id() << "]: "
                            "found " << plain_rp.label_result.size() << "-part label for items[" << item_idx << "]");

                        // Collect the entire label into this vector
                        vector<felt_t> label_as_felts;

                        for (auto &label_parts : plain_rp.label_result)
                        {
                            size_t label_offset = mul_safe(get<1>(I), felts_per_item);
                            gsl::span<felt_t> label_part(
                                label_parts.data() + label_offset, params_.item_params().felts_per_item);
                            copy(label_part.begin(), label_part.end(), back_inserter(label_as_felts));
                        }

                        // Create the label
                        auto label = make_unique<Bitstring>(field_elts_to_bits(
                            label_as_felts,
                            params_.item_bit_count(),
                            params_.seal_params().plain_modulus()));

                        // Set the label
                        mr.label.set(move(label));
                    }

                    // We are done with the MatchRecord, so add it to the mrs vector
                    mrs[item_idx] = move(mr);
                });
            }
        }
    } // namespace receiver
} // namespace apsi
