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

        template<typename T>
        bool has_n_zeros(T *ptr, size_t count)
        {
            return all_of(ptr, ptr + count, [](auto a) { return a == T(0); });
        }
    }

    namespace receiver
    {
        size_t IndexTranslationTable::find_item_idx(size_t table_idx) const noexcept
        {
            auto item_idx = table_idx_to_item_idx_.find(table_idx);
            if (item_idx == table_idx_to_item_idx_.cend())
            {
                return item_count();
            }

            return item_idx->second;
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

        PSIParams Receiver::RequestParams(NetworkChannel &chl)
        {
            // Create parameter request and send to Sender
            chl.send(CreateParamsRequest());

            // Wait for a valid message of the correct type
            ParamsResponse response;
            bool logged_waiting = false;
            while (!(response = to_params_response(chl.receive_response())))
            {
                if (!logged_waiting)
                {
                    // We want to log 'Waiting' only once, even if we have to wait for several sleeps.
                    logged_waiting = true;
                    APSI_LOG_INFO("Waiting for response to parameter request");
                }

                this_thread::sleep_for(50ms);
            }

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
                APSI_LOG_ERROR("Failed to extract OPRF hashes for items: oprf_response is null");
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

        unique_ptr<SenderOperation> Receiver::CreateOPRFRequest(const OPRFReceiver &oprf_receiver)
        {
            auto sop = make_unique<SenderOperationOPRF>();
            sop->data = oprf_receiver.query_data();
            APSI_LOG_INFO("Created OPRF request");

            return sop;
        }

        vector<HashedItem> Receiver::RequestOPRF(const vector<Item> &items, NetworkChannel &chl)
        {
            auto oprf_receiver = CreateOPRFReceiver(items);

            // Create OPRF request and send to Sender
            chl.send(CreateOPRFRequest(oprf_receiver));

            // Wait for a valid message of the correct type
            OPRFResponse response;
            bool logged_waiting = false;
            while (!(response = to_oprf_response(chl.receive_response())))
            {
                if (!logged_waiting)
                {
                    // We want to log 'Waiting' only once, even if we have to wait for several sleeps.
                    logged_waiting = true;
                    APSI_LOG_INFO("Waiting for response to OPRF request");
                }

                this_thread::sleep_for(50ms);
            }

            // Extract the OPRF hashed items
            vector<HashedItem> oprf_items = ExtractHashes(response, oprf_receiver);

            return oprf_items;
        }

        pair<Request, IndexTranslationTable> Receiver::create_query(const vector<HashedItem> &items)
        {
            APSI_LOG_INFO("Creating encrypted query for " << items.size() << " items");
            STOPWATCH(recv_stopwatch, "Receiver::create_query");

            IndexTranslationTable itt;
            itt.item_count_ = items.size();

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
                itt.table_idx_to_item_idx_[item_loc.location()] = item_idx;
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
            auto sop = to_request(move(sop_query));

            APSI_LOG_INFO("Finished creating encrypted query");

            return { move(sop), itt };
        }

        ResultPart Receiver::receive_result(Channel &chl) const
        {
            STOPWATCH(recv_stopwatch, "Receiver::receive_result");

            auto bytes_received = chl.bytes_received();
            auto rp = chl.receive_result_package(crypto_context_->seal_context());
            bytes_received = chl.bytes_received() - bytes_received;
            APSI_LOG_INFO("Received " << bytes_received << " B");

            if (!rp)
            {
                APSI_LOG_ERROR("Failed to receive result package");
                return {};
            }

            APSI_LOG_INFO("Received result package for bundle index " << rp->bundle_idx);
            return rp;
        }

        vector<MatchRecord> Receiver::request_query(const vector<HashedItem> &items, NetworkChannel &chl)
        {
            // Create query and send to Sender
            auto query = create_query(items);
            chl.send(move(query.first));
            auto itt = move(query.second);

            // Wait for query response
            QueryResponse response;
            bool logged_waiting = false;
            while (!(response = to_query_response(chl.receive_response())))
            {
                if (!logged_waiting)
                {
                    // We want to log 'Waiting' only once, even if we have to wait for several sleeps.
                    logged_waiting = true;
                    APSI_LOG_INFO("Waiting for response to query request");
                }

                this_thread::sleep_for(50ms);
            }

            // Set up the result
            vector<MatchRecord> mrs(query.second.item_count());

            // Get the number of ResultPackages we expect to receive
            atomic<int32_t> package_count{ safe_cast<int32_t>(response->package_count) };

            // Launch threads to receive ResultPackages and decrypt results
            vector<thread> threads;
            APSI_LOG_INFO("Launching " << thread_count_ << " result worker threads");
            for (size_t t = 0; t < thread_count_; t++)
            {
                threads.emplace_back([&, t]() {
                    process_result_worker(package_count, mrs, itt, chl);
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

        vector<MatchRecord> Receiver::process_result_part(
            const IndexTranslationTable &itt,
            const ResultPart &result_part) const
        {
            STOPWATCH(recv_stopwatch, "Receiver::process_result_part");

            if (!result_part)
            {
                APSI_LOG_ERROR("Failed to process result: result_part is null");
                return {};
            }

            // Decrypt and decode the result; the result vector will have full batch size
            PlainResultPackage plain_rp = result_part->extract(*crypto_context_);

            size_t felts_per_item = safe_cast<size_t>(params_.item_params().felts_per_item);
            size_t items_per_bundle = safe_cast<size_t>(params_.items_per_bundle());
            size_t bundle_start = mul_safe(safe_cast<size_t>(plain_rp.bundle_idx), items_per_bundle);

            // Set up the result vector
            vector<MatchRecord> mrs(itt.item_count());

            // Iterate over the decoded data to find consecutive zeros indicating a match
            StrideIter<const uint64_t *> plain_rp_iter(plain_rp.psi_result.data(), felts_per_item);
            SEAL_ITERATE(iter(plain_rp_iter, size_t(0)), items_per_bundle, [&](auto I) {
                // Find felts_per_item consecutive zeros
                bool match = has_n_zeros(get<0>(I).ptr(), felts_per_item);
                if (!match)
                {
                    return;
                }

                // Compute the cuckoo table index for this item. Then find the corresponding index in the input
                // items vector so we know where to place the result.
                size_t table_idx = add_safe(get<1>(I), bundle_start);
                auto item_idx = itt.find_item_idx(table_idx);

                // If this table_idx doesn't match any item_idx, ignore the result no matter what it is
                if (item_idx == itt.item_count())
                {
                    return;
                }

                // If a positive MatchRecord is already present, then something is seriously wrong
                if (mrs[item_idx])
                {
                    APSI_LOG_ERROR("The table index -> item index translation table indicated a location that was "
                        "already filled by another match from this result package; the translation table (query) "
                        "has probably been corrupted");

                    throw runtime_error("found a duplicate positive match; something is seriously wrong");
                }

                APSI_LOG_DEBUG("Match found for items[" << item_idx << "] at cuckoo table index " << table_idx);

                // Create a new MatchRecord
                MatchRecord mr;
                mr.found = true;

                // Next, extract the label result(s), if any
                if (!plain_rp.label_result.empty())
                {
                    APSI_LOG_DEBUG("Found " << plain_rp.label_result.size() << "-part label for items[" << item_idx << "]");

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

            return mrs;
        }

        vector<MatchRecord> Receiver::process_result(
            const IndexTranslationTable &itt,
            const vector<ResultPart> &result) const
        {
            APSI_LOG_INFO("Processing " << result.size() << " result parts");
            STOPWATCH(recv_stopwatch, "Receiver::process_result");

            vector<MatchRecord> mrs(itt.item_count());

            for (auto &result_part : result)
            {
                auto this_mrs = process_result_part(itt, result_part);
                if (this_mrs.size() != mrs.size())
                {
                    // Something went wrong with process_result; error is already logged
                    continue;
                }

                // Merge the new MatchRecords with mrs
                SEAL_ITERATE(iter(mrs, this_mrs, size_t(0)), mrs.size(), [](auto I) {
                    if (get<1>(I) && !get<0>(I))
                    {
                        // This match needs to be merged into mrs
                        get<0>(I) = move(get<1>(I));
                    }
                    else if (get<1>(I) && get<0>(I))
                    {
                        // If a positive MatchRecord is already present, then something is seriously wrong
                        APSI_LOG_ERROR("Found a match for items[" << get<2>(I) << "] but an existing match for this "
                            "location was already found before from a different result part");

                        throw runtime_error("found a duplicate positive match; something is seriously wrong");
                    }
                });
            }

            APSI_LOG_INFO("Found " << accumulate(mrs.begin(), mrs.end(), 0,
                [](auto acc, auto &curr) { return acc + curr.found; }) << " matches");

            return mrs;
        }

        void Receiver::process_result_worker(
            atomic<int32_t> &package_count,
            vector<MatchRecord> &mrs,
            const IndexTranslationTable &itt,
            Channel &chl) const
        {
            stringstream sw_ss;
            sw_ss << "Receiver::process_result_worker [" << this_thread::get_id() << "]";
            STOPWATCH(recv_stopwatch, sw_ss.str());

            APSI_LOG_DEBUG("Result worker [" << this_thread::get_id() << "]: starting");

            while (true)
            {
                // Return if all packages have been claimed
                package_count--;
                if (package_count < 0)
                {
                    APSI_LOG_DEBUG("Result worker [" << this_thread::get_id() << "]: all packages claimed; exiting");
                    return;
                }

                // Wait for a valid ResultPart
                ResultPart result_part;
                while (!(result_part = receive_result(chl)));

                // Process the ResultPart to get the corresponding vector of MatchRecords
                auto this_mrs = process_result_part(itt, result_part);

                // Merge the new MatchRecords with mrs
                SEAL_ITERATE(iter(mrs, this_mrs, size_t(0)), mrs.size(), [](auto I) {
                    if (get<1>(I) && !get<0>(I))
                    {
                        // This match needs to be merged into mrs
                        get<0>(I) = move(get<1>(I));
                    }
                    else if (get<1>(I) && get<0>(I))
                    {
                        // If a positive MatchRecord is already present, then something is seriously wrong
                        APSI_LOG_ERROR("Result worker [" << this_thread::get_id() << "]: "
                            "found a match for items[" << get<2>(I) << "] "
                            "but an existing match for this location was already found before from a different result "
                            "part");

                        throw runtime_error("found a duplicate positive match; something is seriously wrong");
                    }
                });
            }
        }
    } // namespace receiver
} // namespace apsi
