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

                APSI_LOG_DEBUG("Plaintext powers computed:" << [&]() {
                        stringstream ss;
                        for (auto &a : powers_)
                        {
                            ss << " " << a.first;
                        }
                        return ss.str();
                    }());
            }
        };
    }

    namespace receiver
    {
        Receiver::Receiver(PSIParams params, size_t thread_count) : params_(move(params))
        {
            thread_count_ = thread_count < 1 ? thread::hardware_concurrency() : thread_count;

            initialize();
        }

        void Receiver::reset_keys()
        {
            // Generate new keys
            KeyGenerator generator(crypto_context_->seal_context());

            // Set the symmetric key, encryptor, and decryptor
            crypto_context_->set_secret(generator.secret_key());

            // Create Serializable<RelinKeys> and move to relin_keys_ for storage
            Serializable<RelinKeys> relin_keys(generator.relin_keys());
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
            crypto_context_ = make_shared<CryptoContext>(SEALContext::Create(params_.seal_params()));

            // Set up the PowersDag
            pd_ = optimal_powers(params_.table_params().max_items_per_bin, params_.query_params().query_powers_count);
            APSI_LOG_INFO("Found a powers configuration with depth: " << pd_.depth());

            // Create new keys
            reset_keys();
        }

        PSIParams Receiver::request_params(Channel &chl)
        {
            APSI_LOG_INFO("Requesting parameters from Sender");
            STOPWATCH(recv_stopwatch, "Receiver::request_params");

            // Send parameter request to Sender
            auto sop_parms = make_unique<SenderOperationParms>();
            chl.send(move(sop_parms));

            unique_ptr<SenderOperationResponse> response;

            // wait_response
            {
                STOPWATCH(recv_stopwatch, "Receiver::request_params::wait_response");

                // Wait for a valid message of the correct type
                while (!(response = chl.receive_response(SenderOperationType::SOP_PARMS)));
            }

            // Return the PSIParams
            auto parms_response = dynamic_cast<SenderOperationResponseParms*>(response.get());
            PSIParams parms = *parms_response->params;

            APSI_LOG_DEBUG("Received parameters:" << endl << parms.to_string());

            return parms;
        }

        vector<SEAL_BYTE> Receiver::obfuscate_items(const vector<Item> &items, unique_ptr<OPRFReceiver> &oprf_receiver)
        {
            APSI_LOG_INFO("Obfuscating items");
            STOPWATCH(recv_stopwatch, "Receiver::obfuscate_items");

            vector<SEAL_BYTE> oprf_query;
            oprf_query.resize(items.size() * oprf_query_size);
            oprf_receiver = make_unique<OPRFReceiver>(items, oprf_query);

            return oprf_query;
        }

        vector<HashedItem> Receiver::deobfuscate_items(
            const vector<SEAL_BYTE> &oprf_response,
            unique_ptr<OPRFReceiver> &oprf_receiver)
        {
            APSI_LOG_INFO("Deobfuscating items");
            STOPWATCH(recv_stopwatch, "Receiver::deobfuscate_items");

            vector<HashedItem> items(oprf_receiver->item_count());
            oprf_receiver->process_responses(oprf_response, items);
            oprf_receiver.reset();

            return items;
        }

        vector<HashedItem> Receiver::request_oprf(const vector<Item> &items, Channel &chl)
        {
            APSI_LOG_INFO("Starting OPRF request for " << items.size() << " items");
            STOPWATCH(recv_stopwatch, "Receiver::oprf");

            unique_ptr<OPRFReceiver> oprf_receiver = nullptr;

            // Send OPRF query to Sender
            auto sop_oprf = make_unique<SenderOperationOPRF>();
            sop_oprf->data = move(obfuscate_items(items, oprf_receiver));
            APSI_LOG_DEBUG("OPRF request created");
            chl.send(move(sop_oprf));
            APSI_LOG_DEBUG("OPRF request sent");

            unique_ptr<SenderOperationResponse> response;
            {
                STOPWATCH(recv_stopwatch, "Receiver::oprf::wait_response");

                // Wait for a valid message of the correct type
                APSI_LOG_DEBUG("Waiting for OPRF response");
                while (!(response = chl.receive_response(SenderOperationType::SOP_OPRF)));
            }
            APSI_LOG_DEBUG("OPRF response received");

            // Extract the OPRF response
            auto &oprf_response = dynamic_cast<SenderOperationResponseOPRF*>(response.get())->data;
            vector<HashedItem> oprf_items = deobfuscate_items(oprf_response, oprf_receiver);
            APSI_LOG_INFO("Finished OPRF request");

            return oprf_items;
        }

        Query Receiver::create_query(const vector<HashedItem> &items)
        {
            APSI_LOG_INFO("Creating encrypted query");
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
                    APSI_LOG_DEBUG("Preparing data for bundle index "
                        << bundle_idx << " / " << params_.bundle_idx_count() - 1);

                    // First, find the items for this bundle index
                    gsl::span<const item_type> bundle_items(
                        cuckoo.table().data() + bundle_idx * params_.items_per_bundle(),
                        params_.items_per_bundle());

                    vector<uint64_t> alg_items;
                    for (auto &item : bundle_items)
                    {
                        // Now set up a BitstringView to this item    
                        gsl::span<const SEAL_BYTE> item_bytes(
                            reinterpret_cast<const SEAL_BYTE*>(item.data()), sizeof(item));
                        BitstringView<const SEAL_BYTE> item_bits(item_bytes, params_.item_bit_count());

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
                    APSI_LOG_DEBUG("Encoding and encrypting data for bundle index "
                        << bundle_idx << " / " << params_.bundle_idx_count() - 1);

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

        vector<MatchRecord> Receiver::request_query(Query &&query, Channel &chl)
        {
            APSI_LOG_INFO("Starting query for " << query.item_count_ << " items");
            STOPWATCH(recv_stopwatch, "Receiver::query");

            chl.send(move(query.sop_));
            APSI_LOG_DEBUG("Query request sent");

            // Wait for query response
            unique_ptr<SenderOperationResponse> response;
            {
                STOPWATCH(recv_stopwatch, "Receiver::query::wait_response");

                // Wait for a valid message of the correct type
                while (!(response = chl.receive_response(SenderOperationType::SOP_QUERY)));
            }
            APSI_LOG_DEBUG("Query response received");

            // Set up the result
            vector<MatchRecord> mrs(query.item_count_);

            // Get the number of ResultPackages we expect to receive
            auto query_response = dynamic_cast<SenderOperationResponseQuery*>(response.get());
            atomic<int32_t> package_count = safe_cast<int32_t>(query_response->package_count);

            APSI_LOG_INFO("Expecting " << package_count << " result packages from Sender");

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
            APSI_LOG_INFO("Finished query");

            return mrs;
        }

        void Receiver::result_package_worker(
            atomic<int32_t> &package_count,
            vector<MatchRecord> &mrs,
            const unordered_map<size_t, size_t> &table_idx_to_item_idx,
            Channel &chl) const
        {
            APSI_LOG_DEBUG("Launched result worker thread " << this_thread::get_id());
            STOPWATCH(recv_stopwatch, "Receiver::query::result_package_worker");

            while (true)
            {
                // Return if all packages have been claimed
                package_count--;
                if (package_count < 0)
                {
                    APSI_LOG_DEBUG("Result worker thread " << this_thread::get_id() << " exiting");
                    return;
                }

                // Wait for a valid ResultPackage
                unique_ptr<ResultPackage> rp;
                while (!(rp = chl.receive_result_package(crypto_context_->seal_context())));
                APSI_LOG_DEBUG("Result package received for bundle index " << rp->bundle_idx
                    << " (thread " << this_thread::get_id() << ")");

                // Decrypt and decode the result; the result vector will have full batch size
                PlainResultPackage plain_rp = rp->extract(*crypto_context_);

                // Iterate over the decoded data to find consecutive zeros indicating a match
                StrideIter<const uint64_t *> plain_rp_iter(
                    plain_rp.psi_result.data(), params_.item_params().felts_per_item);
                size_t felts_per_item = safe_cast<size_t>(params_.item_params().felts_per_item);
                size_t bundle_start = safe_cast<size_t>(mul_safe(plain_rp.bundle_idx, params_.items_per_bundle()));
                SEAL_ITERATE(iter(plain_rp_iter, size_t(0)), params_.items_per_bundle(), [&](auto I) {
                    // Compute the cuckoo table index for this item 
                    size_t table_idx = add_safe(get<1>(I), bundle_start);

                    // Next find the corresponding index in the input items vector
                    auto item_idx_iter = table_idx_to_item_idx.find(table_idx);

                    // If this table_idx doesn't match any item_idx, ignore the result no matter what it is
                    if (item_idx_iter == table_idx_to_item_idx.cend())
                    {
                        return;
                    }
                    // Find felts_per_item consecutive zeros
                    bool match = all_of(get<0>(I), get<0>(I) + felts_per_item, [](auto felt) { return felt == 0; });
                    if (!match)
                    {
                        return;
                    }

                    size_t item_idx = item_idx_iter->second;
                    APSI_LOG_DEBUG("Match found for items[" << item_idx << "] at cuckoo table index " << table_idx
                        << " (thread " << this_thread::get_id() << ")");
                    if (mrs[item_idx])
                    {
                        // If a positive MatchRecord is already present, then something is seriously wrong
                        APSI_LOG_ERROR("Found a match for cuckoo table index " << table_idx
                            << " but an existing match for this location was already found before "
                            << " (thread " << this_thread::get_id() << ")");

                        throw runtime_error("found a pre-existing positive match in the location for this match");
                    }

                    // Create a new MatchRecord
                    MatchRecord mr;
                    mr.found = true;

                    // Next, extract the label result(s), if any
                    if (!plain_rp.label_result.empty())
                    {
                        APSI_LOG_DEBUG("Found " << plain_rp.label_result.size() << "-part label for "
                            << "items[" << item_idx << "] "
                            << "(thread " << this_thread::get_id() << ")");

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

                    APSI_LOG_DEBUG("Finished processing result package for bundle index " << rp->bundle_idx
                        << " (thread " << this_thread::get_id() << ")");
                });
            }
        }
    } // namespace receiver
} // namespace apsi
