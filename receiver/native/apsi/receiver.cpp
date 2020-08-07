// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <algorithm>

// APSI
#include "apsi/logging/log.h"
#include "apsi/network/channel.h"
#include "apsi/network/result_package.h"
#include "apsi/oprf/oprf_receiver.h"
#include "apsi/receiver.h"
#include "apsi/util/utils.h"
#include "apsi/util/db_encoding.h"

// SEAL
#include "seal/util/defines.h"
#include "seal/encryptionparams.h"
#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/plaintext.h"
#include "seal/ciphertext.h"
#include "seal/util/iterator.h"
#include "seal/util/common.h"

// GSL
#include "gsl/span"

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
            PlaintextPowers(vector<uint64_t> values, const PSIParams &params) : mod_(params.seal_params().plain_modulus())
            {
                compute_powers(move(values), params.table_params().window_size, params.table_params().max_items_per_bin);
            }

            map<uint32_t, SEALObject<Ciphertext>> encrypt(const CryptoContext &crypto_context)
            {
                if (!crypto_context.encryptor())
                {
                    throw invalid_argument("encryptor is not set in crypto_context");
                }

                map<uint32_t, SEALObject<Ciphertext>> result;
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

            map<uint32_t, vector<uint64_t>> powers_;

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

            void compute_powers(vector<uint64_t> values, uint32_t window_size, uint32_t max_exponent)
            {
                uint32_t radix = uint32_t(1) << window_size;

                // Loop for as long as 2^(window_size * j) does not exceed max_exponent
                for (uint32_t j = 0; (uint32_t(1) << (window_size * j)) <= max_exponent; j++)
                {
                    powers_[uint32_t(1) << (window_size * j)] = values;

                    // Loop for as long as we are not exceeding the max_exponent
                    for (uint32_t i = 2; (i < radix) && (i * (uint32_t(1) << (window_size * j)) <= max_exponent); i++)
                    {
                        vector<uint64_t> temp(values.size());
                        multiply_array(powers_[(i - 1) * (uint32_t(1) << (window_size * j))], values, temp);
                        powers_[i * (uint32_t(1) << (window_size * j))] = move(temp);
                    }

                    for (uint32_t k = 0; k < window_size; k++)
                    {
                        square_array(values);
                    }
                }
            }
        };
    }

    namespace receiver
    {
        Receiver::Receiver(size_t thread_count) : thread_count_(thread_count)
        {
            if (thread_count_ < 1)
            {
                throw invalid_argument("thread_count must be at least 1");
            }
        }

        Receiver::Receiver(PSIParams params, size_t thread_count) :
            params_(make_unique<PSIParams>(move(params))), thread_count_(thread_count)
        {
            if (thread_count_ < 1)
            {
                throw invalid_argument("thread_count must be at least 1");
            }

            // We have params, so initialize
            initialize();
        }

        void Receiver::reset_keys()
        {
            if (!is_initialized())
            {
                throw logic_error("receiver is uninitialized");
            }

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
            STOPWATCH(recv_stopwatch, "Receiver::initialize");
            APSI_LOG_INFO("Initializing Receiver");

            if (!params_)
            {
                throw logic_error("parameters are not set");
            }

            // Initialize the CryptoContext with a new SEALContext
            crypto_context_ = make_unique<CryptoContext>(SEALContext::Create(params_->seal_params()));

            // Create new keys
            reset_keys();

            APSI_LOG_INFO("Receiver initialized");
        }

        vector<SEAL_BYTE> Receiver::obfuscate_items(const vector<Item> &items)
        {
            APSI_LOG_INFO("Obfuscating items");

            vector<SEAL_BYTE> oprf_query;
            oprf_query.resize(items.size() * oprf_query_size);
            oprf_receiver_ = make_unique<OPRFReceiver>(items, oprf_query);

            return oprf_query;
        }

        vector<Item> Receiver::deobfuscate_items(const vector<SEAL_BYTE> &oprf_response)
        {
            APSI_LOG_INFO("Deobfuscating items");

            vector<Item> items;
            oprf_receiver_->process_responses(oprf_response, items);
            oprf_receiver_.reset();

            return items;
        }

        unique_ptr<SenderOperation> Receiver::create_query(
            const vector<Item> &items, unordered_map<size_t, size_t> &table_idx_to_item_idx)
        {
            STOPWATCH(recv_stopwatch, "Receiver::create_query");
            APSI_LOG_INFO("Receiver starting creating query");

            if (!is_initialized())
            {
                throw logic_error("receiver is uninitialized");
            }

            table_idx_to_item_idx.clear();

            // Create the cuckoo table
            KukuTable cuckoo(
                params_->table_params().table_size,      // Size of the hash table
                0,                                       // Not using a stash
                params_->table_params().hash_func_count, // Number of hash functions
                { 0, 0 },                                // Hardcoded { 0, 0} as the seed
                cuckoo_table_insert_attempts,            // The number of insertion attempts 
                { 0, 0 });                               // The empty element can be set to anything

            // Fill the table
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
                            "Skipping repeated insertion of items[" << item_idx << "]: " << item);
                    }
                    else
                    {
                        stringstream ss;
                        ss << "Failed to insert items[" << item_idx << "]: " << item << endl;
                        throw runtime_error(ss.str());
                    }
                }
            }

            // Set up unencrypted query data
            vector<PlaintextPowers> plain_powers;
            for (uint32_t bundle_idx = 0; bundle_idx < params_->bundle_idx_count(); bundle_idx++)
            {
                // First, find the items for this bundle index
                gsl::span<const item_type> bundle_items(
                    cuckoo.table().data() + bundle_idx * params_->items_per_bundle(),
                    params_->items_per_bundle());

                vector<uint64_t> alg_items;
                for (auto &item : bundle_items)
                {
                    // Now set up a BitstringView to this item    
                    gsl::span<const SEAL_BYTE> item_bytes(
                        reinterpret_cast<const SEAL_BYTE*>(item.data()), sizeof(item));
                    BitstringView<const SEAL_BYTE> item_bits(item_bytes, params_->item_bit_count());

                    // Create an algebraic item by breaking up the item into modulo plain_modulus parts
                    vector<uint64_t> alg_item = bits_to_field_elts(item_bits, params_->seal_params().plain_modulus());
                    copy(alg_item.cbegin(), alg_item.cend(), back_inserter(alg_items));
                }

                // Now that we have the algebraized items for this bundle index, we create a PlaintextPowers object that
                // computes all necessary powers of the algebraized items.
                plain_powers.emplace_back(move(alg_items), *params_);
            }

            // The very last thing to do is encrypt the plain_powers and consolidate the matching powers for different
            // bundle indices
            map<uint32_t, vector<SEALObject<Ciphertext>>> encrypted_powers;
            for (auto &plain_power : plain_powers)
            {
                // Encrypt the data for this power
                map<uint32_t, SEALObject<Ciphertext>> encrypted_power(plain_power.encrypt(*crypto_context_));

                // Move the encrypted data to encrypted_powers
                for (auto &e : encrypted_power)
                {
                    encrypted_powers[e.first].emplace_back(move(e.second));
                }
            }

            // Set up the return value
            unique_ptr<SenderOperation> sop_query =
                make_unique<SenderOperationQuery>(relin_keys_, move(encrypted_powers));

            APSI_LOG_INFO("Receiver done creating query");

            return sop_query;
        }

        vector<MatchRecord> Receiver::query(const vector<Item> &items, Channel &chl)
        {
            STOPWATCH(recv_stopwatch, "Receiver::Query");
            APSI_LOG_INFO("Receiver starting query");

            // This will contain the result of the OPRF query
            vector<Item> oprf_items;

            // First run an OPRF query 
            {
                STOPWATCH(recv_stopwatch, "Receiver::OPRF");
                APSI_LOG_INFO("OPRF processing");

                // Send OPRF query to Sender
                vector<SEAL_BYTE> oprf_query_data = obfuscate_items(items);
                chl.send(make_unique<SenderOperationOPRF>(move(oprf_query_data)));

                unique_ptr<SenderOperationResponse> response;
                {
                    STOPWATCH(recv_stopwatch, "Receiver::OPRF::wait_response");

                    // Wait for a valid message of the correct type
                    while (!(response = chl.receive_response(SenderOperationType::SOP_OPRF)));
                }

                // Extract the OPRF response
                auto &oprf_response = dynamic_cast<SenderOperationResponseOPRF*>(response.get())->data;
                oprf_items = deobfuscate_items(oprf_response);
            }

            // This vector maps the cuckoo table index to the index of the item in the items vector
            unordered_map<size_t, size_t> table_idx_to_item_idx;

            // Create the SenderOperationQuery and send it on the channel
            auto sop_query = create_query(items, table_idx_to_item_idx);
            chl.send(move(sop_query));

            // Wait for query response
            unique_ptr<SenderOperationResponse> response;
            {
                STOPWATCH(recv_stopwatch, "Receiver::Query::wait_response");

                // Wait for a valid message of the correct type
                while (!(response = chl.receive_response(SenderOperationType::SOP_QUERY)));
            }

            // Set up the result
            vector<MatchRecord> mrs(items.size());

            // Get the number of ResultPackages we expect to receive
            auto query_response = dynamic_cast<SenderOperationResponseQuery*>(response.get());
            atomic<uint32_t> package_count = query_response->package_count;

            // Launch threads to receive ResultPackages and decrypt results
            std::vector<std::thread> threads;
            for (size_t t = 0; t < thread_count_; t++)
            {
                threads.emplace_back([&, t]() {
                    result_package_worker(package_count, mrs, table_idx_to_item_idx, chl);
                });
            }

            for (auto &t : threads)
            {
                t.join();
            }

            return mrs;
        }

        void Receiver::result_package_worker(
            atomic<uint32_t> &package_count,
            vector<MatchRecord> &mrs,
            const unordered_map<size_t, size_t> &table_idx_to_item_idx,
            Channel &chl) const
        {
            STOPWATCH(recv_stopwatch, "Receiver::result_package_worker");

            while (package_count--)
            {
                unique_ptr<ResultPackage> rp;

                // Wait for a valid ResultPackage or until package_count has reached zero
                while (!(rp = chl.receive_result_package(crypto_context_->seal_context())));

                // Decrypt and decode the result; the result vector will have full batch size
                PlainResultPackage plain_rp = rp->extract(crypto_context_->seal_context());

                // Iterate over the decoded data to find consequtive zeros indicating a match
                StrideIter<const uint64_t *> plain_rp_iter(
                    plain_rp.psi_result.data(), params_->item_params().felts_per_item);
                size_t felts_per_item = safe_cast<size_t>(params_->item_params().felts_per_item);
                size_t bundle_start = safe_cast<size_t>(mul_safe(plain_rp.bundle_idx, params_->items_per_bundle()));
                SEAL_ITERATE(iter(plain_rp_iter, size_t(0)), params_->items_per_bundle(), [&](auto I) {
                    // Compute the cuckoo table index for this item 
                    size_t table_idx = add_safe(get<1>(I), bundle_start);

                    // Next find the corresponding index in the input items vector
                    auto item_idx_iter = table_idx_to_item_idx.find(table_idx);

                    if (item_idx_iter == table_idx_to_item_idx.cend())
                    {
                        // If this table_idx doesn't match any item_idx; ignore the result no matter what it is
                        return;
                    }

                    // Find felts_per_item consequtive zeros
                    bool match = all_of(get<0>(I), get<0>(I) + felts_per_item, [](auto felt) { return felt == 0; });

                    if (match)
                    {
                        size_t item_idx = item_idx_iter->second;
                        if (mrs[item_idx])
                        {
                            // If a positive MatchRecord is already present, then something is seriously wrong
                            throw runtime_error("found a pre-existing positive match in the location for this match");
                        }

                        // Create a new MatchRecord
                        MatchRecord mr;
                        mr.found = true;

                        // Next, extract the label result(s), if any
                        if (!plain_rp.label_result.empty())
                        {
                            // Collect the entire label into this vector
                            vector<felt_t> label_as_felts;

                            for (auto &label_parts : plain_rp.label_result)
                            {
                                size_t label_offset = mul_safe(get<1>(I), felts_per_item);
                                gsl::span<felt_t> label_part(
                                    label_parts.data() + label_offset, params_->item_params().felts_per_item);
                                copy_n(label_part.begin(), label_part.end(), back_inserter(label_as_felts));
                            }

                            // Create the label
                            unique_ptr<Bitstring> label = make_unique<Bitstring>(
                                field_elts_to_bits(label_as_felts, params_->seal_params().plain_modulus()));

                            // Set the label
                            mr.label.set(move(label));
                        }

                        // We are done with the MatchRecord, so add it to the mrs vector
                        mrs[item_idx] = move(mr);
                    }
                });
            }
        }
    } // namespace receiver
} // namespace apsi
