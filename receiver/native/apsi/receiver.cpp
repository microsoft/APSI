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
    using namespace logging;
    using namespace util;
    using namespace network;
    using namespace oprf;

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
            STOPWATCH(recv_stop_watch, "Receiver::initialize");
            Log::info("Initializing Receiver");

            if (!params_)
            {
                throw logic_error("parameters are not set");
            }

            // Initialize the CryptoContext with a new SEALContext
            crypto_context_ = make_unique<CryptoContext>(SEALContext::Create(params_->seal_params()));

            // Create new keys
            reset_keys();

            Log::info("Receiver initialized");
        }

        SenderOperationQuery Receiver::create_query(
            const vector<Item> &items, unordered_map<size_t, size_t> &table_idx_to_item_idx)
        {
            STOPWATCH(recv_stop_watch, "Receiver::create_query");
            Log::info("Receiver starting creating query");

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
                        Log::info("Skipping repeated insertion of items[" << item_idx << "]: " << item);
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
            map<uint32_t, vector<vector<uint64_t>>> raw_query_data;

            // Set up the encrypted data
            map<uint64_t, vector<SEALObject<Ciphertext>>> data;

            map<uint64_t, FFieldArray> powers;
            generate_powers(*ffield_items, powers);

            map<uint64_t, vector<string>> ciphers;
            encrypt(powers, ciphers);

            Log::info("Receiver preprocess end");

            return { move(ciphers), move(cuckoo) };

            return ciphertexts;
        }

        vector<MatchRecord> Receiver::query(const vector<Item> &items, Channel &chl)
        {
            STOPWATCH(recv_stop_watch, "Receiver::Query");
            Log::info("Receiver starting query");

            // This will contain the result of the OPRF query
            vector<Item> oprf_items;

            // First run an OPRF query 
            {
                STOPWATCH(recv_stop_watch, "Receiver::OPRF");
                Log::info("OPRF processing");

                // Send OPRF query to Sender
                vector<SEAL_BYTE> oprf_query_data = obfuscate_items(items);
                chl.send(make_unique<SenderOperationOPRF>(move(oprf_query_data)));

                unique_ptr<SenderOperationResponse> response;
                {
                    STOPWATCH(recv_stop_watch, "Receiver::OPRF::wait_response");

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
            chl.send(make_unique<SenderOperation>(move(sop_query)));

            // Wait for query response
            unique_ptr<SenderOperationResponse> response;
            {
                STOPWATCH(recv_stop_watch, "Receiver::Query::wait_response");

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
            STOPWATCH(recv_stop_watch, "Receiver::result_package_worker");

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

        vector<SEAL_BYTE> Receiver::obfuscate_items(const vector<Item> &items)
        {
            Log::info("Obfuscating items");

            vector<SEAL_BYTE> oprf_query;
            oprf_query.resize(items.size() * oprf_query_size);
            oprf_receiver_ = make_unique<OPRFReceiver>(items, oprf_query);

            return oprf_query;
        }

        vector<Item> Receiver::deobfuscate_items(const vector<SEAL_BYTE> &oprf_response)
        {
            Log::info("Deobfuscating items");

            vector<Item> items;
            oprf_receiver_->process_responses(oprf_response, items);
            oprf_receiver_.reset();

            return items;
        }

        void Receiver::handshake(Channel &chl)
        {
            STOPWATCH(recv_stop_watch, "Receiver::handshake");
            Log::info("Initial handshake");

            // Send a parameter request
            chl.send(make_unique<SenderOperationParms>());

            unique_ptr<SenderOperationResponse> response;
            {
                STOPWATCH(recv_stop_watch, "Receiver::handshake::wait_response");

                // Wait for a valid message of the correct type
                while (!(response = chl.receive_response(SenderOperationType::SOP_PARMS)));
            }

            // Extract the parameters
            params_ = move(dynamic_cast<SenderOperationResponseParms*>(response.get())->params);

            Log::debug("Received parameters from Sender:");
            Log::debug(params_.to_string());

            // Once we have parameters, initialize Receiver
            initialize();

            Log::info("Handshake done");
        }

        pair<map<uint64_t, vector<string>>, unique_ptr<KukuTable>> Receiver::preprocess(vector<Item> &items)
        {
            STOPWATCH(recv_stop_watch, "Receiver::preprocess");
            Log::info("Receiver preprocess start");

            // find the item length
            unique_ptr<KukuTable> cuckoo;
            unique_ptr<FFieldArray> ffield_items;

            uint32_t padded_cuckoo_capacity =
                static_cast<uint32_t>(((get_params().table_size() + slot_count_ - 1) / slot_count_) * slot_count_);

            ffield_items = make_unique<FFieldArray>(padded_cuckoo_capacity, *field_);

            size_t item_bit_count = get_params().item_bit_length_used_after_oprf();

            bool fm = get_params().use_fast_membership();
            if (items.size() > 1 || (!fm))
            {
                cuckoo = cuckoo_hashing(items);
                ffield_encoding(*cuckoo, *ffield_items);
            }
            else
            {
                // Perform repeated encoding.
                Log::info("Using repeated encoding for single query");
                for (size_t i = 0; i < get_params().table_size(); i++)
                {
                    ffield_items->set(i, items[0].to_ffield_element(*field_, item_bit_count));
                }
            }

            map<uint64_t, FFieldArray> powers;
            generate_powers(*ffield_items, powers);

            map<uint64_t, vector<string>> ciphers;
            encrypt(powers, ciphers);

            Log::info("Receiver preprocess end");

            return { move(ciphers), move(cuckoo) };
        }

        unique_ptr<KukuTable> Receiver::cuckoo_hashing(const vector<Item> &items)
        {
            item_type receiver_null_item{ 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL };

            auto cuckoo = make_unique<KukuTable>(
                get_params().table_size(),
                0, // stash size
                get_params().hash_func_count(), item_type{ get_params().hash_func_seed(), 0 }, get_params().max_probe(),
                receiver_null_item);

            auto coeff_bit_count = field_->characteristic().bit_count() - 1;
            auto degree = field_ ? field_->degree() : 1;

            if (get_params().item_bit_count() > static_cast<size_t>(static_cast<uint32_t>(coeff_bit_count) * degree))
            {
                Log::error(
                    "Reduced items too long. Only have %i bits.", static_cast<uint32_t>(coeff_bit_count) * degree);
                throw runtime_error("Reduced items too long.");
            }
            else
            {
                Log::debug(
                    "Using %i out of %ix%i bits of ffield element", get_params().item_bit_count(), coeff_bit_count - 1,
                    degree);
            }

            for (size_t i = 0; i < items.size(); i++)
            {
                auto cuckoo_item = items[i].value();
                bool insertionSuccess = cuckoo->insert(cuckoo_item);
                if (!insertionSuccess)
                {
                    string msg = "Cuckoo hashing failed";
                    Log::error("%s: current element: %i", msg.c_str(), i);
                    throw logic_error(msg);
                }
            }

            return cuckoo;
        }

        vector<size_t> Receiver::cuckoo_indices(const vector<Item> &items, kuku::KukuTable &cuckoo)
        {
            // This is the true size of the table; a multiple of slot_count_
            size_t padded_cuckoo_capacity = ((cuckoo.table_size() + slot_count_ - 1) / slot_count_) * slot_count_;

            vector<size_t> indices(padded_cuckoo_capacity, -size_t(1));
            auto &table = cuckoo.table();

            for (size_t i = 0; i < items.size(); i++)
            {
                auto cuckoo_item = items[i].value();
                auto q = cuckoo.query(cuckoo_item);

                Log::debug("cuckoo_indices: Setting indices at location: %i to: %i", q.location(), i);
                indices[q.location()] = i;

                if (!are_equal_item(cuckoo_item, table[q.location()]))
                    throw runtime_error("items[i] different from encodings[q.location()]");
            }
            return indices;
        }

        void Receiver::ffield_encoding(KukuTable &cuckoo, FFieldArray &ret)
        {
            size_t item_bit_count = get_params().item_bit_length_used_after_oprf();
            Log::debug("item bit count before decoding: %i", item_bit_count);

            // oprf? depends
            auto &encodings = cuckoo.table();

            Log::debug("bit count of ptxt modulus = %i", ret.field().characteristic().bit_count());

            for (size_t i = 0; i < cuckoo.table_size(); i++)
            {
                ret.set(i, Item(encodings[i]).to_ffield_element(ret.field(), item_bit_count));
            }

            auto empty_field_item = Item(cuckoo.empty_item()).to_ffield_element(ret.field(), item_bit_count);
            for (size_t i = cuckoo.table_size(); i < ret.size(); i++)
            {
                ret.set(i, empty_field_item);
            }
        }

        void Receiver::generate_powers(const FFieldArray &ffield_items, map<uint64_t, FFieldArray> &result)
        {
            uint64_t split_size =
                (get_params().sender_bin_size() + get_params().split_count() - 1) / get_params().split_count();
            uint32_t window_size = get_params().window_size();
            uint32_t radix = 1 << window_size;

            // todo: this bound needs to be re-visited.
            uint64_t max_supported_degree = static_cast<uint64_t>(get_params().max_supported_degree());

            // find the bound by enumerating
            uint64_t bound = static_cast<uint64_t>(split_size);
            while (bound > 0 && util::maximal_power(max_supported_degree, bound, radix) >= split_size)
            {
                bound--;
            }
            bound++;

            Log::debug(
                "Generate powers: split_size %i, window_size %i, radix %i, bound %i", split_size, window_size, radix,
                bound);

            FFieldArray current_power = ffield_items;
            for (uint64_t j = 0; j < static_cast<uint64_t>(bound); j++)
            {
                result.emplace(1ULL << (window_size * j), current_power);
                for (uint32_t i = 2; i < radix; i++)
                {
                    if (i * (1ULL << (window_size * j)) > static_cast<uint64_t>(split_size))
                    {
                        return;
                    }
                    result.emplace(
                        i * (1ULL << (window_size * j)),
                        result.at((i - 1) * (1ULL << (window_size * j))) * current_power);
                }
                for (uint32_t k = 0; k < window_size; k++)
                {
                    current_power.sq();
                }
            }
        }

        void Receiver::encrypt(map<uint64_t, FFieldArray> &input, map<uint64_t, vector<string>> &destination)
        {
            size_t count = 0;
            destination.clear();
            for (auto it = input.begin(); it != input.end(); it++)
            {
                encrypt(it->second, destination[it->first]);
                count += (it->second.size() + static_cast<size_t>(slot_count_) - 1) / static_cast<size_t>(slot_count_);
            }
            Log::debug("Receiver sending %i ciphertexts", count);
        }

        void Receiver::encrypt(const FFieldArray &input, vector<string> &destination)
        {
            size_t batch_size = slot_count_;
            size_t num_of_batches = (input.size() + batch_size - 1) / batch_size;
            vector<uint64_t> integer_batch(batch_size, 0);
            destination.clear();
            destination.reserve(num_of_batches);

            auto local_pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);
            Plaintext plain(local_pool);
            FFieldArray batch(batch_encoder_->create_array());

            for (size_t i = 0; i < num_of_batches; i++)
            {
                for (size_t j = 0; j < batch_size; j++)
                {
                    batch.set(j, i * batch_size + j, input);
                }
                batch_encoder_->compose(batch, plain);

                stringstream ss;
                Serializable<Ciphertext> ser_cipher = encryptor_->encrypt_symmetric(plain, local_pool);
                ser_cipher.save(ss, compr_mode_type::deflate);
                destination.emplace_back(ss.str());

                // note: this is not doing the setting to zero yet.
#ifdef APSI_DEBUG
                Log::debug(
                    "Fresh encryption noise budget = %i",
                    decryptor_->invariant_noise_budget([this](const string &ct_str) -> Ciphertext {
                        Ciphertext ct_out;
                        stringstream ss(ct_str);
                        ct_out.load(seal_context_, ss);
                        return ct_out;
                    }(destination.back())));
#endif
            }
        }
    } // namespace receiver
} // namespace apsi
