// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>

// APSI
#include "apsi/logging/log.h"
#include "apsi/network/channel.h"
#include "apsi/network/network_utils.h"
#include "apsi/oprf/oprf_receiver.h"
#include "apsi/receiver.h"
#include "apsi/result_package.h"
#include "apsi/util/utils.h"

// SEAL
#include <seal/encryptionparams.h>
#include <seal/keygenerator.h>
#include <seal/util/common.h>
#include <seal/util/uintcore.h>

using namespace std;
using namespace seal;
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
            if (thread_count < 1)
            {
                throw invalid_argument("thread_count must be at least 1");
            }
        }

        Receiver::Receiver(const PSIParams &params, size_t thread_count)
            : params_(make_unique<PSIParams>(params)), thread_count_(thread_count)
        {
            if (thread_count < 1)
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

            // Create Serializable<RelinKeys> and write them directory to a stream
            stringstream relin_keys_ss;
            Serializable<RelinKeys> relin_keys(generator.relin_keys());
            relin_keys.save(relin_keys_ss, compr_mode_type::deflate);

            // Save the relinearization keys string
            relin_keys_ = relin_keys_ss.str();
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
            crypto_context_ = make_unique<CryptoContext>(SEALContext::Create(params_.encryption_params()));

            // Create new keys
            reset_keys();

            Log::info("Receiver initialized");
        }

        map<uint64_t, vector<string>> &Receiver::query(vector<Item> &items)
        {
            STOPWATCH(recv_stop_watch, "Receiver::query");
            Log::info("Receiver starting query");

            if (!is_initialized())
            {
                throw logic_error("receiver is uninitialized");
            }

            preprocess_result_ =
                make_unique<pair<map<uint64_t, vector<string>>, unique_ptr<KukuTable>>>(preprocess(items));
            auto &ciphertexts = preprocess_result_->first;

            return ciphertexts;
        }

        pair<vector<bool>, Matrix<unsigned char>> Receiver::decrypt_result(vector<Item> &items, Channel &chl)
        {
            pair<vector<bool>, Matrix<unsigned char>> empty_result;

            if (nullptr == preprocess_result_)
            {
                return empty_result;
            }

            auto &cuckoo = *(preprocess_result_->second);
            size_t padded_table_size = ((get_params().table_size() + slot_count_ - 1) / slot_count_) * slot_count_;

            vector<size_t> table_to_input_map(padded_table_size, 0);
            if (items.size() > 1 || (!get_params().use_fast_membership()))
            {
                table_to_input_map = cuckoo_indices(items, cuckoo);
            }
            else
            {
                Log::info("Receiver single query table to input map");
            }

            /* Receive results */
            SenderResponseQuery query_resp;
            {
                STOPWATCH(recv_stop_watch, "Receiver::query::wait_response");
                if (!chl.receive(query_resp))
                {
                    Log::error("Not able to receive query response");
                    return empty_result;
                }

                Log::debug("Sender will send %i result packages", query_resp.package_count);
            }

            auto intersection = stream_decrypt(chl, table_to_input_map, items);

            Log::info("Receiver completed query");

            return intersection;
        }

        pair<vector<bool>, Matrix<unsigned char>> Receiver::query(vector<Item> &items, Channel &chl)
        {
            STOPWATCH(recv_stop_watch, "Receiver::query_full");
            Log::info("Receiver starting full query");

            // OPRF
            // This block is used so the Receiver::OPRF stopwatch measures only OPRF, and nothing else
            {
                STOPWATCH(recv_stop_watch, "Receiver::OPRF");
                Log::info("OPRF processing");

                vector<SEAL_BYTE> items_buffer;
                obfuscate_items(items, items_buffer);

                // Send obfuscated buffer to Sender
                chl.send_preprocess(items_buffer);

                // Get response and remove our obfuscation
                SenderResponsePreprocess preprocess_resp;
                chl.receive(preprocess_resp);

                deobfuscate_items(preprocess_resp.buffer, items);
            }

            // Then get encrypted query
            auto &encrypted_query = query(items);

            // Send encrypted query
            chl.send_query(relin_keys_, encrypted_query);

            // Decrypt result
            return decrypt_result(items, chl);
        }

        void Receiver::obfuscate_items(const std::vector<Item> &items, std::vector<SEAL_BYTE> &items_buffer)
        {
            Log::info("Obfuscating items");

            items_buffer.resize(items.size() * oprf_query_size);
            oprf_receiver_ = make_unique<OPRFReceiver>(items, items_buffer);
        }

        void Receiver::deobfuscate_items(const std::vector<SEAL_BYTE> &items_buffer, std::vector<Item> &items)
        {
            Log::info("Deobfuscating items");

            oprf_receiver_->process_responses(items_buffer, items);
            oprf_receiver_.reset();
        }

        void Receiver::handshake(Channel &chl)
        {
            STOPWATCH(recv_stop_watch, "Receiver::handshake");
            Log::info("Initial handshake");

            SenderResponseGetParameters sender_params;
            chl.send_get_parameters();

            {
                STOPWATCH(recv_stop_watch, "Receiver::handshake::wait_response");
                chl.receive(sender_params);
            }

            // Set parameters from Sender.
            params_ = make_unique<PSIParams>(
                sender_params.psiconf_params, sender_params.table_params, sender_params.cuckoo_params,
                sender_params.seal_params, sender_params.ffield_params);

            Log::debug("Received parameters from Sender:");
            Log::debug(
                "item bit count: %i, sender size: %lli, sender bin size: %lli, use labels: %s, use fast membership: "
                "%s, num chunks: %i",
                sender_params.psiconf_params.item_bit_count, sender_params.psiconf_params.sender_size,
                sender_params.psiconf_params.sender_bin_size,
                sender_params.psiconf_params.use_labels ? "true" : "false",
                sender_params.psiconf_params.use_fast_membership ? "true" : "false",
                sender_params.psiconf_params.num_chunks);
            Log::debug(
                "log table size: %i, split count: %i, split size: %i, binning sec level: %i, window size: %i, dynamic "
                "split count: %s",
                sender_params.table_params.log_table_size, sender_params.table_params.split_count,
                sender_params.table_params.split_size, sender_params.table_params.binning_sec_level,
                sender_params.table_params.window_size,
                sender_params.table_params.use_dynamic_split_count ? "true" : "false");
            Log::debug(
                "hash func count: %i, hash func seed: %i, max probe: %i", sender_params.cuckoo_params.hash_func_count,
                sender_params.cuckoo_params.hash_func_seed, sender_params.cuckoo_params.max_probe);
            Log::debug(
                "poly modulus degree: %i, plain modulus: 0x%llx, max supported degree: %i",
                sender_params.seal_params.encryption_params.poly_modulus_degree(),
                sender_params.seal_params.encryption_params.plain_modulus().value(),
                sender_params.seal_params.max_supported_degree);
            Log::debug(
                "coeff modulus: %i elements", sender_params.seal_params.encryption_params.coeff_modulus().size());
            for (size_t i = 0; i < sender_params.seal_params.encryption_params.coeff_modulus().size(); i++)
            {
                Log::debug(
                    "Coeff modulus %i: 0x%llx", i,
                    sender_params.seal_params.encryption_params.coeff_modulus()[i].value());
            }
            Log::debug(
                "ffield characteristic: 0x%llx, ffield degree: %i", sender_params.ffield_params.characteristic,
                sender_params.ffield_params.degree);

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

        std::pair<std::vector<bool>, Matrix<unsigned char>> Receiver::stream_decrypt(
            Channel &channel, const std::vector<size_t> &table_to_input_map, const std::vector<Item> &items)
        {
            STOPWATCH(recv_stop_watch, "Receiver::stream_decrypt");
            std::pair<std::vector<bool>, Matrix<unsigned char>> ret;
            auto &ret_bools = ret.first;
            auto &ret_labels = ret.second;

            ret_bools.resize(items.size(), false);

            if (get_params().use_labels())
            {
                ret_labels.resize(items.size(), get_params().label_byte_count());
            }

            size_t num_of_splits = get_params().split_count();
            size_t num_of_batches = get_params().batch_count();
            size_t block_count = num_of_splits * num_of_batches;
            size_t batch_size = slot_count_;

            Log::info("Receiver batch size = %i", batch_size);

            size_t num_threads = thread_count_;
            Log::debug(
                "Decrypting %i blocks(%ib x %is) with %i threads", block_count, num_of_batches, num_of_splits,
                num_threads);

            std::vector<std::thread> thrds(num_threads);
            for (size_t t = 0; t < thrds.size(); ++t)
            {
                thrds[t] = std::thread(
                    [&](size_t idx) {
                        stream_decrypt_worker(
                            idx, batch_size, thread_count_, block_count, channel, table_to_input_map, ret_bools,
                            ret_labels);
                    },
                    static_cast<int>(t));
            }

            for (auto &thrd : thrds)
                thrd.join();

            return ret;
        }

        void Receiver::stream_decrypt_worker(
            size_t thread_idx, size_t batch_size, size_t num_threads, size_t block_count, Channel &channel,
            const vector<size_t> &table_to_input_map, vector<bool> &ret_bools, Matrix<unsigned char> &ret_labels)
        {
            STOPWATCH(recv_stop_watch, "Receiver::stream_decrypt_worker");
            MemoryPoolHandle local_pool(MemoryPoolHandle::New());
            Plaintext p(local_pool);
            Ciphertext tmp(seal_context_, local_pool);
            unique_ptr<FFieldArray> batch = make_unique<FFieldArray>(batch_encoder_->create_array());

            bool first = true;
            uint64_t processed_count = 0;

            for (size_t i = thread_idx; i < block_count; i += num_threads)
            {
                bool has_result = false;
                std::vector<unsigned char> has_label(batch_size);

                ResultPackage pkg;
                {
                    STOPWATCH(recv_stop_watch, "Receiver::stream_decrypt_worker_wait");
                    if (!channel.receive(pkg))
                    {
                        Log::error("Could not receive Result package");
                        return;
                    }
                }

                size_t base_idx = pkg.bundle_idx * batch_size;
                Log::debug("Thread idx: %i, pkg.batch_idx: %i", thread_idx, pkg.bundle_idx);

                // recover the sym poly values
                has_result = false;

                get_ciphertext(seal_context_, tmp, pkg.data);
                if (first && thread_idx == 0)
                {
                    first = false;
                    Log::info("Noise budget: %i bits", decryptor_->invariant_noise_budget(tmp));
                }

                decryptor_->decrypt(tmp, p);
                batch_encoder_->decompose(p, *batch);

                for (size_t k = 0; k < batch_size; k++)
                {
                    size_t idx = table_to_input_map[base_idx + k];
                    if (idx != -size_t(1))
                    {
                        auto &is_zero = has_label[k];

                        is_zero = batch->is_zero(k);

                        if (is_zero)
                        {
                            Log::debug(
                                "Found zero at thread_idx: %i, base_idx: %i, k: %i, idx: %i", thread_idx, base_idx, k,
                                idx);
                            has_result = true;
                            ret_bools[idx] = true;
                        }
                    }
                }

                if (has_result && get_params().use_labels())
                {
                    get_ciphertext(seal_context_, tmp, pkg.label_data);
                    decryptor_->decrypt(tmp, p);

                    // make sure its the right size. decrypt will shorted when there are zero coeffs at the top.
                    p.resize(batch_encoder_->n());

                    batch_encoder_->decompose(p, *batch);

                    // if (batch->is_zero()) {
                    Log::debug("decrypted label data is zero? %i", batch->is_zero());
                    //}

                    for (size_t k = 0; k < batch_size; k++)
                    {
                        if (has_label[k])
                        {
                            size_t idx = table_to_input_map[base_idx + k];
                            Log::debug(
                                "Found label at thread_idx: %i, base_idx: %i, k: %i, idx: %i", thread_idx, base_idx, k,
                                idx);

                            batch->get(k).decode(ret_labels[idx], get_params().label_bit_count());
                        }
                    }
                }

                processed_count++;
            }

            Log::debug("Thread %d processed %d blocks.", thread_idx, processed_count);
        }
    } // namespace receiver
} // namespace apsi
