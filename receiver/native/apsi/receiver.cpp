// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <sstream>
#include <map>
#include <iostream>

// APSI
#include "apsi/receiver.h"
#include "apsi/logging/log.h"
#include "apsi/network/network_utils.h"
#include "apsi/network/channel.h"
#include "apsi/tools/utils.h"
#include "apsi/result_package.h"
#include "apsi/oprf/oprf_receiver.h"

// SEAL
#include <seal/util/common.h>
#include <seal/util/uintcore.h>
#include <seal/encryptionparams.h>
#include <seal/keygenerator.h>

using namespace std;
using namespace seal;
using namespace kuku;

namespace apsi
{
    using namespace logging;
    using namespace tools;
    using namespace network;
    using namespace oprf;

    namespace receiver
    {
        Receiver::Receiver(int thread_count) :
            thread_count_(thread_count),
            field_(nullptr),
            slot_count_(0)
        {
            if (thread_count_ <= 0)
            {
                throw invalid_argument("thread_count must be positive");
            }
        }

        Receiver::Receiver(const PSIParams& params, int thread_count) :
            params_(make_unique<PSIParams>(params)),
            thread_count_(thread_count),
            field_(nullptr),
            slot_count_(0)
        {
            if (thread_count_ <= 0)
            {
                throw invalid_argument("thread_count must be positive");
            }

            // We have params, so initialize
            initialize();
        }


        void Receiver::initialize()
        {
            STOPWATCH(recv_stop_watch, "Receiver::initialize");
            Log::info("Initializing Receiver");

            field_ = make_unique<FField>(
                SmallModulus(get_params().ffield_characteristic()),
                get_params().ffield_degree());

            slot_count_ = get_params().batch_size();

            seal_context_ = SEALContext::Create(get_params().encryption_params());
            KeyGenerator generator(seal_context_);

            public_key_ = generator.public_key();
            secret_key_ = generator.secret_key();

            encryptor_ = make_unique<Encryptor>(seal_context_, public_key_, secret_key_);
            decryptor_ = make_unique<Decryptor>(seal_context_, secret_key_);

            // Initializing tools for dealing with compressed ciphertexts
            compressor_ = make_unique<CiphertextCompressor>(
                seal_context_,
                MemoryManager::GetPool(mm_prof_opt::FORCE_NEW));

            stringstream relin_keys_ss;
            Serializable<RelinKeys> relin_keys = generator.relin_keys();
            relin_keys.save(relin_keys_ss, compr_mode_type::deflate);
            relin_keys_ = relin_keys_ss.str();

            batch_encoder_ = make_shared<FFieldBatchEncoder>(seal_context_, *field_);

            Log::info("Receiver initialized");
        }

        map<u64, vector<string>>& Receiver::query(vector<Item>& items)
        {
            STOPWATCH(recv_stop_watch, "Receiver::query");
            Log::info("Receiver starting query");

            if (nullptr == params_)
            {
                throw runtime_error("No parameters have been configured.");
            }

            preprocess_result_ = make_unique<pair<map<uint64_t, vector<string>>, unique_ptr<KukuTable>>>
                (preprocess(items));
            auto& ciphertexts = preprocess_result_->first;

            return ciphertexts;
        }

        pair<vector<bool>, Matrix<u8>> Receiver::decrypt_result(vector<Item>& items, Channel& chl)
        {
            pair<vector<bool>, Matrix<u8>> empty_result;

            if (nullptr == preprocess_result_)
            {
                return empty_result;
            }

            auto& cuckoo = *(preprocess_result_->second);
            size_t padded_table_size = static_cast<size_t>(
                ((get_params().table_size() + slot_count_ - 1) / slot_count_) * slot_count_);

            vector<int> table_to_input_map(padded_table_size, 0);
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

        pair<vector<bool>, Matrix<u8>> Receiver::query(vector<Item>& items, Channel& chl)
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

                deobfuscate_items(items, preprocess_resp.buffer);
            }

            // Then get encrypted query
            auto& encrypted_query = query(items);

            // Send encrypted query
            chl.send_query(relin_keys_, encrypted_query);

            // Decrypt result
            return decrypt_result(items, chl);
        }

        void Receiver::obfuscate_items(std::vector<Item>& items, std::vector<SEAL_BYTE>& items_buffer)
        {
            Log::info("Obfuscating items");

            items_buffer.resize(items.size() * oprf_query_size);
            oprf_receiver_ = make_shared<OPRFReceiver>(items, items_buffer);
        }

        void Receiver::deobfuscate_items(std::vector<Item>& items, std::vector<SEAL_BYTE>& items_buffer)
        {
            Log::info("Deobfuscating items");

            oprf_receiver_->process_responses(items_buffer, items);
        }

        void Receiver::handshake(Channel& chl)
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
                sender_params.psiconf_params,
                sender_params.table_params,
                sender_params.cuckoo_params,
                sender_params.seal_params,
                sender_params.ffield_params);

            Log::debug("Received parameters from Sender:");
            Log::debug(
                "item bit count: %i, sender size: %lli, sender bin size: %lli, use labels: %s, use fast membership: %s, num chunks: %i",
                sender_params.psiconf_params.item_bit_count,
                sender_params.psiconf_params.sender_size,
                sender_params.psiconf_params.sender_bin_size,
                sender_params.psiconf_params.use_labels ? "true" : "false",
                sender_params.psiconf_params.use_fast_membership ? "true" : "false",
                sender_params.psiconf_params.num_chunks);
            Log::debug(
                "log table size: %i, split count: %i, split size: %i, binning sec level: %i, window size: %i, dynamic split count: %s",
                sender_params.table_params.log_table_size,
                sender_params.table_params.split_count,
                sender_params.table_params.split_size,
                sender_params.table_params.binning_sec_level,
                sender_params.table_params.window_size,
                sender_params.table_params.dynamic_split_count ? "true" : "false");
            Log::debug(
                "hash func count: %i, hash func seed: %i, max probe: %i",
                sender_params.cuckoo_params.hash_func_count,
                sender_params.cuckoo_params.hash_func_seed,
                sender_params.cuckoo_params.max_probe);
            Log::debug(
                "poly modulus degree: %i, plain modulus: 0x%llx, max supported degree: %i",
                sender_params.seal_params.encryption_params.poly_modulus_degree(),
                sender_params.seal_params.encryption_params.plain_modulus().value(),
                sender_params.seal_params.max_supported_degree);
            Log::debug("coeff modulus: %i elements", sender_params.seal_params.encryption_params.coeff_modulus().size());
            for (size_t i = 0; i < sender_params.seal_params.encryption_params.coeff_modulus().size(); i++)
            {
                Log::debug("Coeff modulus %i: 0x%llx", i, sender_params.seal_params.encryption_params.coeff_modulus()[i].value());
            }
            Log::debug(
                "ffield characteristic: 0x%llx, ffield degree: %i",
                sender_params.ffield_params.characteristic,
                sender_params.ffield_params.degree);

            // Once we have parameters, initialize Receiver
            initialize();

            Log::info("Handshake done");
        }

        pair<
            map<u64, vector<string>>,
            unique_ptr<KukuTable>>
            Receiver::preprocess(vector<Item> &items)
        {
            STOPWATCH(recv_stop_watch, "Receiver::preprocess");
            Log::info("Receiver preprocess start");

            // find the item length 
            unique_ptr<KukuTable> cuckoo;
            unique_ptr<FFieldArray> ffield_items;

            u32 padded_cuckoo_capacity = static_cast<u32>(
                ((get_params().table_size() + slot_count_ - 1) / slot_count_) * slot_count_);

            ffield_items = make_unique<FFieldArray>(padded_cuckoo_capacity, *field_);

            int item_bit_count = get_params().item_bit_length_used_after_oprf();

            bool fm = get_params().use_fast_membership();
            if (items.size() > 1 || (!fm)) {
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

            map<u64, FFieldArray> powers;
            generate_powers(*ffield_items, powers);

            map<u64, vector<string>> ciphers;
            encrypt(powers, ciphers);

            Log::info("Receiver preprocess end");

            return { move(ciphers), move(cuckoo) };
        }

        unique_ptr<KukuTable> Receiver::cuckoo_hashing(const vector<Item> &items)
        {
            auto receiver_null_item = all_one_item;

            auto cuckoo = make_unique<KukuTable>(
                get_params().log_table_size(),
                0, // stash size
                get_params().hash_func_count(),
                item_type{ get_params().hash_func_seed(), 0 },
                get_params().max_probe(),
                receiver_null_item);

            auto coeff_bit_count = field_->ch().bit_count() - 1;
            auto degree = field_ ? field_->d() : 1;

            if (get_params().item_bit_count() > coeff_bit_count * degree)
            {
                Log::error("Reduced items too long. Only have %i bits.", coeff_bit_count * degree);
                throw runtime_error("Reduced items too long.");
            }
            else
            {
                Log::debug("Using %i out of %ix%i bits of ffield element",
                    get_params().item_bit_count(),
                    coeff_bit_count - 1,
                    degree);
            }

            for (size_t i = 0; i < items.size(); i++)
            {
                auto cuckoo_item = items[i].get_value();
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

        vector<int> Receiver::cuckoo_indices(
            const vector<Item> &items,
            kuku::KukuTable &cuckoo)
        {
            // This is the true size of the table; a multiple of slot_count_
            size_t padded_cuckoo_capacity = static_cast<size_t>(
                ((cuckoo.table_size() + slot_count_ - 1) / slot_count_) * slot_count_);

            vector<int> indices(padded_cuckoo_capacity, -1);
            auto& table = cuckoo.table();

            for (size_t i = 0; i < items.size(); i++)
            {
                auto cuckoo_item = items[i].get_value();
                auto q = cuckoo.query(cuckoo_item);

                Log::debug("cuckoo_indices: Setting indices at location: %i to: %i", q.location(), i);
                indices[q.location()] = static_cast<int>(i);

                if (!are_equal_item(cuckoo_item, table[q.location()]))
                    throw runtime_error("items[i] different from encodings[q.location()]");
            }
            return indices;
        }

        void Receiver::ffield_encoding(
            KukuTable &cuckoo,
            FFieldArray &ret)
        {
            int item_bit_count = get_params().item_bit_length_used_after_oprf();
            Log::debug("item bit count before decoding: %i", item_bit_count);

            // oprf? depends 
            auto& encodings = cuckoo.table();

            Log::debug("bit count of ptxt modulus = %i", ret.field().ch().bit_count());

            for (size_t i = 0; i < cuckoo.table_size(); i++)
            {
                ret.set(i, Item(encodings[i]).to_ffield_element(ret.field(), item_bit_count));
            }

            auto empty_field_item = Item(cuckoo.empty_item())
                .to_ffield_element(ret.field(), item_bit_count);
            for (size_t i = cuckoo.table_size(); i < ret.size(); i++)
            {
                ret.set(i, empty_field_item);
            }
        }

        void Receiver::generate_powers(const FFieldArray& ffield_items,
            map<u64, FFieldArray>& result)
        {
            u64 split_size = (get_params().sender_bin_size() + get_params().split_count() - 1) / get_params().split_count();
            u32 window_size = get_params().window_size();
            u32 radix = 1 << window_size;

            // todo: this bound needs to be re-visited. 
            int max_supported_degree = get_params().max_supported_degree();

            // find the bound by enumerating 
            i64 bound = split_size;
            while (bound > 0 && tools::maximal_power(max_supported_degree, bound, radix) >= split_size)
            {
                bound--;
            }
            bound++;

            Log::debug("Generate powers: split_size %i, window_size %i, radix %i, bound %i",
                split_size, window_size, radix, bound);

            FFieldArray current_power = ffield_items;
            for (u64 j = 0; j < static_cast<u64>(bound); j++)
            {
                result.emplace(1ULL << (window_size * j), current_power);
                for (u32 i = 2; i < radix; i++)
                {
                    if (i * (1ULL << (window_size * j)) > static_cast<u64>(split_size))
                    {
                        return;
                    }
                    result.emplace(i * (1ULL << (window_size * j)), result.at((i - 1) * (1ULL << (window_size * j))) * current_power);
                }
                for (u32 k = 0; k < window_size; k++)
                {
                    current_power.sq();
                }
            }
        }

        void Receiver::encrypt(map<u64, FFieldArray> &input, map<u64, vector<string>> &destination)
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
            int batch_size = slot_count_, num_of_batches = static_cast<int>((input.size() + batch_size - 1) / batch_size);
            vector<u64> integer_batch(batch_size, 0);
            destination.clear();
            destination.reserve(num_of_batches);

            auto local_pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);
            Plaintext plain(local_pool);
            FFieldArray batch(batch_encoder_->create_array());

            for (int i = 0; i < num_of_batches; i++)
            {
                for (int j = 0; j < batch_size; j++)
                {
                    size_t sti = static_cast<size_t>(i);
                    size_t stj = static_cast<size_t>(j);
                    batch.set(stj, sti * batch_size + stj, input);
                }
                batch_encoder_->compose(batch, plain);

                stringstream ss;
                Serializable<Ciphertext> ser_cipher = encryptor_->encrypt_symmetric(plain, local_pool);
                ser_cipher.save(ss, compr_mode_type::deflate);
                destination.emplace_back(ss.str());

                // note: this is not doing the setting to zero yet.
#ifdef APSI_DEBUG
                Log::debug("Fresh encryption noise budget = %i",
                    decryptor_->invariant_noise_budget(
                        [this](const string &ct_str) -> Ciphertext {
                            Ciphertext ct_out;
                            stringstream ss(ct_str);
                            ct_out.load(seal_context_, ss);
                            return ct_out;
                        }(destination.back())
                    )
                );
#endif
            }
        }

        std::pair<std::vector<bool>, Matrix<u8>> Receiver::stream_decrypt(
            Channel& channel,
            const std::vector<int>& table_to_input_map,
            std::vector<Item>& items)
        {
            STOPWATCH(recv_stop_watch, "Receiver::stream_decrypt");
            std::pair<std::vector<bool>, Matrix<u8>> ret;
            auto& ret_bools = ret.first;
            auto& ret_labels = ret.second;

            ret_bools.resize(items.size(), false);

            if (get_params().use_labels())
            {
                ret_labels.resize(items.size(), get_params().label_byte_count());
            }

            int num_of_splits = get_params().split_count(),
                num_of_batches = get_params().batch_count(),
                block_count = num_of_splits * num_of_batches,
                batch_size = slot_count_;

            Log::info("Receiver batch size = %i", batch_size);

            auto num_threads = thread_count_;
            Log::debug("Decrypting %i blocks(%ib x %is) with %i threads",
                block_count,
                num_of_batches,
                num_of_splits,
                num_threads);

            std::vector<std::thread> thrds(num_threads);
            for (size_t t = 0; t < thrds.size(); ++t)
            {
                thrds[t] = std::thread([&](int idx)
                    {
                        stream_decrypt_worker(
                            idx,
                            batch_size,
                            thread_count_,
                            block_count,
                            channel,
                            table_to_input_map,
                            ret_bools,
                            ret_labels);
                    }, static_cast<int>(t));
            }

            for (auto& thrd : thrds)
                thrd.join();

            return ret;
        }

        void Receiver::stream_decrypt_worker(
            int thread_idx,
            int batch_size,
            int num_threads,
            int block_count,
            Channel& channel,
            const vector<int>& table_to_input_map,
            vector<bool>& ret_bools,
            Matrix<u8>& ret_labels)
        {
            STOPWATCH(recv_stop_watch, "Receiver::stream_decrypt_worker");
            MemoryPoolHandle local_pool(MemoryPoolHandle::New());
            Plaintext p(local_pool);
            Ciphertext tmp(seal_context_, local_pool);
            unique_ptr<FFieldArray> batch = make_unique<FFieldArray>(batch_encoder_->create_array());

            bool first = true;
            u64 processed_count = 0;

            for (u64 i = thread_idx; i < static_cast<u64>(block_count); i += num_threads)
            {
                bool has_result = false;
                std::vector<u8> has_label(batch_size);

                ResultPackage pkg;
                {
                    STOPWATCH(recv_stop_watch, "Receiver::stream_decrypt_worker_wait");
                    if (!channel.receive(pkg))
                    {
                        Log::error("Could not receive Result package");
                        return;
                    }
                }

                int base_idx = static_cast<int>(pkg.batch_idx * batch_size);
                Log::debug("Thread idx: %i, pkg.batch_idx: %i", thread_idx, pkg.batch_idx);

                // recover the sym poly values 
                has_result = false;
                stringstream ss(pkg.data);

                compressor_->compressed_load(ss, tmp);
                if (first && thread_idx == 0)
                {
                    first = false;
                    Log::info("Noise budget: %i bits", decryptor_->invariant_noise_budget(tmp));
                }

                decryptor_->decrypt(tmp, p);
                batch_encoder_->decompose(p, *batch);

                for (int k = 0; k < batch_size; k++)
                {
                    auto idx = table_to_input_map[base_idx + k];
                    if (idx >= 0)
                    {
                        auto& is_zero = has_label[k];

                        is_zero = batch->is_zero(k);

                        if (is_zero)
                        {
                            Log::debug("Found zero at thread_idx: %i, base_idx: %i, k: %i, idx: %i", thread_idx, base_idx, k, idx);
                            has_result = true;
                            ret_bools[idx] = true;
                        }
                    }
                }

                if (has_result && get_params().use_labels())
                {
                    std::stringstream ss(pkg.label_data);

                    compressor_->compressed_load(ss, tmp);

                    decryptor_->decrypt(tmp, p);

                    // make sure its the right size. decrypt will shorted when there are zero coeffs at the top.
                    p.resize(static_cast<i32>(batch_encoder_->n()));

                    batch_encoder_->decompose(p, *batch);

                    //if (batch->is_zero()) {
                    Log::debug("decrypted label data is zero? %i", batch->is_zero());
                    //}

                    for (int k = 0; k < batch_size; k++)
                    {
                        if (has_label[k])
                        {
                            auto idx = table_to_input_map[base_idx + k];
                            Log::debug("Found label at thread_idx: %i, base_idx: %i, k: %i, idx: %i", thread_idx, base_idx, k, idx);

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