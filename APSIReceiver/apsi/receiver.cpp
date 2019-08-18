// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

// STD
#include <sstream>
#include <map>
#include <iostream>

// APSI
#include "apsi/receiver.h"
#include "apsi/apsidefines.h"
#include "apsi/logging/log.h"
#include "apsi/network/network_utils.h"
#include "apsi/network/channel.h"
#include "apsi/tools/fourq.h"
#include "apsi/tools/prng.h"
#include "apsi/tools/utils.h"
#include "apsi/result_package.h"
#include "apsi/tools/blake2/blake2.h"

// SEAL
#include "seal/util/common.h"
#include "seal/util/uintcore.h"
#include "seal/encryptionparams.h"
#include "seal/keygenerator.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace cuckoo;
using namespace apsi;
using namespace apsi::logging;
using namespace apsi::tools;
using namespace apsi::network;
using namespace apsi::receiver;



Receiver::Receiver(int thread_count, const MemoryPoolHandle &pool) :
    thread_count_(thread_count),
    pool_(pool),
    field_(nullptr),
    slot_count_(0)
{
    if (thread_count_ <= 0)
    {
        throw invalid_argument("thread_count must be positive");
    }
}

void Receiver::initialize()
{
    STOPWATCH(recv_stop_watch, "Receiver::initialize");
    Log::info("Initializing Receiver");

    field_ = make_unique<FField>(
        SmallModulus(get_params().exfield_characteristic()),
        get_params().exfield_degree());

    //slot_count_ = static_cast<int>(get_params().encryption_params().poly_modulus_degree() / get_params().exfield_degree());
    slot_count_ = get_params().batch_size();

    seal_context_ = SEALContext::Create(get_params().encryption_params());
    KeyGenerator generator(seal_context_);

    public_key_ = generator.public_key();
    secret_key_ = generator.secret_key();

    encryptor_ = make_unique<Encryptor>(seal_context_, public_key_);
    decryptor_ = make_unique<Decryptor>(seal_context_, secret_key_);

    // Initializing tools for dealing with compressed ciphertexts
    // We don't actually need the evaluator
    shared_ptr<Evaluator> dummy_evaluator = nullptr;
    compressor_ = make_unique<CiphertextCompressor>(seal_context_, 
        dummy_evaluator, pool_);


	auto key_material = generator.relin_keys_seeds_out(get_params().decomposition_bit_count()); 
	relin_keys_seeds_ = key_material.first;
	relin_keys_ = key_material.second;
    for (auto &a : relin_keys_.data())
    {
        if (a.size())
        {
            for (auto &b : a)
            {
                for (std::size_t i = 1; i < b.size(); i += 2)
                {
                    // Set seed-generated polynomial to zero
                    util::set_zero_poly(
                        b.poly_modulus_degree(), b.coeff_mod_count(), b.data(i));
                }
            }
        }
    }

    
    // relin_keys_ = generator.relin_keys(get_params().decomposition_bit_count());
    // relin_keys_ = generator.relin_keys(get_params().decomposition_bit_count());
    Log::info("Receiver initialized with relin keys seeds %i and %i", relin_keys_seeds_.first, relin_keys_seeds_.second); 

    ex_batch_encoder_ = make_shared<FFieldFastBatchEncoder>(seal_context_, *field_);

    Log::info("Receiver initialized");
}

std::pair<std::vector<bool>, Matrix<u8>> Receiver::query(vector<Item>& items, Channel& chl)
{
    STOPWATCH(recv_stop_watch, "Receiver::query");
    Log::info("Receiver starting query");
	if (items.size() > 10) {
		throw runtime_error("more than 10 queries is not supported"); 
	}

    if (nullptr == params_)
    {
        string msg = "Handshake has not been performed.";
        Log::error(msg.c_str());
        throw runtime_error(msg);
    }

    auto qq = preprocess(items, chl);
    auto& ciphertexts = qq.first;
    auto& cuckoo = *qq.second;

    chl.send_query(/*public_key_, */relin_keys_, ciphertexts, relin_keys_seeds_);

    auto table_to_input_map = cuckoo_indices(items, cuckoo);

    /* Receive results */
    SenderResponseQuery query_resp;
    {
        STOPWATCH(recv_stop_watch, "Receiver::query::wait_response");
        chl.receive(query_resp);
        Log::debug("Sender will send %i result packages", query_resp.package_count);
    }

    auto intersection = stream_decrypt(chl, table_to_input_map, items);

    Log::info("Receiver completed query");

    return intersection;
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

	Log::info("received sender bin size %i from sender: ", sender_params.psiconf_params.sender_bin_size); 

    // Set parameters from Sender.
    params_ = make_unique<PSIParams>(
        sender_params.psiconf_params,
        sender_params.table_params,
        sender_params.cuckoo_params,
        sender_params.seal_params,
        sender_params.exfield_params);

    Log::debug("Received parameters from Sender:");
    Log::debug(
        "item bit count: %i, sender size: %i, use OPRF: %s, use labels: %s",
        sender_params.psiconf_params.item_bit_count,
        sender_params.psiconf_params.sender_size,
        sender_params.psiconf_params.use_oprf ? "true" : "false",
        sender_params.psiconf_params.use_labels ? "true" : "false");
    Log::debug(
        "log table size: %i, split count: %i, binning sec level: %i, window size: %i",
        sender_params.table_params.log_table_size,
        sender_params.table_params.split_count,
        sender_params.table_params.binning_sec_level,
        sender_params.table_params.window_size);
    Log::debug(
        "hash func count: %i, hash func seed: %i, max probe: %i",
        sender_params.cuckoo_params.hash_func_count,
        sender_params.cuckoo_params.hash_func_seed,
        sender_params.cuckoo_params.max_probe);
    Log::debug(
        "decomposition bit count: %i, poly modulus degree: %i, plain modulus: 0x%llx",
        sender_params.seal_params.decomposition_bit_count,
        sender_params.seal_params.encryption_params.poly_modulus_degree(),
        sender_params.seal_params.encryption_params.plain_modulus().value());
    Log::debug("coeff modulus: %i elements", sender_params.seal_params.encryption_params.coeff_modulus().size());
    for (u64 i = 0; i < sender_params.seal_params.encryption_params.coeff_modulus().size(); i++)
    {
        Log::debug("Coeff modulus %i: 0x%llx", i, sender_params.seal_params.encryption_params.coeff_modulus()[i].value());
    }
    Log::debug(
        "exfield characteristic: 0x%llx, exfield degree: %i",
        sender_params.exfield_params.characteristic,
        sender_params.exfield_params.degree);

    // Once we have parameters, initialize Receiver
    initialize();

    Log::info("Handshake done");
}

pair<
    map<uint64_t, vector<SeededCiphertext> >,
    unique_ptr<CuckooTable> >
    Receiver::preprocess(vector<Item> &items, Channel &channel)
{
    STOPWATCH(recv_stop_watch, "Receiver::preprocess");
    Log::info("Receiver preprocess start");

    if (get_params().use_oprf())
    {
		Log::info("receiver preprocessing uses oprf"); 
        PRNG prng(zero_block);
        vector<vector<u64>> b;
        b.reserve(items.size());
        FourQCoordinate x;

        auto step = FourQCoordinate::byte_count();
        vector<u8> buff(items.size() * step);
        auto iter = buff.data();

        for (u64 i = 0; i < items.size(); i++)
        {
            x.random(prng);
            b.emplace_back(x.data(), x.data() + FourQCoordinate::word_count());

            PRNG pp(items[i], /* buffer_size */ 8);

            x.random(pp);
            x.multiply_mod_order(b[i].data());
            x.to_buffer(iter);

            iter += step;
        }

        // send the data over the network and prep for the response.
        channel.send_preprocess(buff);

        // compute 1/b so that we can compute (x^ba)^(1/b) = x^a
        for (u64 i = 0; i < items.size(); ++i)
        {
            FourQCoordinate inv(b[i].data());
            inv.inversion_mod_order();
            b[i] = vector<u64>(inv.data(), inv.data() + FourQCoordinate::word_count());
        }

        // Now we can receive response from Sender
        SenderResponsePreprocess sender_preproc;
        {
            STOPWATCH(recv_stop_watch, "Receiver::preprocess::wait_response");
            channel.receive(sender_preproc);
        }

        iter = sender_preproc.buffer.data();
        for (u64 i = 0; i < items.size(); i++)
        {
            x.from_buffer(iter);
            x.multiply_mod_order(b[i].data());
            x.to_buffer(iter);

            // Compress with BLAKE2b
            blake2(
                reinterpret_cast<uint8_t*>(items[i].data()),
                sizeof(items[i].get_value()),
                reinterpret_cast<const uint8_t*>(iter), step,
                nullptr, 0);

            iter += step;
        }
    }

	// find the item length 
    unique_ptr<CuckooTable> cuckoo = cuckoo_hashing(items);

    unique_ptr<FFieldArray> exfield_items;
    unsigned padded_cuckoo_capacity = static_cast<unsigned>(
        ((cuckoo->table_size() + slot_count_ - 1) / slot_count_) * slot_count_);

    exfield_items = make_unique<FFieldArray>(padded_cuckoo_capacity, *field_);
    exfield_encoding(*cuckoo, *exfield_items);

    map<uint64_t, FFieldArray> powers;
    generate_powers(*exfield_items, powers);

    map<uint64_t, vector<SeededCiphertext> > ciphers;
    encrypt(powers, ciphers);

    Log::info("Receiver preprocess end");

    return { move(ciphers), move(cuckoo) };
}

unique_ptr<CuckooTable> Receiver::cuckoo_hashing(const vector<Item> &items)
{
    auto receiver_null_item = all_one_block;

    unique_ptr<CuckooTable> cuckoo{ make_unique<CuckooTable>(
        get_params().log_table_size(),
        0, // stash size
        get_params().hash_func_count(),
        make_item(get_params().hash_func_seed(), 0),
        get_params().max_probe(),
        receiver_null_item) };

    auto coeff_bit_count = field_->ch().bit_count() - 1;
    auto degree = field_ ? field_->d() : 1;

    if (get_params().item_bit_count() > coeff_bit_count * degree)
    {
        Log::error("Reduced items too long. Only have %i bits.", coeff_bit_count * degree);
        throw runtime_error("Reduced items too long.");
    }
    else
    {
        Log::debug("Using %i out of %ix%i bits of exfield element",
            get_params().item_bit_count(),
            coeff_bit_count - 1,
            degree);
    }

    for (int i = 0; i < items.size(); i++)
    {
        auto cuckoo_item = make_item(items[i].get_value());
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
    cuckoo::CuckooTable &cuckoo)
{
    // This is the true size of the table; a multiple of slot_count_
    unsigned padded_cuckoo_capacity = static_cast<unsigned>(
        ((cuckoo.table_size() + slot_count_ - 1) / slot_count_) * slot_count_);

    vector<int> indices(padded_cuckoo_capacity, -1);
    auto& table = cuckoo.table();

    for (int i = 0; i < items.size(); i++)
    {
        auto cuckoo_item = make_item(items[i].get_value());
        auto q = cuckoo.query(cuckoo_item);
        indices[q.location()] = i;

        if (not_equal(cuckoo_item, table[q.location()]))
            throw runtime_error("items[i] different from encodings[q.location()]");
    }
    return indices;
}

void Receiver::exfield_encoding(
    CuckooTable &cuckoo,
    FFieldArray &ret)
{
    int item_bit_count = get_params().item_bit_count();
	if (get_params().use_oprf()) {
		item_bit_count = 120; // hardcoded.
	}
	Log::info("item bit count before decoding: %i", item_bit_count); 
	// oprf? depends 
	auto& encodings = cuckoo.table();

	Log::info("bit count of ptxt modulus = %i", ret.field().ch().bit_count());

    for (size_t i = 0; i < cuckoo.table_size(); i++)
    {
        ret.set(i, Item(encodings[i]).to_exfield_element(ret.field(), item_bit_count));
    }

    auto empty_field_item = Item(cuckoo.empty_item())
        .to_exfield_element(ret.field(), item_bit_count); 
    for (size_t i = cuckoo.table_size(); i < ret.size(); i++)
    {
        ret.set(i, empty_field_item);
    }
}

void Receiver::generate_powers(const FFieldArray &exfield_items,
    map<uint64_t, FFieldArray> &result)
{
    int split_size = (get_params().sender_bin_size() + get_params().split_count() - 1) / get_params().split_count();
    int window_size = get_params().window_size();
    int radix = 1 << window_size;
    int bound = static_cast<int>(floor(log2(split_size) / window_size) + 1);

    Log::debug("Generate powers: split_size %i, window_size %i, radix %i, bound %i",
        split_size, window_size, radix, bound);

    FFieldArray current_power = exfield_items;
    for (uint64_t j = 0; j < bound; j++)
    {
        result.emplace(1ULL << (window_size * j), current_power);
        for (uint64_t i = 2; i < radix; i++)
        {
            if (i * (1ULL << (window_size * j)) > split_size)
            {
                return;
            }
            result.emplace(i * (1ULL << (window_size * j)), result.at((i - 1) * (1ULL << (window_size * j))) * current_power);
        }
        for (int k = 0; k < window_size; k++)
        {
            current_power.sq();
        }
    }
}

void Receiver::encrypt(map<uint64_t, FFieldArray> &input, map<uint64_t, vector<SeededCiphertext>> &destination)
{
    // debugging
    int count = 0; 
    destination.clear();
    for (auto it = input.begin(); it != input.end(); it++)
    {
        encrypt(it->second, destination[it->first]);
        count += (it->second.size() + slot_count_ - 1) / slot_count_; 
    }
    Log::info("receiver sending %i ciphertexts", count); 
}

void Receiver::encrypt(const FFieldArray &input, vector<SeededCiphertext> &destination)
{
    int batch_size = slot_count_, num_of_batches = static_cast<int>((input.size() + batch_size - 1) / batch_size);
    vector<uint64_t> integer_batch(batch_size, 0);
    destination.clear();
    destination.reserve(num_of_batches);
    Plaintext plain(pool_);
    FFieldArray batch(ex_batch_encoder_->create_array());
    random_device rd;
    for (int i = 0; i < num_of_batches; i++)
    {
        for (int j = 0; j < batch_size; j++)
        {
            batch.set(j, i * batch_size + j, input);
        }
        ex_batch_encoder_->compose(batch, plain);
		seed128 seeds_placeholder;
        destination.push_back({seeds_placeholder,  Ciphertext(seal_context_, pool_)});
        seed128 seeds = encryptor_->encrypt_sk_seeds_out(plain, destination.back().second, secret_key_,  pool_);
		destination.back().first = seeds;
		Log::info("Seeds = %i, %i", seeds.first, seeds.second);
		// debug 
        // note: this is not doing the setting to zero yet. s
        Log::info("Fresh encryption noise budget = %i", decryptor_->invariant_noise_budget(destination.back().second)); 
        seal::util::set_zero_poly(destination.back().second.poly_modulus_degree(), destination.back().second.coeff_mod_count(), destination.back().second.data(1));
        //Log::info("cipher after setting to zero : ");
        //for (int i = 0; i< 10; i++)
        //    Log::info("(%i, %i)", i, destination.back().second.data(1)[i]); 
    }
}

std::pair<std::vector<bool>, Matrix<u8>> Receiver::stream_decrypt(
    Channel& channel,
    const std::vector<int> &table_to_input_map,
    std::vector<Item> &items)
{


    STOPWATCH(recv_stop_watch, "Receiver::stream_decrypt");
    std::pair<std::vector<bool>, Matrix<u8>> ret;
    auto& ret_bools = ret.first;
    auto& ret_labels = ret.second;

    ret_bools.resize(items.size(), false);

    if (get_params().use_labels())
    {
        ret_labels.resize(items.size(), get_params().get_label_byte_count());
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
    for (u64 t = 0; t < thrds.size(); ++t)
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

    return std::move(ret);
}

void Receiver::stream_decrypt_worker(
    int thread_idx,
    int batch_size,
    int num_threads,
    int block_count,
    Channel& channel,
    const vector<int> &table_to_input_map,
    vector<bool>& ret_bools,
    Matrix<u8>& ret_labels)
{
    STOPWATCH(recv_stop_watch, "Receiver::stream_decrypt_worker");
    MemoryPoolHandle local_pool(MemoryPoolHandle::New());
    Plaintext p(local_pool);
    Ciphertext tmp(seal_context_, local_pool);
    unique_ptr<FFieldArray> batch = make_unique<FFieldArray>(ex_batch_encoder_->create_array());

    bool has_result;
    std::vector<char> has_label(batch_size);

    bool first = true;
    u64 processed_count = 0;

    for (u64 i = thread_idx; i < block_count; i += num_threads)
    {
        ResultPackage pkg;
        {
            STOPWATCH(recv_stop_watch, "Receiver::stream_decrypt_worker_wait");
            channel.receive(pkg);
        }

        auto base_idx = pkg.batch_idx * batch_size;

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
        ex_batch_encoder_->decompose(p, *batch);

        // cout << "Batch = " << pkg.batch_idx << "; Returned array size: " << batch->size() << " / batch_size = " << batch_size << "; degree = " << batch->field().d() << endl;

        for (int k = 0; k < batch_size; k++)
        {
            auto idx = table_to_input_map[base_idx + k];
            if (idx >= 0)
            {
                auto &is_zero = has_label[k];

                is_zero = batch->is_zero(k);
                //cout << "Item at slot " << k << ": ";
                //for (size_t a = 0; a < batch->field().d(); a++)
                //{
                    //cout << batch->get_coeff_of(k, a) << " ";
                //}
                //cout << endl;

                if (is_zero)
                {
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
            p.resize(static_cast<i32>(ex_batch_encoder_->n()));

            ex_batch_encoder_->decompose(p, *batch);

            for (int k = 0; k < batch_size; k++)
            {
                if (has_label[k])
                {
                    auto idx = table_to_input_map[base_idx + k];
                    batch->get(k).decode(ret_labels[idx], get_params().get_label_bit_count());
                }
            }
        }

        processed_count++;
    }

    Log::debug("Thread %d processed %d blocks.", thread_idx, processed_count);
}
