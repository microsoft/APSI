// STD
#include <sstream>
#include <map>

// APSI
#include "apsi/sender/sender.h"
#include "apsi/receiver/receiver.h"
#include "apsi/apsidefines.h"
#include "apsi/logging/log.h"
#include "apsi/network/network_utils.h"
#include "apsi/network/channel.h"
#include "apsi/tools/ec_utils.h"
#include "apsi/tools/prng.h"
#include "apsi/tools/utils.h"
#include "apsi/result_package.h"

// SEAL
#include "seal/util/common.h"
#include "seal/util/uintcore.h"
#include "seal/encryptionparams.h"
#include "seal/keygenerator.h"

// CryptoPP
#include "cryptopp/sha3.h"

// FourQ
#include "FourQ_api.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace cuckoo;
using namespace apsi;
using namespace apsi::logging;
using namespace apsi::tools;
using namespace apsi::network;
using namespace apsi::receiver;


Receiver::Receiver(const PSIParams &params, int thread_count, const MemoryPoolHandle &pool) :
    params_(params),
    thread_count_(thread_count),
    pool_(pool),
    ex_field_(FField::Acquire(params.exfield_characteristic(), params.exfield_degree())),
    slot_count_((params_.encryption_params().poly_modulus_degree() / params_.exfield_degree()))
{
    if (thread_count_ <= 0)
    {
        throw invalid_argument("thread_count must be positive");
    }

    initialize();
}

void Receiver::initialize()
{
    StopwatchScope init_receiver(recv_stop_watch, "Receiver::initialize");
    Log::info("Initializing Receiver");

    seal_context_ = SEALContext::Create(params_.encryption_params());
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

    relin_keys_ = generator.relin_keys(params_.decomposition_bit_count());

    ex_batch_encoder_ = make_shared<FFieldFastBatchEncoder>(ex_field_->ch(), ex_field_->d(),
        get_power_of_two(params_.encryption_params().poly_modulus_degree()));

    Log::info("Receiver initialized");
}

std::pair<std::vector<bool>, Matrix<u8>> Receiver::query(vector<Item>& items, Channel& chl)
{
    StopwatchScope recv_query(recv_stop_watch, "Receiver::query");
    Log::info("Receiver starting query");

    // Perform initial communication with Sender
    handshake(chl);

    auto qq = preprocess(items, chl);
    auto& ciphertexts = qq.first;
    auto& cuckoo = *qq.second;

    chl.send_query(public_key_, relin_keys_, ciphertexts);

    auto table_to_input_map = cuckoo_indices(items, cuckoo);

    /* Receive results */
    SenderResponseQuery query_resp;
    {
        StopwatchScope qryw_sc(recv_stop_watch, "Receiver::query::wait_response");
        chl.receive(query_resp);
    }

    auto intersection = decrypt(query_resp.result, table_to_input_map, items);

    Log::info("Receiver completed query");

    return intersection;
}

void Receiver::handshake(Channel& chl)
{
    StopwatchScope rcvr_hndshk_scope(recv_stop_watch, "Receiver::handshake");
    Log::info("Initial handshake");

    SenderResponseGetParameters sender_params;
    chl.send_get_parameters();

    {
        StopwatchScope wait_hnd_sc(recv_stop_watch, "Receiver::handshake::wait_response");
        chl.receive(sender_params);
    }

    // Set parameters we got from Sender.
    Log::debug("Set item bit count to %i", sender_params.item_bit_count);
    params_.set_item_bit_count(sender_params.item_bit_count);

    Log::debug("Set label bit count to %i", sender_params.label_bit_count);
    params_.set_value_bit_count(sender_params.label_bit_count);

    Log::debug("Set sender bin size to %i", sender_params.sender_bin_size);
    params_.set_sender_bin_size(sender_params.sender_bin_size);
 
    if (sender_params.use_oprf)
    {
        Log::debug("Sender is using OPRF. Turning on.");
    }
    else
    {
        Log::debug("Sender is not using OPRF. Turning off.");
    }
    params_.set_use_oprf(sender_params.use_oprf);

    Log::info("Handshake done");
}

pair<
    map<uint64_t, vector<Ciphertext> >,
    unique_ptr<CuckooInterface> >
    Receiver::preprocess(vector<Item> &items, Channel &channel)
{
    StopwatchScope preprocess_scope(recv_stop_watch, "Receiver::preprocess");
    Log::info("Receiver preprocess start");

    if (params_.use_oprf())
    {
        PRNG prng(zero_block);
        vector<vector<digit_t>> b;
        b.reserve(items.size());
        digit_t x[NWORDS_ORDER];

        auto step = (sizeof(digit_t) * NWORDS_ORDER) - 1;
        vector<u8> buff(items.size() * step);
        auto iter = buff.data();
        for (u64 i = 0; i < items.size(); i++)
        {
            random_fourq(x, prng);
            b.emplace_back(x, x + NWORDS_ORDER);

            PRNG pp(items[i], /* buffer_size */ 8);

            random_fourq(x, pp);
            Montgomery_multiply_mod_order(x, b[i].data(), x);
            eccoord_to_buffer(x, iter);
            iter += step;
        }

        // send the data over the network and prep for the response.
        channel.send_preprocess(buff);

        // compute 1/b so that we can compute (x^ba)^(1/b) = x^a
        for (u64 i = 0; i < items.size(); ++i)
        {
            digit_t inv[NWORDS_ORDER];
            Montgomery_inversion_mod_order(b[i].data(), inv);
            b[i] = vector<digit_t>(inv, inv + NWORDS_ORDER);
        }

        // Now we can receive response from Sender
        SenderResponsePreprocess sender_preproc;
        {
            StopwatchScope rcv_ppwait_sc(recv_stop_watch, "Receiver::preprocess::wait_response");
            channel.receive(sender_preproc);
        }

        iter = sender_preproc.buffer.data();
        for (u64 i = 0; i < items.size(); i++)
        {
            buffer_to_eccoord(iter, x);
            Montgomery_multiply_mod_order(x, b[i].data(), x);
            eccoord_to_buffer(x, iter);

            // Compress with SHA3
            CryptoPP::SHA3_256 sha;
            sha.Update(iter, step);
            sha.TruncatedFinal(reinterpret_cast<CryptoPP::byte*>(&items[i]), sizeof(block));

            iter += step;
        }
    }

    unique_ptr<CuckooInterface> cuckoo = cuckoo_hashing(items);

    unique_ptr<FFieldArray> exfield_items;
    unsigned padded_cuckoo_capacity = static_cast<unsigned>(((cuckoo->table_size() + slot_count_ - 1) / slot_count_) * slot_count_);

    vector<shared_ptr<FField> > field_vec;
    field_vec.reserve(padded_cuckoo_capacity);
    for (unsigned i = 0; i < padded_cuckoo_capacity; i++)
    {
        field_vec.emplace_back(ex_batch_encoder_->field(i % slot_count_));
    }

    exfield_items = make_unique<FFieldArray>(field_vec);
    exfield_encoding(*cuckoo, *exfield_items);

    map<uint64_t, FFieldArray> powers;
    generate_powers(*exfield_items, powers);

    map<uint64_t, vector<Ciphertext> > ciphers;
    encrypt(powers, ciphers);

    Log::info("Receiver preprocess end");

    return { move(ciphers), move(cuckoo) };
}

unique_ptr<CuckooInterface> Receiver::cuckoo_hashing(const vector<Item> &items)
{
    auto receiver_null_item = all_one_block;

    unique_ptr<CuckooInterface> cuckoo(
        static_cast<CuckooInterface*>(new Cuckoo(
            params_.hash_func_count(),
            params_.hash_func_seed(),
            params_.log_table_size(),
            params_.item_bit_count(),
            params_.max_probe(),
            receiver_null_item))
    );

    auto coeff_bit_count = seal::util::get_significant_bit_count(ex_field_->ch()) - 1;
    auto degree = ex_field_ ? ex_field_->d() : 1;

    if (cuckoo->encoding_bit_length() > coeff_bit_count * degree)
    {
        Log::error("Reduced items too long. Only have %i bits.", coeff_bit_count * degree);
        throw runtime_error("Reduced items too long.");
    }
    else
    {
        Log::debug("Using %i out of %ix%i bits of exfield element",
            cuckoo->encoding_bit_length(),
            seal::util::get_significant_bit_count(params_.exfield_characteristic()) - 1,
            degree);
    }

    bool insertionSuccess;
    for (int i = 0; i < items.size(); i++)
    {
        insertionSuccess = cuckoo->insert(items[i]);
        if (!insertionSuccess)
            throw logic_error("Cuckoo hashing failed.");
    }

    return cuckoo;
}


vector<int> Receiver::cuckoo_indices(const vector<Item> &items, cuckoo::CuckooInterface &cuckoo)
{
    vector<int> indice(cuckoo.table_size(), -1);
    auto& encodings = cuckoo.get_encodings();

    for (int i = 0; i < items.size(); i++)
    {
        auto q = cuckoo.query_item(items[i]);
        indice[q.table_index()] = i;

        if (not_equal(items[i], encodings[q.table_index()]))
            throw runtime_error("items[i] different from encodings[q.table_index()]");
    }
    return indice;
}

void Receiver::exfield_encoding(
    CuckooInterface &cuckoo,
    FFieldArray &ret)
{
    int encoding_bit_length = static_cast<int>(cuckoo.encoding_bit_length());
    auto encoding_u64_len = round_up_to(encoding_bit_length, 64) / 64;

    auto& encodings = cuckoo.get_encodings();

    for (int i = 0; i < cuckoo.table_size(); i++)
    {
        ret.set(i, Item(encodings[i]).to_exfield_element(ret.field(i), encoding_bit_length));
    }
    for (size_t i = cuckoo.table_size(); i < ret.size(); i++)
    {
        ret.set(i, Item(cuckoo.null_value()).to_exfield_element(ret.field(i), encoding_bit_length));
    }
}

void Receiver::generate_powers(const FFieldArray &exfield_items,
    map<uint64_t, FFieldArray> &result)
{
    int split_size = (params_.sender_bin_size() + params_.split_count() - 1) / params_.split_count();
    int window_size = params_.window_size();
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

void Receiver::encrypt(map<uint64_t, FFieldArray> &input, map<uint64_t, vector<Ciphertext>> &destination)
{
    destination.clear();
    for (auto it = input.begin(); it != input.end(); it++)
    {
        encrypt(it->second, destination[it->first]);
    }
}

void Receiver::encrypt(const FFieldArray &input, vector<Ciphertext> &destination)
{
    int batch_size = slot_count_, num_of_batches = static_cast<int>((input.size() + batch_size - 1) / batch_size);
    vector<uint64_t> integer_batch(batch_size, 0);
    destination.clear();
    destination.reserve(num_of_batches);
    Plaintext plain(pool_);
    FFieldArray batch(ex_batch_encoder_->create_array());
    for (int i = 0; i < num_of_batches; i++)
    {
        for (int j = 0; j < batch_size; j++)
        {
            batch.set(j, i * batch_size + j, input);
        }
        ex_batch_encoder_->compose(batch, plain);
        destination.emplace_back(seal_context_, pool_);
        encryptor_->encrypt(plain, destination.back(), pool_);
    }
}

std::pair<std::vector<bool>, Matrix<u8>> Receiver::decrypt(
    const vector<ResultPackage>& result,
    const std::vector<int> &table_to_input_map,
    std::vector<Item> &items)
{
    StopwatchScope decrypt_scope(recv_stop_watch, "Receiver::decrypt");
    std::pair<std::vector<bool>, Matrix<u8>> ret;
    auto& ret_bools = ret.first;
    auto& ret_labels = ret.second;

    ret_bools.resize(items.size(), false);

    if (params_.get_label_bit_count())
    {
        ret_labels.resize(items.size(), params_.get_label_byte_count());
    }

    int num_of_splits = params_.split_count(),
        num_of_batches = params_.batch_count(),
        block_count = num_of_splits * num_of_batches,
        batch_size = slot_count_;

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
            decrypt_worker(
                idx,
                batch_size,
                thread_count_,
                result,
                table_to_input_map,
                ret_bools,
                ret_labels);
        }, static_cast<int>(t));
    }

    for (auto& thrd : thrds)
        thrd.join();

    return std::move(ret);
}

void Receiver::decrypt_worker(
    int thread_idx,
    int batch_size,
    int num_threads,
    const vector<ResultPackage>& result,
    const vector<int> &table_to_input_map,
    vector<bool>& ret_bools,
    Matrix<u8>& ret_labels)
{
    StopwatchScope recv_str_decr_wkr_scope(recv_stop_watch, "Receiver::decrypt_worker");
    MemoryPoolHandle local_pool(MemoryPoolHandle::New());
    Plaintext p(local_pool);
    Ciphertext tmp(seal_context_, local_pool);
    unique_ptr<FFieldArray> batch = make_unique<FFieldArray>(ex_batch_encoder_->create_array());
    vector<uint64_t> integer_batch(batch_size);

    bool has_result;
    std::vector<char> has_label(batch_size);

    bool first = true;

    for (u64 i = thread_idx; i < result.size(); i += num_threads)
    {
        auto& pkg = result[i];

        auto base_idx = pkg.batch_idx * batch_size;

        // recover the sym poly values 
        has_result = false;
        stringstream ss(pkg.data);
        compressor_->compressed_load(ss, tmp);

        if (first && thread_idx == 0)
        {
            first = false;
            Log::debug("Noise budget: %i bits", decryptor_->invariant_noise_budget(tmp, local_pool));
        }

        decryptor_->decrypt(tmp, p, local_pool);
        ex_batch_encoder_->decompose(p, *batch);

        for (int k = 0; k < integer_batch.size(); k++)
        {
            auto &is_zero = has_label[k];
            auto idx = table_to_input_map[base_idx + k];

            is_zero = batch->is_zero(k);

            if (is_zero)
            {
                has_result = true;
                ret_bools[idx] = true;
            }
        }

        if (has_result && params_.get_label_bit_count())
        {
            std::stringstream ss(pkg.label_data);

            compressor_->compressed_load(ss, tmp);

            decryptor_->decrypt(tmp, p, local_pool);

            // make sure its the right size. decrypt will shorted when there are zero coeffs at the top.
            p.resize(static_cast<i32>(ex_batch_encoder_->n()));

            ex_batch_encoder_->decompose(p, *batch);

            for (int k = 0; k < integer_batch.size(); k++)
            {
                if (has_label[k])
                {
                    auto idx = table_to_input_map[base_idx + k];
                    batch->get(k).decode(ret_labels[idx], params_.get_label_bit_count());
                }
            }
        }
    }
}
