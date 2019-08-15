// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

// STD
#include <memory>
#include <thread>

// APSI
#include "apsi/senderdb.h"
#include "apsi/apsidefines.h"
#include "apsi/tools/prng.h"
#include "apsi/tools/fourq.h"
#include "apsi/tools/blake2/blake2.h"

// SEAL
#include <seal/evaluator.h>

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace apsi;
using namespace apsi::tools;
using namespace apsi::sender;
using namespace apsi::logging;

SenderDB::SenderDB(const PSIParams &params, 
    shared_ptr<SEALContext> &seal_context, 
    FField field) :
    params_(params),
    seal_context_(seal_context),
    field_(field),
    null_element_(field_),
    neg_null_element_(field_),
    next_locs_(params.table_size(), 0),
    batch_random_symm_poly_storage_(params.split_count() * params.batch_count() * (params.split_size() + 1))
{
    for (auto &plain : batch_random_symm_poly_storage_)
    {
        // Reserve memory for ciphertext size plaintexts (NTT transformed mod q)
        plain.reserve(static_cast<int>(params_.encryption_params().coeff_modulus().size() *
            params_.encryption_params().poly_modulus_degree()));
    }

#ifdef USE_SECURE_SEED
    prng_.set_seed(sys_random_seed());
#else
    TODO("***************** INSECURE *****************, define USE_SECURE_SEED to fix");
    prng_.set_seed(one_block, /* buffer_size */ 256);
#endif

    // Set null value for sender: 1111...1110 (128 bits)
    // Receiver's null value comes from the Cuckoo class: 1111...1111
    sender_null_item_[0] = ~1;
    sender_null_item_[1] = ~0;

    // What is the actual length of strings stored in the hash table
    encoding_bit_length_ = params.item_bit_count();

    // Create the null ExFieldElement (note: encoding truncation affects high bits)
    null_element_ = sender_null_item_.to_exfield_element(field_, encoding_bit_length_);
    neg_null_element_ = -null_element_;

    int batch_size = params_.batch_size();
    int split_size = params_.split_size();

    // debugging 
    int num_ctxts = params_.batch_count() * params_.sender_bin_size(); 
	if (params_.sender_size() > pow(2, 16)) {
		throw runtime_error("sender size must be bounded by 65536."); 
	}
    Log::info("sender size = %i", params_.sender_size());
    Log::info("table size = %i", params_.table_size());
    Log::info("sender bin size = %i", params_.sender_bin_size());
    Log::info("split size = %i", split_size); 
    Log::info("number of ciphertexts in senderdb = %i", num_ctxts);

    int byte_length = static_cast<int>(round_up_to(params_.get_label_bit_count(), 8) / 8);
    int nb = params_.batch_count();
    int ns = params_.split_count();
    db_blocks_.resize(nb, ns);

    for (int b_idx = 0; b_idx < nb; b_idx++)
    {
        for (int s_idx = 0; s_idx < ns; s_idx++)
        {
            db_blocks_(b_idx, s_idx)->init(
                b_idx, s_idx,
                byte_length,
                batch_size,
                split_size);
        }
    }
}

void SenderDB::clear_db()
{
    for (auto& block : db_blocks_)
        block.clear();
}

void SenderDB::set_data(gsl::span<const Item> data, int thread_count)
{
    set_data(data, {}, thread_count);
}

void SenderDB::set_data(gsl::span<const Item> data, MatrixView<u8> vals, int thread_count)
{
    STOPWATCH(sender_stop_watch, "SenderDB::set_data");
    clear_db();
    add_data(data, vals, thread_count);
}

void SenderDB::add_data(gsl::span<const Item> data, MatrixView<u8> values, int thread_count)
{
    STOPWATCH(sender_stop_watch, "SenderDB::add_data");

    if (values.stride() != params_.get_label_byte_count())
        throw std::invalid_argument("unexpacted label length");

    vector<thread> thrds(thread_count);
    for (int t = 0; t < thrds.size(); t++)
    {
        auto seed = prng_.get<block>();
        thrds[t] = thread([&, t, seed](int idx)
        {
            add_data_worker(idx, thread_count, seed, data, values);
        }, t);
    }

    for (auto &t : thrds)
    {
        t.join();
    }

    bool validate = false;
    if (validate)
    {

        vector<cuckoo::LocFunc> normal_loc_func;
        for (int i = 0; i < params_.hash_func_count(); i++)
        {
            normal_loc_func.emplace_back(cuckoo::LocFunc(
                params_.log_table_size(),
                cuckoo::make_item(params_.hash_func_seed() + i, 0)));
        }


        for (i64 i = 0; i < data.size(); ++i)
        {

            // Claim an emply location in each matching bin
            for (unsigned j = 0; j < params_.hash_func_count(); j++)
            {
                Item key;
                u64 cuckoo_loc;

                // Compute bin locations
                auto cuckoo_item = cuckoo::make_item(data[i].get_value());
                cuckoo_loc = normal_loc_func[j](cuckoo_item);
                key = data[i];

                // Lock-free thread-safe bin position search
                DBBlock::Position pos;
                auto batch_idx = cuckoo_loc / params_.batch_size();
                pos.batch_offset = cuckoo_loc % params_.batch_size();

                auto count = 0;
                for (u64 j = 0; j < db_blocks_.columns(); ++j)
                {
                    auto &blk = *db_blocks_(batch_idx, j);
                    ;
                    for (pos.split_offset = 0;
                        pos.split_offset < blk.items_per_split_;
                        ++pos.split_offset)
                    {
                        if (blk.has_item(pos) &&
                            blk.get_key(pos) == key)
                        {
                            ++count;
                        }
                    }
                }

                if (count != 1)
                    throw std::runtime_error("");
            }
        }
    }
}

void SenderDB::add_data_worker(int thread_idx, int thread_count, const block& seed, gsl::span<const Item> data, MatrixView<u8> values)
{
    STOPWATCH(sender_stop_watch, "SenderDB::add_data_worker");

    PRNG prng(seed, /* buffer_size */ 256);
    u64 start = thread_idx * data.size() / thread_count;
    u64 end = (thread_idx + 1) * data.size() / thread_count;

    vector<u8> buff(FourQCoordinate::byte_count());
    PRNG pp(cc_block);
    FourQCoordinate key(pp);

    vector<cuckoo::LocFunc> normal_loc_func;
    for (int i = 0; i < params_.hash_func_count(); i++)
    {
        normal_loc_func.emplace_back(
            params_.log_table_size(),
            cuckoo::make_item(params_.hash_func_seed() + i, 0));
    }

    map<int, int> bin_counting_map;
    for (int i = 0; i < params_.table_size(); i++) {
        bin_counting_map[i] = 0;
    }
    int maxload = 0; 
    


    for (size_t i = start; i < end; i++)
    {
        // Do we do OPRF for Sender's security?
        if (params_.use_oprf())
        {
            // Compute EC PRF first for data
            PRNG p(data[i], /* buffer_size */ 8);
            FourQCoordinate a(p);
            a.multiply_mod_order(key);
            a.to_buffer(buff.data());

            // Then compress with BLAKE2b
            blake2(
                reinterpret_cast<uint8_t*>(const_cast<uint64_t*>(data[i].data())),
                sizeof(block),
                reinterpret_cast<const uint8_t*>(buff.data()), buff.size(),
                nullptr, 0);
        }
        std::vector<u64> locs(params_.hash_func_count());
        std::vector<Item> keys(params_.hash_func_count());
        std::vector<bool> skip(params_.hash_func_count());

        // std::array<Item, params_.hash_func_count()> keys;
        //std::array<bool, params_.hash_func_count()> skip{ false, false, false };

        // Compute bin locations
		// Set keys and skip
        auto cuckoo_item = cuckoo::make_item(data[i].get_value());
        // Set keys and skip
        for (int j = 0; j < params_.hash_func_count(); j++) {
            locs[j] = normal_loc_func[j](cuckoo_item);
            //locs[1] = normal_loc_func[1].location(data[i]);
            //locs[2] = normal_loc_func[2].location(data[i]);
            keys[j] = data[i]; 
            skip[j] = false;
            if (j > 0) { // check if same. 
                for (int k = 0; k < j; k++) {
                    if (locs[j] == locs[k]) {
                        skip[j] = true; 
                        break; 
                    }
                }
            }
        }
        // keys[0] = keys[1] = keys[2] = data[i];
        //skip[1] = locs[0] == locs[1];
        //skip[2] = locs[0] == locs[2] || locs[1] == locs[2];
        // printing some info: 
        // in particular, printing stuff....



        // Claim an empty location in each matching bin
        for (unsigned j = 0; j < params_.hash_func_count(); j++)
        {
            // debugging
            bin_counting_map[locs[j]] ++;
            if (bin_counting_map[locs[j]] > maxload) {
                maxload = bin_counting_map[locs[j]]; 
            }
            if (skip[j] == false)
            {

                // Lock-free thread-safe bin position search
                auto block_pos = acquire_db_position(locs[j], prng);
                auto& db_block = *block_pos.first;
                auto pos = block_pos.second;


                db_block.get_key(pos) = keys[j];

                if (params_.use_labels())
                {
                    auto dest = db_block.get_label(pos);
                    memcpy(dest, values[i].data(), params_.get_label_byte_count());
                }
            }
        }
    }
    // debugging: print the bin load 
    Log::info("max load for thread %i = %i", thread_idx, maxload);

}

void SenderDB::add_data(gsl::span<const Item> data, int thread_count)
{
    add_data(data, {}, thread_count);
}

std::pair<DBBlock*, DBBlock::Position>
    SenderDB::acquire_db_position(size_t cuckoo_loc, PRNG &prng)
{
    auto batch_idx = cuckoo_loc / params_.batch_size();
    auto batch_offset = cuckoo_loc % params_.batch_size();

    auto s_idx = prng.get<u32>() % db_blocks_.stride();
    for (int i = 0; i < db_blocks_.stride(); ++i)
    {
        auto pos = db_blocks_(batch_idx, s_idx)->try_aquire_position(batch_offset, prng);
        if (pos.is_initialized())
        {
            return { db_blocks_(batch_idx, s_idx) , pos };
        }

        s_idx = (s_idx + 1) % db_blocks_.stride();
    }

    // Throw an error because bin overflowed
    throw runtime_error("simple hashing failed due to bin overflow");
}

void SenderDB::add_data(const Item &item, int thread_count)
{
    add_data(vector<Item>(1, item), thread_count);
}

void SenderDB::batched_randomized_symmetric_polys(
    SenderThreadContext &context,
    int start_block,
    int end_block,
    shared_ptr<Evaluator> evaluator,
    shared_ptr<FFieldFastBatchEncoder> ex_batch_encoder)
{
    // Get the symmetric block
    auto symm_block = context.symm_block();

    int table_size = params_.table_size(),
        batch_size = params_.batch_size(),
        split_size_plus_one = params_.split_size() + 1;

    FFieldArray batch_vector(batch_size, context.field());
    vector<uint64_t> integer_batch_vector(batch_size);

    // Data in batch-split table is stored in "batch-major order"
    auto indexer = [splitStep = params_.batch_count() * split_size_plus_one,
        batchStep = split_size_plus_one](int splitIdx, int batchIdx)
    {
        return splitIdx * splitStep + batchIdx * batchStep;
    };

    MemoryPoolHandle local_pool = context.pool();

    for (int next_block = start_block; next_block < end_block; next_block++)
    {
        int split = next_block / params_.batch_count();
        int batch = next_block % params_.batch_count();

        int batch_start = batch * batch_size,
            batch_end = batch_start + batch_size;
            //batch_end = (batch_start + batch_size < table_size ? (batch_start + batch_size) : table_size);

        auto &block = db_blocks_.data()[next_block];
        block.randomized_symmetric_polys(context, symm_block, encoding_bit_length_, neg_null_element_);
        block.batch_random_symm_poly_ = { &batch_random_symm_poly_storage_[indexer(split, batch)] , split_size_plus_one };

        for (int i = 0; i < split_size_plus_one; i++)
        {
            Plaintext &poly = block.batch_random_symm_poly_[i];

            // This branch works even if ex_field_ is an integer field, but it is slower than normal batching.
            for (int k = 0; batch_start + k < batch_end; k++)
            {
                copy_n(symm_block(k, i), batch_vector.field().d(), batch_vector.data(k));
                //fq_nmod_set(batch_vector.data() + k, &symm_block(k, i), batch_vector.field(k)->ctx());
            }
            ex_batch_encoder->compose(batch_vector, poly);
            evaluator->transform_to_ntt_inplace(poly, seal_context_->first_parms_id(), local_pool);
        }

        context.inc_randomized_polys();
    }
}

void SenderDB::batched_interpolate_polys(
    SenderThreadContext &th_context,
    int start_block,
    int end_block,
    shared_ptr<Evaluator> evaluator,
    shared_ptr<FFieldFastBatchEncoder> ex_batch_encoder)
{
    auto &mod = params_.encryption_params().plain_modulus();

    DBInterpolationCache cache(ex_batch_encoder, params_.batch_size(), params_.split_size(), params_.get_label_byte_count());
    // minus 1 to be safe.
    auto coeffBitCount = seal::util::get_significant_bit_count(mod.value()) - 1;
    u64 degree = 1;
    if (ex_batch_encoder)
    {
        degree = ex_batch_encoder->d();
    }

    if (params_.get_label_bit_count() >= coeffBitCount * degree)
    {
        throw std::runtime_error("labels are too large for exfield.");
    }

    for (int bIdx = start_block; bIdx < end_block; bIdx++)
    {
        auto &block = *db_blocks_(bIdx);
        block.batch_interpolate(th_context, seal_context_, evaluator, ex_batch_encoder, cache, params_);
        th_context.inc_interpolate_polys();
    }
}
