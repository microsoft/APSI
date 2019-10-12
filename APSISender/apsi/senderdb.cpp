// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <memory>
#include <thread>

// APSI
#include "apsi/senderdb.h"
#include "apsi/apsidefines.h"
#include "apsi/tools/prng.h"
#include "apsi/tools/fourq.h"

// SEAL
#include <seal/evaluator.h>
#include <seal/util/blake2.h>

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
    if (params_.use_oprf()) {
        encoding_bit_length_ = params.item_bit_length_used_after_oprf();
        Log::debug("encoding bit length = %i", encoding_bit_length_); 
    }

    // Create the null ExFieldElement (note: encoding truncation affects high bits)
    null_element_ = sender_null_item_.to_exfield_element(field_, encoding_bit_length_);
    neg_null_element_ = -null_element_;

    int batch_size = params_.batch_size();
    int split_size = params_.split_size();

    // debugging 
    int num_ctxts = params_.batch_count() * params_.sender_bin_size(); 
    Log::debug("sender size = %i", params_.sender_size());
    Log::debug("table size = %i", params_.table_size());
    Log::debug("sender bin size = %i", params_.sender_bin_size());
    Log::debug("split size = %i", split_size); 
    Log::debug("number of ciphertexts in senderdb = %i", num_ctxts);
    Log::debug("number of hash functions = %i", params_.hash_func_count());
    int byte_length = static_cast<int>(round_up_to(params_.get_label_bit_count(), 8) / 8);
    int nb = params_.batch_count();

    // here, need to make split count larger to fit
    // another place the split count is modified is after add_data.
    int ns = (params_.sender_bin_size() + params_.split_size() - 1) / params_.split_size(); 
    params_.set_split_count(ns);
    params_.set_sender_bin_size(ns * params_.split_size());

    // important: here it resizes the db blocks.
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

    batch_random_symm_poly_storage_.resize(params_.split_count() * params_.batch_count() * (params_.split_size() + 1));
    for (auto& plain : batch_random_symm_poly_storage_)
    {
        // Reserve memory for ciphertext size plaintexts (NTT transformed mod q)
        plain.reserve(static_cast<int>(params_.encryption_params().coeff_modulus().size() *
            params_.encryption_params().poly_modulus_degree()));
    }

}

void SenderDB::clear_db()
{
    if (batch_random_symm_poly_storage_[0].is_ntt_form())
    {
        // Clear all storage
        for (auto& plain : batch_random_symm_poly_storage_)
        {
            plain.release();
            plain.reserve(static_cast<int>(params_.encryption_params().coeff_modulus().size() *
                params_.encryption_params().poly_modulus_degree()));
        }
    }

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


    bool fm = get_params().use_fast_membership();
    if (fm) {
        Log::debug("Fast membership: add data with no hashing");
        add_data_no_hash(data, vals); 
    }
    else {
        add_data(data, vals, thread_count);
    }
}

void SenderDB::add_data(gsl::span<const Item> data, MatrixView<u8> values, int thread_count)
{
    STOPWATCH(sender_stop_watch, "SenderDB::add_data");

    if (values.stride() != params_.get_label_byte_count())
        throw std::invalid_argument("unexpacted label length");

    vector<thread> thrds(thread_count);


    vector<vector<int>> thread_loads(thread_count);
    for (int t = 0; t < thrds.size(); t++)
    {
        auto seed = prng_.get<block>();
        thrds[t] = thread([&, t, seed](int idx)
        {
            add_data_worker(idx, thread_count, seed, data, values, thread_loads[t]);
        }, t);
    }

    for (auto &t : thrds)
    {
        t.join();
    }

    // aggregate and find the max.
    int maxload = 0;
    for (unsigned i = 0; i < params_.table_size(); i++) {
        for (int t = 1; t < thread_count; t++) {
            thread_loads[0][i] += thread_loads[t][i]; 
        }
        maxload = max(maxload, thread_loads[0][i]);
    }
    Log::debug("Original max load =  %i", maxload); 

    // making sure maxload is a multiple of split_size
    unsigned new_split_count = (maxload + params_.split_size() - 1) / params_.split_size();
    maxload = new_split_count * params_.split_size();	
    params_.set_sender_bin_size(maxload);
    params_.set_split_count(new_split_count);

    // resize the matrix of blocks.
    db_blocks_.resize(params_.batch_count(), new_split_count);


    Log::debug("New max load, new split count = %i, %i", params_.sender_bin_size(), params_.split_count());
}


void SenderDB::add_data_no_hash(gsl::span<const Item> data, MatrixView<u8> values)
{
    STOPWATCH(sender_stop_watch, "SenderDB::add_data_no_hash");

    u64 start = 0;
    u64 end = data.size();

    vector<u8> buff(FourQCoordinate::byte_count());
    PRNG pp(cc_block);
    FourQCoordinate key(pp);

    vector<int> loads(params_.table_size(), 0);
    u64 maxload = 0;

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
        u64 loc = i % get_params().table_size();

        loads[loc] ++;
        if (loads[loc] > maxload) {
            maxload = loads[loc];
        }

        // Lock-free thread-safe bin position search
        std::pair<DBBlock*, DBBlock::Position> block_pos;
        block_pos = acquire_db_position_after_oprf(loc);
        
        auto& db_block = *block_pos.first;
        auto pos = block_pos.second;

        db_block.get_key(pos) = data[i];

        if (params_.use_labels())
        {
            auto dest = db_block.get_label(pos);
            memcpy(dest, values[i].data(), params_.get_label_byte_count());
        }
    }

    // debugging: print the bin load 
    Log::debug("Original max load = %i", maxload);

    u64 new_split_count = (maxload + params_.split_size() - 1) / params_.split_size();
    maxload = new_split_count * params_.split_size();
    params_.set_sender_bin_size(static_cast<unsigned>(maxload));
    params_.set_split_count(static_cast<unsigned>(new_split_count));

    // resize the matrix of blocks.
    db_blocks_.resize(params_.batch_count(), new_split_count);

    Log::debug("New max load, new split count = %i, %i", params_.sender_bin_size(), params_.split_count());

}

void SenderDB::add_data_worker(int thread_idx, int thread_count, const block& seed, gsl::span<const Item> data, MatrixView<u8> values, vector<int> &loads)
{
    STOPWATCH(sender_stop_watch, "SenderDB::add_data_worker");

    PRNG prng(seed, /* buffer_size */ 256);
    u64 start = thread_idx * data.size() / thread_count;
    u64 end = (thread_idx + 1) * data.size() / thread_count;

    vector<u8> buff(FourQCoordinate::byte_count());
    PRNG pp(cc_block);
    FourQCoordinate key(pp);

    vector<cuckoo::LocFunc> normal_loc_func;
    for (unsigned i = 0; i < params_.hash_func_count(); i++)
    {
        normal_loc_func.emplace_back(
            params_.log_table_size(),
            cuckoo::make_item(params_.hash_func_seed() + i, 0));
    }

    loads.resize(params_.table_size(), 0);
    u64 maxload = 0; 
    
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

        // Compute bin locations
        // Set keys and skip
        auto cuckoo_item = data[i].get_value();

        // Set keys and skip
        for (unsigned j = 0; j < params_.hash_func_count(); j++) {
            locs[j] = normal_loc_func[j](cuckoo_item);
            keys[j] = data[i]; 
            skip[j] = false;

            if (j > 0) { // check if same. 
                for (unsigned k = 0; k < j; k++) {
                    if (locs[j] == locs[k]) {
                        skip[j] = true; 
                        break; 
                    }
                }
            }
        }
        
        // Claim an empty location in each matching bin
        for (unsigned j = 0; j < params_.hash_func_count(); j++)
        {
            // debugging
            loads[locs[j]] ++;
            if (loads[locs[j]] > maxload) {
                maxload = loads[locs[j]]; 
            }

            if (skip[j] == false)
            {

                // Lock-free thread-safe bin position search
                std::pair<DBBlock*, DBBlock::Position> block_pos;
                if (params_.use_oprf()) {
                    // Log::info("find db position with oprf");
                    block_pos = acquire_db_position_after_oprf(locs[j]);
                }
                else {
                    block_pos = acquire_db_position(locs[j], prng);
                }

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
    Log::debug("max load for thread %i = %i", thread_idx, maxload);
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
        auto pos = db_blocks_(batch_idx, s_idx)->try_aquire_position(static_cast<int>(batch_offset), prng);
        if (pos.is_initialized())
        {
            return { db_blocks_(batch_idx, s_idx) , pos };
        }

        s_idx = (s_idx + 1) % db_blocks_.stride();
    }

    // Throw an error because bin overflowed
    throw runtime_error("simple hashing failed due to bin overflow");
}

std::pair<DBBlock*, DBBlock::Position>
SenderDB::acquire_db_position_after_oprf(size_t cuckoo_loc)
{
    auto batch_idx = cuckoo_loc / params_.batch_size();
    auto batch_offset = cuckoo_loc % params_.batch_size();

    auto s_idx = 0;
    for (int i = 0; i < db_blocks_.stride(); ++i)
    {
        auto pos = db_blocks_(batch_idx, s_idx)->try_aquire_position_after_oprf(static_cast<int>(batch_offset));
        if (pos.is_initialized())
        {
            return { db_blocks_(batch_idx, s_idx) , pos };
        }
        s_idx++;
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

        auto &block = db_blocks_.data()[next_block];
        if (get_params().use_oprf()) {
            block.symmetric_polys(context, symm_block, encoding_bit_length_, neg_null_element_);
        }
        else {
            Log::debug("no oprf -- computing randomized blocks"); 
            block.randomized_symmetric_polys(context, symm_block, encoding_bit_length_, neg_null_element_);
        }
        block.batch_random_symm_poly_ = { &batch_random_symm_poly_storage_[indexer(split, batch)] , split_size_plus_one };

        for (int i = 0; i < split_size_plus_one; i++)
        {
            Plaintext &poly = block.batch_random_symm_poly_[i];


            // This branch works even if ex_field_ is an integer field, but it is slower than normal batching.
            for (int k = 0; batch_start + k < batch_end; k++)
            {
                copy_n(symm_block(k, i), batch_vector.field().d(), batch_vector.data(k));
            }
            ex_batch_encoder->compose(batch_vector, poly);

            if (get_params().use_oprf())
            {
                if (i == split_size_plus_one - 1)
                {
                    for (size_t j = 1; j < poly.coeff_count(); j++) {
                        if (poly.data()[j] != 0) {
                            Log::debug("something wrong");
                            break;
                        }
                    }
                    if (poly.data()[0] != 1) {
                        Log::debug("something wrong");
                    }
                }
            }

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
