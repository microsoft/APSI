// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <memory>
#include <thread>

// APSI
#include "apsi/senderdb.h"

using namespace std;
using namespace seal;

namespace apsi
{
    using namespace tools;
    using namespace logging;

    namespace sender
    {
        SenderDB::SenderDB(const PSIParams &params, 
            shared_ptr<SEALContext> &seal_context) :
            params_(params),
            seal_context_(move(seal_context)),
            next_locs_(params.table_size(), 0),
            batch_random_symm_poly_storage_(params.split_count() * params.batch_count() * (params.split_size() + 1))
        {
            // Set null value for sender: 1111...1110 (128 bits)
            // Receiver's null value comes from the Cuckoo class: 1111...1111
            sender_null_item_[0] = ~1;
            sender_null_item_[1] = ~0;

            // What is the actual length of strings stored in the hash table
            encoding_bit_length_ = params.item_bit_length_used_after_oprf();
            Log::debug("encoding bit length = %i", encoding_bit_length_); 

            // Create the null FFieldElement (note: encoding truncation affects high bits)
            FField field(params_.ffield_characteristic(), params_.ffield_degree());
            null_element_ = sender_null_item_.to_ffield_element(field, encoding_bit_length_);
            neg_null_element_ = -null_element_;

            int batch_size = params_.batch_size();
            int split_size = params_.split_size();

            // debugging 
            u64 num_ctxts = params_.batch_count() * params_.sender_bin_size();
            Log::debug("sender size = %i", params_.sender_size());
            Log::debug("table size = %i", params_.table_size());
            Log::debug("sender bin size = %i", params_.sender_bin_size());
            Log::debug("split size = %i", split_size); 
            Log::debug("number of ciphertexts in senderdb = %i", num_ctxts);
            Log::debug("number of hash functions = %i", params_.hash_func_count());
            u32 byte_length = round_up_to(params_.label_bit_count(), 8u) / 8;
            u64 nb = params_.batch_count();

            // here, need to make split count larger to fit
            // another place the split count is modified is after add_data.
            u64 ns = (params_.sender_bin_size() + params_.split_size() - 1) / params_.split_size(); 
            params_.set_split_count(static_cast<u32>(ns));
            params_.set_sender_bin_size(ns * params_.split_size());

            // important: here it resizes the db blocks.
            db_blocks_.resize(static_cast<size_t>(nb),
                            static_cast<size_t>(ns));

            for (u64 b_idx = 0; b_idx < nb; b_idx++)
            {
                for (u64 s_idx = 0; s_idx < ns; s_idx++)
                {
                    db_blocks_(static_cast<size_t>(b_idx),
                            static_cast<size_t>(s_idx))->init(
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

            //// Set local ffields for multi-threaded efficient use of memory pools.
            //vector<thread> thrds;
            //for (int i = 0; i < total_thread_count_; i++)
            //{
                //available_thread_contexts_.push_back(i);
                //thrds[i] = thread([&, i]()
                //{
                    //auto local_pool = MemoryPoolHandle::New();
                    //thread_contexts_[i].set_id(i);
                    //thread_contexts_[i].set_pool(local_pool);

                    //// Allocate memory for repeated use from the given memory pool.
                    //thread_contexts_[i].construct_variables(params_);
                //});
            //}

            //for (auto &thrd : thrds)
            //{
                //thrd.join();
            //}
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

            if (values.stride() != params_.label_byte_count())
                throw invalid_argument("unexpacted label length");

            vector<thread> thrds(thread_count);

            vector<vector<int>> thread_loads(thread_count);
            for (size_t t = 0; t < thrds.size(); t++)
            {
                thrds[t] = thread([&, t](int idx)
                {
                    add_data_worker(idx, thread_count, data, values, thread_loads[t]);
                }, static_cast<int>(t));
            }

            for (auto &t : thrds)
            {
                t.join();
            }

            // aggregate and find the max.
            int maxload = 0;
            for (u32 i = 0; i < params_.table_size(); i++)
            {
                for (int t = 1; t < thread_count; t++)
                {
                    thread_loads[0][i] += thread_loads[t][i]; 
                }
                maxload = max(maxload, thread_loads[0][i]);
            }
            Log::debug("Original max load =  %i", maxload); 

            if (get_params().dynamic_split_count())
            {
                // making sure maxload is a multiple of split_size
                u32 new_split_count = (maxload + params_.split_size() - 1) / params_.split_size();
                maxload = new_split_count * params_.split_size();
                params_.set_sender_bin_size(maxload);
                params_.set_split_count(new_split_count);

                // resize the matrix of blocks.
                db_blocks_.resize(params_.batch_count(), new_split_count);

                Log::debug("New max load, new split count = %i, %i", params_.sender_bin_size(), params_.split_count());
            }
        }


        void SenderDB::add_data_no_hash(gsl::span<const Item> data, MatrixView<u8> values)
        {
            STOPWATCH(sender_stop_watch, "SenderDB::add_data_no_hash");

            u64 start = 0;
            u64 end = data.size();

            vector<int> loads(params_.table_size(), 0);
            u64 maxload = 0;

            for (size_t i = static_cast<size_t>(start); i < end; i++)
            {
                size_t loc = i % get_params().table_size();

                loads[loc] ++;
                if (loads[loc] > maxload) {
                    maxload = loads[loc];
                }

                // Lock-free thread-safe bin position search
                pair<DBBlock*, DBBlock::Position> block_pos;
                block_pos = acquire_db_position_after_oprf(loc);
                
                auto& db_block = *block_pos.first;
                auto pos = block_pos.second;

                db_block.get_key(pos) = data[i];

                if (params_.use_labels())
                {
                    auto dest = db_block.get_label(pos);
                    memcpy(dest, values[i].data(), params_.label_byte_count());
                }
            }

            // debugging: print the bin load 
            Log::debug("Original max load = %i", maxload);

            if (get_params().dynamic_split_count())
            {
                u64 new_split_count = (maxload + params_.split_size() - 1) / params_.split_size();
                maxload = new_split_count * params_.split_size();
                params_.set_sender_bin_size(maxload);
                params_.set_split_count(static_cast<u32>(new_split_count));

                // resize the matrix of blocks.
                db_blocks_.resize(params_.batch_count(), static_cast<size_t>(new_split_count));

                Log::debug("New max load, new split count = %i, %i", params_.sender_bin_size(), params_.split_count());
            }
        }

        void SenderDB::add_data_worker(int thread_idx, int thread_count, gsl::span<const Item> data, MatrixView<u8> values, vector<int> &loads)
        {
            STOPWATCH(sender_stop_watch, "SenderDB::add_data_worker");

            u64 start = thread_idx * data.size() / thread_count;
            u64 end = (thread_idx + 1) * data.size() / thread_count;

            vector<kuku::LocFunc> normal_loc_func;
            for (u32 i = 0; i < params_.hash_func_count(); i++)
            {
                normal_loc_func.emplace_back(
                    params_.log_table_size(),
                    kuku::make_item(params_.hash_func_seed() + i, 0));
            }

            loads.resize(params_.table_size(), 0);
            u64 maxload = 0; 
            
            for (size_t i = static_cast<size_t>(start); i < end; i++)
            {
                vector<u64> locs(params_.hash_func_count());
                vector<Item> keys(params_.hash_func_count());
                vector<bool> skip(params_.hash_func_count());

                // Compute bin locations
                // Set keys and skip
                auto cuckoo_item = data[i].get_value();

                // Set keys and skip
                for (u32 j = 0; j < params_.hash_func_count(); j++)
                {
                    locs[j] = normal_loc_func[j](cuckoo_item);
                    keys[j] = data[i]; 
                    skip[j] = false;

                    if (j > 0) { // check if same. 
                        for (u32 k = 0; k < j; k++)
                        {
                            if (locs[j] == locs[k])
                            {
                                skip[j] = true; 
                                break; 
                            }
                        }
                    }
                }
                
                // Claim an empty location in each matching bin
                for (u32 j = 0; j < params_.hash_func_count(); j++)
                {
                    // debugging
                    size_t idxlocs = static_cast<size_t>(locs[j]);
                    loads[idxlocs] ++;
                    if (loads[idxlocs] > maxload)
                    {
                        maxload = loads[idxlocs]; 
                    }

                    if (skip[j] == false)
                    {

                        // Lock-free thread-safe bin position search
                        pair<DBBlock*, DBBlock::Position> block_pos;

                        // Log::info("find db position with oprf");
                        block_pos = acquire_db_position_after_oprf(idxlocs);

                        auto& db_block = *block_pos.first;
                        auto pos = block_pos.second;

                        db_block.get_key(pos) = keys[j];

                        if (params_.use_labels())
                        {
                            auto dest = db_block.get_label(pos);
                            memcpy(dest, values[i].data(), params_.label_byte_count());
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

        pair<DBBlock*, DBBlock::Position>
        SenderDB::acquire_db_position_after_oprf(size_t cuckoo_loc)
        {
            auto batch_idx = cuckoo_loc / params_.batch_size();
            auto batch_offset = cuckoo_loc % params_.batch_size();

            auto s_idx = 0;
            for (size_t i = 0; i < db_blocks_.stride(); ++i)
            {
                auto pos = db_blocks_(batch_idx, s_idx)->try_acquire_position_after_oprf(static_cast<int>(batch_offset));
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
            int end_block)
        {
            // Get the symmetric block
            auto symm_block = context.symm_block();

            int table_size = params_.table_size(),
                batch_size = params_.batch_size(),
                split_size_plus_one = params_.split_size() + 1;

            FFieldArray batch_vector(batch_size, *session_context_.ffield());
            vector<u64> integer_batch_vector(batch_size);

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
                block.symmetric_polys(context, symm_block, encoding_bit_length_, neg_null_element_);
                block.batch_random_symm_poly_ = { &batch_random_symm_poly_storage_[indexer(split, batch)] , split_size_plus_one };

                for (int i = 0; i < split_size_plus_one; i++)
                {
                    Plaintext &poly = block.batch_random_symm_poly_[i];

                    // This branch works even if FField is an integer field, but it is slower than normal batching.
                    for (int k = 0; batch_start + k < batch_end; k++)
                    {
                        copy_n(symm_block(k, i), batch_vector.field().d(), batch_vector.data(k));
                    }
                    session_context_.encoder()->compose(batch_vector, poly);

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

                    session_context_.evaluator()->transform_to_ntt_inplace(poly, seal_context_->first_parms_id(), local_pool);
                }

                context.inc_randomized_polys();
            }
        }

        void SenderDB::batched_interpolate_polys(
            SenderThreadContext &th_context,
            int start_block,
            int end_block)
        {
            auto &mod = params_.encryption_params().plain_modulus();

            DBInterpolationCache cache(
                *session_context_.ffield(),
                params_.batch_size(),
                params_.split_size(),
                params_.label_byte_count());

            // Minus 1 to be safe.
            auto coeffBitCount = seal::util::get_significant_bit_count(mod.value()) - 1;

            if (params_.label_bit_count() >= coeffBitCount * session_context_.encoder()->d())
            {
                throw runtime_error("labels are too large for ffield");
            }

            for (int bIdx = start_block; bIdx < end_block; bIdx++)
            {
                auto &block = *db_blocks_(bIdx);
                block.batch_interpolate(
                    th_context,
                    seal_context_,
                    session_context_.evaluator(),
                    session_context_.encoder(),
                    cache,
                    params_);
                th_context.inc_interpolate_polys();
            }
        }

        void SenderDB::load_db(const vector<Item> &data, MatrixView<u8> vals)
        {
            set_data(data, vals, total_thread_count_);

            params_.set_split_count(params_.split_count());
            params_.set_sender_bin_size(params_.sender_bin_size());

            // Compute symmetric polys and batch
            offline_compute();
        }

        void SenderDB::offline_compute()
        {
            STOPWATCH(sender_stop_watch, "SenderDB::offline_compute");
            Log::info("Offline compute started");

            for (auto& ctx : thread_contexts_)
            {
                ctx.clear_processed_counts();
            }

            vector<thread> thread_pool(total_thread_count_);
            for (int i = 0; i < total_thread_count_; i++)
            {
                thread_pool[i] = thread([&]()
                {
                    offline_compute_work();
                });
            }

            atomic<bool> work_finished = false;
            thread progress_thread([&]()
            {
                report_offline_compute_progress(total_thread_count_, work_finished);
            });

            for (size_t i = 0; i < thread_pool.size(); i++)
            {
                thread_pool[i].join();
            }

            // Signal progress thread work is done
            work_finished = true;
            progress_thread.join();

            Log::info("Offline compute finished.");
        }

        void SenderDB::offline_compute_work()
        {
            STOPWATCH(sender_stop_watch, "SenderDB::offline_compute_work");

            int thread_context_idx = acquire_thread_context();

            SenderThreadContext &context = thread_contexts_[thread_context_idx];
            int start_block = static_cast<int>(thread_context_idx * get_block_count() / total_thread_count_);
            int end_block = static_cast<int>((thread_context_idx + 1) * get_block_count() / total_thread_count_);

            int blocks_to_process = end_block - start_block;
            Log::debug("Thread %i processing %i blocks.", thread_context_idx, blocks_to_process);

            context.set_total_randomized_polys(blocks_to_process);
            if (params_.use_labels())
            {
                context.set_total_interpolate_polys(blocks_to_process);
            }

            STOPWATCH(sender_stop_watch, "SenderDB::offline_compute_work::calc_symmpoly");
            batched_randomized_symmetric_polys(context, start_block, end_block, evaluator_, batch_encoder_);

            if (params_.use_labels())
            {
                STOPWATCH(sender_stop_watch, "SenderDB::offline_compute_work::calc_interpolation");
                batched_interpolate_polys(context, start_block, end_block, evaluator_, batch_encoder_);
            }

            release_thread_context(context.id());
        }

        void SenderDB::report_offline_compute_progress(int total_threads, atomic<bool>& work_finished)
        {
            int progress = 0;
            while (!work_finished)
            {
                float threads_progress = 0.0f;
                for (int i = 0; i < total_threads; i++)
                {
                    threads_progress += thread_contexts_[i].get_progress();
                }

                int int_progress = static_cast<int>((threads_progress / total_threads) * 100.0f);

                if (int_progress > progress)
                {
                    progress = int_progress;
                    Log::info("Offline compute progress: %i%%", progress);
                }

                // Check for progress 10 times per second
                this_thread::sleep_for(100ms);
            }
        }

        int SenderDB::acquire_thread_context()
        {
            // Multiple threads can enter this function to compete for thread context resources.
            int thread_context_idx = -1;
            while (thread_context_idx == -1)
            {
                if (!available_thread_contexts_.empty())
                {
                    unique_lock<mutex> lock(thread_context_mtx_);
                    if (!available_thread_contexts_.empty())
                    {
                        thread_context_idx = available_thread_contexts_.front();
                        available_thread_contexts_.pop_front();
                    }
                }
                else
                {
                    this_thread::sleep_for(chrono::milliseconds(50));
                }
            }

            return thread_context_idx;
        }

        void SenderDB::release_thread_context(int idx)
        {
            unique_lock<mutex> lock(thread_context_mtx_);
            available_thread_contexts_.push_back(idx);
        }
    } // namespace sender
} // namespace apsi
