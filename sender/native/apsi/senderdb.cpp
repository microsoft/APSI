// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <deque>
#include <memory>
#include <mutex>
#include <thread>

// APSI
#include "apsi/senderdb.h"

using namespace std;
using namespace seal;

namespace apsi
{
    using namespace util;
    using namespace logging;

    namespace sender
    {
        SenderDB::SenderDB(PSIParams params)
            : params_(params), field_(params_.ffield_characteristic(), params_.ffield_degree()), null_element_(field_),
              neg_null_element_(field_), next_locs_(params.table_size(), 0),
              batch_random_symm_poly_storage_(params.split_count() * params.batch_count() * (params.split_size() + 1)),
              session_context_(SEALContext::Create(params.encryption_params()))
        {
            session_context_.set_ffield(field_);

            // Set null value for sender: 1111...1110 (128 bits)
            // Receiver's null value comes from the Cuckoo class: 1111...1111
            sender_null_item_[0] = ~uint64_t(1);
            sender_null_item_[1] = ~uint64_t(0);

            // What is the actual length of strings stored in the hash table
            encoding_bit_length_ = params.item_bit_length_used_after_oprf();
            Log::debug("encoding bit length = %i", encoding_bit_length_);

            // Create the null FFieldElement (note: encoding truncation affects high bits)
            null_element_ = sender_null_item_.to_ffield_element(field_, encoding_bit_length_);
            neg_null_element_ = -null_element_;

            size_t batch_size = params_.batch_size();
            size_t split_size = params_.split_size();

            // debugging
            uint64_t num_ctxts = params_.batch_count() * params_.sender_bin_size();
            Log::debug("sender size = %i", params_.sender_size());
            Log::debug("table size = %i", params_.table_size());
            Log::debug("sender bin size = %i", params_.sender_bin_size());
            Log::debug("split size = %i", split_size);
            Log::debug("number of ciphertexts in senderdb = %i", num_ctxts);
            Log::debug("number of hash functions = %i", params_.hash_func_count());
            size_t byte_length = round_up_to(params_.label_bit_count(), size_t(8)) / 8;
            uint64_t nb = params_.batch_count();

            // here, need to make split count larger to fit
            // another place the split count is modified is after add_data.
            uint64_t ns = (params_.sender_bin_size() + params_.split_size() - 1) / params_.split_size();
            params_.set_split_count(static_cast<uint32_t>(ns));
            params_.set_sender_bin_size(ns * params_.split_size());

            // important: here it resizes the db blocks.
            bin_bundles_.resize(static_cast<size_t>(nb), static_cast<size_t>(ns));

            for (uint64_t b_idx = 0; b_idx < nb; b_idx++)
            {
                for (uint64_t s_idx = 0; s_idx < ns; s_idx++)
                {
                    bin_bundles_(static_cast<size_t>(b_idx), static_cast<size_t>(s_idx))
                        ->init(b_idx, s_idx, byte_length, batch_size, split_size);
                }
            }

            batch_random_symm_poly_storage_.resize(
                params_.split_count() * params_.batch_count() * (params_.split_size() + 1));
            for (auto &plain : batch_random_symm_poly_storage_)
            {
                // Reserve memory for ciphertext size plaintexts (NTT transformed mod q)
                plain.reserve(
                    params_.encryption_params().coeff_modulus().size() *
                    params_.encryption_params().poly_modulus_degree());
            }
        }

        void SenderDB::clear_db()
        {
            if (batch_random_symm_poly_storage_[0].is_ntt_form())
            {
                // Clear all storage
                for (auto &plain : batch_random_symm_poly_storage_)
                {
                    plain.release();
                    plain.reserve(
                        params_.encryption_params().coeff_modulus().size() *
                        params_.encryption_params().poly_modulus_degree());
                }
            }

            for (auto &block : bin_bundles_)
                block.clear();
        }

        void SenderDB::set_data(gsl::span<const Item> data, size_t thread_count)
        {
            set_data(data, {}, thread_count);
        }

        void SenderDB::set_data(gsl::span<const Item> data, MatrixView<unsigned char> vals, size_t thread_count)
        {
            STOPWATCH(sender_stop_watch, "SenderDB::set_data");
            clear_db();

            bool fm = get_params().use_fast_membership();
            if (fm)
            {
                Log::debug("Fast membership: add data with no hashing");
                add_data_no_hash(data, vals);
            }
            else
            {
                add_data(data, vals, thread_count);
            }
        }

        template<>
        void SenderDB<vector<uint8_t> >::add_data(map<Item, vector<uint8_t> > &data, size_t thread_count)
        {
            STOPWATCH(sender_stop_watch, "SenderDB::add_data");

            if (values.stride() != params_.label_byte_count())
                throw invalid_argument("unexpacted label length");

            // Construct the cuckoo hash functions
            vector<kuku::LocFunc> normal_loc_funcs;
            for (size_t i = 0; i < params_.hash_func_count(); i++)
            {
                kuku::LocFunc f = kuku::LocFunc(
                    params_.table_size(),
                    kuku::make_item(params_.hash_func_seed() + i, 0)
                );
                normal_loc_funcs.push_back(f);
            }

            // Calculate the cuckoo indices for each item. Store every pair of (&item-label, cuckoo_idx) in a vector.
            // Later, we're gonna sort this vector by cuckoo_idx and use the result to parallelize the work of inserting
            // the items into BinBundles
            vector<pair<&pair<Item, vector<uint8_t> >, size_t> > data_with_indices;
            for (auto &item_label_pair : data)
            {
                Item &item = item_label_pair.first;
                // Collect the cuckoo indices, ignoring duplicates
                std::set<size_t> cuckoo_indices;
                for (kuku::LocFunc &hash_func : normal_loc_funcs)
                {
                    // The cuckoo index must be aligned to number of bins an item takes up
                    size_t cuckoo_idx = hash_func(item) * bins_per_item;;

                    // Store the data along with its index
                    data_with_indices.push_back({ item_label_pair, cuckoo_idx });
                }
            }

            // Sort by cuckoo index
            sort(
                data_with_indices.begin(),
                data_with_indices.end(),
                [](auto &data_with_idx1, auto &data_with_idx2) {
                    size_t idx1 = data_with_idx1.second;
                    size_t idx2 = data_with_idx2.second;
                    return idx1 < idx2;
                }
            );

            // Divide the work across threads. Each thread gets its own nonoverlapping range of bundle indices
            size_t total_insertions = data_with_indices.size();
            size_t expected_insertions_per_thread = (total_insertions + (thread_count - 1)) / thread_count;
            size_t bins_per_bundle = params_.batch_size();

            // Contains indices into data_with_indicies. If partitions = {i, j}, then that means
            // the first partition is data_with_indices[0..i) (i.e., inclusive lower bound, noninclusive upper bound)
            // the second partition is data_with_indices[i..j)
            // the third partition is data_with_indices[j..] (i.e., including index j, all the way through the end)
            vector<size_t> partitions;

            // A simple partitioning algorithm. Two constraints:
            // 1. We want threads to do roughly the same amount of work. That is, these partitions should be roughly
            //    equally sized.
            // 2. A bundle index cannot appear in two partitions. This would cause multiple threads to modify the same
            //    data structure, which is not safe.
            //
            // So the algorithm is, for each partition: put the minimal number of elements in the partition. Then, on
            // the next bundle index boundary, mark the partition end.
            size_t insertion_count = 0;
            int last_bundle_idx = -1;
            for (size_t i = 0; i < data_with_indices.size(); i++)
            {
                auto &data_with_idx = data_with_indices.at(i);
                size_t cuckoo_idx = data_with_idx.second;
                size_t bin_idx = cuckoo_idx % bins_per_bundle;;
                size_t bundle_idx = (cuckoo_idx - bin_idx) / bins_per_bundle;

                insertion_count++;

                // If this partition is big enough and we've hit a BinBundle boundary, break the partition off here
                if (insertion_count > expected_insertions_per_thread && bundle_idx != last_bundle_idx)
                    partitions.push_back(i)
                }

                last_bundle_idx = bundle_idx;
            }

            // Partition the data and run the threads on the partitions
            vector<thread> threads;
            gsl::span data_span(data_with_indices);
            size_t last_partition_cutoff = 0;
            for (size_t t = 0; t < thread_count; t++)
            {
                // Run a thread on the partition data_with_indices[partitions[t-1]..partitions[t]), where the base case
                // partitions[-1] = 0;
                size_t partition_cutoff = partitions[t];
                size_t partition_size = partitions[t] - last_partition_cutoff;
                gsl::span<pair<&pair<Item, vector<uint8_t> >, size_t> > partition =
                    data_span.subspan(partition_cutoff, partition_size);

                threads.emplace_back([&, t]() { add_data_worker(partition); });

                last_partition_cutoff = partition_cutoff;
            }

            // Wait for the threads to finish
            for (auto &t : thrds)
            {
                t.join();
            }
        }

        void SenderDB::add_data_no_hash(gsl::span<const Item> data, MatrixView<unsigned char> values)
        {
            STOPWATCH(sender_stop_watch, "SenderDB::add_data_no_hash");

            uint64_t start = 0;
            uint64_t end = data.size();

            vector<int> loads(params_.table_size(), 0);
            int maxload = 0;

            for (size_t i = static_cast<size_t>(start); i < end; i++)
            {
                size_t loc = i % get_params().table_size();

                loads[loc]++;
                if (loads[loc] > maxload)
                {
                    maxload = loads[loc];
                }

                // Lock-free thread-safe bin position search
                pair<BinBundle *, BinBundle::Position> block_pos;
                block_pos = acquire_db_position_after_oprf(loc);

                auto &db_block = *block_pos.first;
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

            if (get_params().use_dynamic_split_count())
            {
                size_t new_split_count =
                    (static_cast<size_t>(maxload) + params_.split_size() - 1) / params_.split_size();
                params_.set_sender_bin_size(new_split_count * params_.split_size());
                params_.set_split_count(new_split_count);

                // resize the matrix of blocks.
                bin_bundles_.resize(params_.batch_count(), static_cast<size_t>(new_split_count));

                Log::debug("New max load, new split count = %i, %i", params_.sender_bin_size(), params_.split_count());
            }
        }

        /**
        Inserts the given items and corresponding labels into the database at the given cuckoo indices. Concretely, for
        every ((item, label), cuckoo_idx) element, the item is inserted into the database at cuckoo_idx and its label is
        set to label.
        */
        template<>
        void SenderDB<vector<uint8_t> >::add_data_worker(
            const gsl::span<pair<&pair<Item, vector<uint8_t> >, size_t> > data_with_indices;
        ) {
            STOPWATCH(sender_stop_watch, "SenderDB::add_data_worker");

            const SEAL::Modulus &mod = params_.seal_params_.encryption_params.plain_modulus();

            // bins_per_item = ⌈item_bit_count / (mod_bitlen - 1)⌉
            size_t modulus_size = (size_t)mod.bit_count();
            size_t bins_per_item = (params_.item_bit_count() + (modulus_size-2)) / (modulus_size-1)
            size_t bins_per_bundle = params_.batch_size();

            // Iteratively insert each item-label pair
            for (auto &data_with_idx : data_with_indices)
            {
                Item &item = data_with_idx.first.first;
                vector<uint8_t> &label = data_with_idx.first.second;
                size_t cuckoo_idx = data_with_indices.second;

                // Convert the label to the appropriately sized bitstring
                Bitstring label_bs(item_label_pair.second, params_.item_bit_count);
                // Then convert the label from the bitstring to a sequence of field elements
                vector<felt_t> label = bits_to_field_elts(bs, mod);
                if (label.size() != 2)
                {
                    throw logic_error("Labels must be precisely 2 field elements wide");
                }

                // We will compute all the locations that this item gets placed in
                array<felt_t, 2> item = item_label_pair.first.get_value();

                // Collect the item-label field element pairs
                vector<pair<felt_t, felt_t> > item_label_felt_pairs;
                item_label_felt_pairs.push_back({ item[0], label[0] });
                item_label_felt_pairs.push_back({ item[1], label[1] });

                for (size_t &cuckoo_idx : cuckoo_idx_set)
                {
                    size_t bin_idx = cuckoo_idx % bins_per_bundle;;
                    size_t bundle_idx = (cuckoo_idx - bin_idx) / bins_per_bundle;

                    set<BinBundle> &bundle_set = bin_bundles_.at(bundle_idx);

                    // Try to insert these field elements somewhere
                    bool inserted = false;
                    for (BinBundle &bundle : bundle_set)
                    {
                        // Do a dry-run insertion and see if the new largest bin size in the range
                        // exceeds the limit
                        int new_largest_bin_size = bundle.multi_insert_dry_run(item_label_felt_pairs, bin_idx);

                        // Check if inserting would violate the max bin size constraint
                        if (new_largest_bin_size > 0 && new_largest_bin_size < PARAMS_MAX_BIN_SIZE)
                        {
                            // All good
                            bundle.multi_insert_for_real(item_label_felt_pairs, bin_idx);
                            inserted = true;
                        }
                    }

                    // If we had conflicts everywhere, then we need to make a new BinBundle and insert the data there
                    if (!inserted)
                    {
                        // Make a fresh BinBundle and insert
                        BinBundle new_bin_bundle(SO, MANY, ARGUMENTS);
                        int res = new_bin_bundle.multi_insert_for_real(item_label_felt_pairs, bin_idx);

                        // If even that failed, I don't know what could've happened
                        if (res < 0)
                        {
                            throw logic_error("Couldn't insert item into a brand new BinBundle");
                        }

                        bin_bundles.insert(new_bin_bundle);
                    }
                }
            }
        }

        void SenderDB::add_data(gsl::span<const Item> data, size_t thread_count)
        {
            add_data(data, {}, thread_count);
        }

        pair<BinBundle *, BinBundle::Position> SenderDB::acquire_db_position_after_oprf(size_t cuckoo_loc)
        {
            size_t batch_idx = cuckoo_loc / params_.batch_size();
            size_t batch_offset = cuckoo_loc % params_.batch_size();

            size_t s_idx = 0;
            for (size_t i = 0; i < bin_bundles_.stride(); ++i)
            {
                BinBundle::Position pos = bin_bundles_(batch_idx, s_idx)->try_acquire_position_after_oprf(batch_offset);
                if (pos.is_initialized())
                {
                    return { bin_bundles_(batch_idx, s_idx), pos };
                }
                s_idx++;
            }

            // Throw an error because bin overflowed
            throw runtime_error("simple hashing failed due to bin overflow");
        }

        void SenderDB::add_data(const Item &item, size_t thread_count)
        {
            add_data(vector<Item>(1, item), thread_count);
        }

        void SenderDB::batched_randomized_symmetric_polys(
            SenderThreadContext &context, size_t start_block, size_t end_block)
        {
            size_t batch_size = params_.batch_size();
            size_t split_size_plus_one = params_.split_size() + 1;

            FFieldArray batch_vector(batch_size, *session_context_.ffield());
            vector<uint64_t> integer_batch_vector(batch_size);

            // Data in batch-split table is stored in "batch-major order"
            auto indexer = [splitStep = params_.batch_count() * split_size_plus_one,
                            batchStep = split_size_plus_one](size_t splitIdx, size_t batchIdx) {
                return splitIdx * splitStep + batchIdx * batchStep;
            };

            MemoryPoolHandle local_pool = context.pool();

            for (size_t next_block = start_block; next_block < end_block; next_block++)
            {
                size_t split = next_block / params_.batch_count();
                size_t batch = next_block % params_.batch_count();

                size_t batch_start = batch * batch_size, batch_end = batch_start + batch_size;

                auto &block = bin_bundles_.data()[next_block];
                block.symmetric_polys(context, encoding_bit_length_, neg_null_element_);
                block.batch_random_symm_poly_ = { &batch_random_symm_poly_storage_[indexer(split, batch)],
                                                  static_cast<size_t>(split_size_plus_one) };

                for (size_t i = 0; i < split_size_plus_one; i++)
                {
                    Plaintext &poly = block.batch_random_symm_poly_[i];

                    // This branch works even if FField is an integer field, but it is slower than normal batching.
                    for (size_t k = 0; batch_start + k < batch_end; k++)
                    {
                        copy_n(context.symm_block()(k, i), batch_vector.field().degree(), batch_vector.data(k));
                    }
                    session_context_.encoder()->compose(batch_vector, poly);
                    if (!is_valid_for(poly, session_context_.seal_context()))
                        throw;

                    if (i == split_size_plus_one - 1)
                    {
                        for (size_t j = 1; j < poly.coeff_count(); j++)
                        {
                            if (poly.data()[j] != 0)
                            {
                                Log::debug("something wrong");
                                break;
                            }
                        }
                        if (poly.data()[0] != 1)
                        {
                            Log::debug("something wrong");
                        }
                    }

                    session_context_.evaluator()->transform_to_ntt_inplace(
                        poly, session_context_.seal_context()->first_parms_id(), local_pool);
                }

                context.inc_randomized_polys();
            }
        }

        void SenderDB::batched_interpolate_polys(SenderThreadContext &th_context, size_t start_block, size_t end_block)
        {
            auto &mod = params_.encryption_params().plain_modulus();

            DBInterpolationCache cache(
                *session_context_.ffield(), params_.batch_size(), params_.split_size(), params_.label_byte_count());

            // Minus 1 to be safe.
            size_t coeffBitCount = static_cast<size_t>(seal::util::get_significant_bit_count(mod.value()) - 1);

            if (params_.label_bit_count() >= coeffBitCount * session_context_.encoder()->degree())
            {
                throw runtime_error("labels are too large for ffield");
            }

            for (size_t bIdx = start_block; bIdx < end_block; bIdx++)
            {
                auto &block = *bin_bundles_(bIdx);
                block.batch_interpolate(
                    th_context, session_context_.seal_context(), session_context_.evaluator(),
                    session_context_.encoder(), cache, params_);
                th_context.inc_interpolate_polys();
            }
        }

        void SenderDB::load_db(size_t thread_count, const vector<Item> &data, MatrixView<unsigned char> vals)
        {
            set_data(data, vals, thread_count);

            // Compute symmetric polys and batch
            offline_compute(thread_count);
        }

        void SenderDB::offline_compute(size_t thread_count)
        {
            STOPWATCH(sender_stop_watch, "SenderDB::offline_compute");
            Log::info("Offline compute started");

            // Thread contexts
            vector<SenderThreadContext> thread_contexts(thread_count);

            // Field is needed to create the thread contexts
            FField field(params_.ffield_characteristic(), params_.ffield_degree());

            // Set local ffields for multi-threaded efficient use of memory pools.
            vector<thread> thrds;
            for (size_t i = 0; i < thread_count; i++)
            {
                thrds.emplace_back([&, i]() {
                    thread_contexts[i].set_id(seal::util::safe_cast<int>(i));
                    thread_contexts[i].set_pool(MemoryManager::GetPool(mm_prof_opt::FORCE_NEW));

                    // Allocate memory for repeated use from the given memory pool.
                    thread_contexts[i].construct_variables(params_, field);
                });
            }

            for (auto &thrd : thrds)
            {
                thrd.join();
            }

            thrds.clear();

            for (auto &ctx : thread_contexts)
            {
                ctx.clear_processed_counts();
            }

            for (size_t i = 0; i < thread_count; i++)
            {
                thrds.emplace_back([&, i]() { offline_compute_work(thread_contexts[i], thread_count); });
            }

            atomic<bool> work_finished = false;
            thread progress_thread([&]() { report_offline_compute_progress(thread_contexts, work_finished); });

            for (auto &thrd : thrds)
            {
                thrd.join();
            }

            // Signal progress thread work is done
            work_finished = true;
            progress_thread.join();

            Log::info("Offline compute finished.");
        }

        void SenderDB::offline_compute_work(SenderThreadContext &th_context, size_t total_thread_count)
        {
            STOPWATCH(sender_stop_watch, "SenderDB::offline_compute_work");

            size_t thread_context_idx = static_cast<size_t>(th_context.id());
            size_t start_block = thread_context_idx * get_block_count() / total_thread_count;
            size_t end_block = (thread_context_idx + 1) * get_block_count() / total_thread_count;

            size_t blocks_to_process = end_block - start_block;
            Log::debug("Thread %i processing %i blocks.", thread_context_idx, blocks_to_process);

            th_context.set_total_randomized_polys(static_cast<int>(blocks_to_process));
            if (params_.use_labels())
            {
                th_context.set_total_interpolate_polys(static_cast<int>(blocks_to_process));
            }

            STOPWATCH(sender_stop_watch, "SenderDB::offline_compute_work::calc_symmpoly");
            batched_randomized_symmetric_polys(th_context, start_block, end_block);

            if (params_.use_labels())
            {
                STOPWATCH(sender_stop_watch, "SenderDB::offline_compute_work::calc_interpolation");
                batched_interpolate_polys(th_context, start_block, end_block);
            }
        }

        void SenderDB::report_offline_compute_progress(
            vector<SenderThreadContext> &thread_contexts, atomic<bool> &work_finished)
        {
            size_t thread_count = thread_contexts.size();
            int progress = 0;
            while (!work_finished)
            {
                float threads_progress = 0.0f;
                for (size_t i = 0; i < thread_count; i++)
                {
                    threads_progress += thread_contexts[i].get_progress();
                }

                int int_progress = static_cast<int>((threads_progress / thread_count) * 100.0f);

                if (int_progress > progress)
                {
                    progress = int_progress;
                    Log::info("Offline compute progress: %i%%", progress);
                }

                // Check for progress 10 times per second
                this_thread::sleep_for(100ms);
            }
        }
    } // namespace sender
} // namespace apsi
