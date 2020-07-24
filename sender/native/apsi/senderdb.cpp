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
        LabeledSenderDB::LabeledSenderDB(PSIParams params) :
            params_(params),
            session_context_(SEALContext::Create(params.encryption_params()))
        {
            // What is the actual length of strings stored in the hash table
            encoding_bit_length_ = params.item_bit_length_used_after_oprf();
            Log::debug("encoding bit length = %i", encoding_bit_length_);
        }

        void LabeledSenderDB::clear_db()
        {
            bin_bundles_.clear();
        }

        template<typename L>
        void LabeledSenderDB<L>::set_data(map<Item, vector<uint8_t> > &data, size_t thread_count)
        {
            STOPWATCH(sender_stop_watch, "LabeledSenderDB::set_data");
            clear_db();
            add_data(data, thread_count);
        }

        /**
        Inserts the given data into the database, using at most thread_count threads
        */
        void LabeledSenderDB<vector<uint8_t> >::add_data(map<Item, vector<uint8_t> > &data, size_t thread_count)
        {
            STOPWATCH(sender_stop_watch, "LabeledSenderDB::add_data");

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
                auto &data_with_idx = data_with_indices[i];
                size_t cuckoo_idx = data_with_idx.second;
                size_t bin_idx = cuckoo_idx % bins_per_bundle;
                size_t bundle_idx = (cuckoo_idx - bin_idx) / bins_per_bundle;

                insertion_count++;

                // If this partition is big enough and we've hit a BinBundle boundary, break the partition off here
                if (insertion_count > expected_insertions_per_thread && bundle_idx != last_bundle_idx)
                    partitions.push_back(i)
                }

                last_bundle_idx = bundle_idx;
            }

            // Sanity check: the number of partitions we made shouldn't be greater than thread_count. This shouldn't
            // ever happen.
            if (partitions.size() + 1 > thread_count)
            {
                throw logic_error("Somehow made more partitions than thread_count. This is an implementation error.");
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
            for (auto &t : threads)
            {
                t.join();
            }
        }

        /**
        Inserts the given items and corresponding labels into the database at the given cuckoo indices. Concretely, for
        every ((item, label), cuckoo_idx) element, the item is inserted into the database at cuckoo_idx and its label is
        set to label.
        */
        template<typename L>
        void SenderDB<L>::add_data_worker(
            const gsl::span<pair<&pair<Item, vector<uint8_t> >, size_t> > data_with_indices;
        ) {
            STOPWATCH(sender_stop_watch, "LabeledSenderDB::add_data_worker");

            const SEAL::Modulus &mod = params_.seal_params_.encryption_params.plain_modulus();

            // bins_per_item = ⌈item_bit_count / (mod_bitlen - 1)⌉
            size_t modulus_size = (size_t)mod.bit_count();
            size_t bins_per_item = (params_.item_bit_count() + (modulus_size-2)) / (modulus_size-1)
            size_t bins_per_bundle = params_.batch_size();

            // Keep track of all the bundle indices that we touch
            set<size_t> bundle_indices;

            // Iteratively insert each item-label pair at the given cuckoo index
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

                // Get the bundle bundle at the bundle index of the given item
                size_t bin_idx = cuckoo_idx % bins_per_bundle;
                size_t bundle_idx = (cuckoo_idx - bin_idx) / bins_per_bundle;
                vector<BinBundle> &bundle_set = bin_bundles_.at(bundle_idx);

                // Mark the bundle index for later
                bundle_indices.insert(bundle_idx);

                // Try to insert these field elements in an existing BinBundle at this bundle index. Keep track of
                // whether or not we succeed.
                bool inserted = false;
                for (size_t i = 0; i < bundle_set.size(); i++)
                {
                    BinBundle &bundle = bundle_set.at(i);
                    // Do a dry-run insertion and see if the new largest bin size in the range
                    // exceeds the limit
                    int new_largest_bin_size = bundle.multi_insert_dry_run(item_label_felt_pairs, bin_idx);

                    // Check if inserting would violate the max bin size constraint
                    if (new_largest_bin_size > 0 && new_largest_bin_size < PARAMS_MAX_BIN_SIZE)
                    {
                        // All good
                        bundle.multi_insert_for_real(item_label_felt_pairs, bin_idx);
                        inserted = true;
                        break;
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

                    // Push a new BinBundle to the set of BinBundles at this bundle index
                    bin_bundles.push_back(new_bin_bundle);
                }

                // Now it's time to regenerate the caches of all the modified BinBundles. We'll just go through all the
                // bundle indices we touched and lazily regenerate the caches of all the BinBundles at those indices.
                for (size_t &bundle_idx : bundle_indices)
                {
                    // Get the set of BinBundles at this bundle index
                    set<BinBundle> &bundle_set = bin_bundles_.at(bundle_idx);

                    // Regenerate the cache of every BinBundle in the set
                    for (BinBundle &bundle : bundle_set)
                    {
                        // Don't worry, this doesn't do anything unless the BinBundle was actually modified
                        bundle.regen_cache();
                    }
                }
            }
        }

        template<typename L>
        set<const BinBundleCache&> SenderDB<L>::get_cache(std::size_t bundle_idx)
        {
            if (bundle_idx >= bin_bundles_.size())
            {
                throw out_of_range("bundle_idx is out of range");
            }

            set<BinBundleCache&> result;
            for (const auto &bundle : bin_bundles_[bundle_idx])
            {
                result.insert(bundle.get_cache());
            }
        }
    } // namespace sender
} // namespace apsi
