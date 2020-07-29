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
            crypto_context_(SEALContext::Create(params.encryption_params()))
        {
            // What is the actual length of strings stored in the hash table
            encoding_bit_length_ = params.item_bit_length_used_after_oprf();
            Log::debug("encoding bit length = %i", encoding_bit_length_);
        }

        void LabeledSenderDB::clear_db()
        {
            // Lock the database for writing
            auto lock = db_lock_.acquire_write();

            bin_bundles_.clear();
        }

        template<typename L>
        void LabeledSenderDB<L>::set_data(map<Item, vector<uint8_t> > &data, size_t thread_count)
        {
            STOPWATCH(sender_stop_watch, "LabeledSenderDB::set_data");
            clear_db();
            add_data(data, thread_count);
        }

        template<typename L>
        Modulus& BinBundle<L>::field_mod()
        {
            // Forgive me
            ContextData &context_data = crypto_context_.seal_context()->first_context_data();
            return context_data.parms().plain_modulus();
        }

        AlgItemLabel<felt_t> algebraize_item_label(Item &item, FullWidthLabel &label)
        {
            Modulus& mod = field_mod();

            // Convert the item from to a sequence of field elements. This is the "algebraic item".
            vector<felt_t> alg_item = bits_to_field_elts(item.to_bitstring(), mod);

            // Convert the label from to a sequence of field elements. This is the "algebraic label".
            vector<felt_t> alg_label = bits_to_field_elts(label.to_bitstring(), mod);

            // The number of field elements necessary to represent both these values MUST be the same
            if (alg_item.size() != alg_label.size())
            {
                throw logic_error("Items must take up as many slots as labels");
            }

            // Convert pair of vector to vector of pairs
            AlgItemLabel<felt_t> ret;
            for (size_t i = 0; i < alg_item.size(); i++)
            {
                ret.emplace_back({ alg_item[i], alg_label[i] });
            }

            return ret;
        }

        AlgItemLabel<monostate> algebraize_item(Item &item)
        {
            Modulus mod = field_mod();

            // Convert the item from to a sequence of field elements. This is the "algebraic item".
            vector<felt_t> alg_item = bits_to_field_elts(item.to_bitstring(), mod);

            // Convert vector to vector of pairs where the second element of each pair is monostate
            AlgItemLabel<monostate> ret;
            for (size_t i = 0; i < alg_item.size(); i++)
            {
                ret.emplace_back({ alg_item[i], monostate{} });
            }

            return ret;
        }

        vector<pair<AlgItemLabel<felt_t>, size_t> > preprocess_labeled_data(
            const std::map<Item, FullWidthLabel> &data,
            const size_t bins_per_item,
            const vector<kuku::LocFunc> &cuckoo_funcs
        ) {
            // Calculate the cuckoo indices for each item. Store every pair of (&item-label, cuckoo_idx) in a vector.
            // Later, we're gonna sort this vector by cuckoo_idx and use the result to parallelize the work of inserting
            // the items into BinBundles
            vector<pair<AlgItemLabel<felt_t>, size_t> > data_with_indices;
            for (auto &item_label_pair : data)
            {
                // Serialize the data into field elements
                Item &item = item_label_pair.first;
                FullWidthLabel &label = item_label_pair.second;
                AlgItemLabel<felt_t> alg_item_label = algebraize_item_label(item, label);

                // Collect the cuckoo indices, ignoring duplicates
                std::set<size_t> cuckoo_indices;
                for (kuku::LocFunc &hash_func : normal_loc_funcs)
                {
                    // The cuckoo index must be aligned to number of bins an item takes up
                    size_t cuckoo_idx = hash_func(item) * bins_per_item;

                    // Store the data along with its index
                    data_with_indices.push_back({ alg_item_label, cuckoo_idx });
                }
            }
        }

        vector<pair<AlgItemLabel<monostate>, size_t> > preprocess_unlabeled_data(
            const std::map<Item, monostate> &data,
            const size_t bins_per_item,
            const vector<kuku::LocFunc> &cuckoo_funcs
        ) {
            // Calculate the cuckoo indices for each item. Store every pair of (&item-label, cuckoo_idx) in a vector.
            // Later, we're gonna sort this vector by cuckoo_idx and use the result to parallelize the work of inserting
            // the items into BinBundles
            vector<pair<AlgItemLabel<felt_t>, size_t> > data_with_indices;
            for (auto &item_label_pair : data)
            {
                // Serialize the data into field elements
                Item &item = item_label_pair.first;
                AlgItemLabel<monostate> alg_item = algebraize_item(item);

                // Collect the cuckoo indices, ignoring duplicates
                std::set<size_t> cuckoo_indices;
                for (kuku::LocFunc &hash_func : normal_loc_funcs)
                {
                    // The cuckoo index must be aligned to number of bins an item takes up
                    size_t cuckoo_idx = hash_func(item) * bins_per_item;

                    // Store the data along with its index
                    data_with_indices.push_back({ alg_item, cuckoo_idx });
                }
            }
        }

        /**
        Inserts the given data into the database, using at most thread_count threads
        */
        void add_data(std::map<Item, FullWidthLabel> &data, size_t thread_count)
        {
            // Lock the database for writing
            auto lock = db_lock_.acquire_write();

            STOPWATCH(sender_stop_watch, "LabeledSenderDB::add_data");

            if (values.stride() != params_.label_byte_count())
                throw invalid_argument("unexpacted label length");


            // Construct the cuckoo hash functions
            vector<kuku::LocFunc> normal_loc_funcs;
            size_t bins_per_item = params_.bins_per_item();
            for (size_t i = 0; i < params_.hash_func_count(); i++)
            {
                kuku::LocFunc f = kuku::LocFunc(
                    params_.table_size(),
                    kuku::make_item(params_.hash_func_seed() + i, 0)
                );
                normal_loc_funcs.push_back(f);
            }

            // Break the data down into its field element sequences and cuckoo indices
            vector<pair<AlgItemLabel<felt_t>, size_t> > data_with_indices
                = preprocess_labeled_data(data, normal_loc_funcs);

            // Collect the bundle indices and partition them into thread_count many partitions. By some uniformity
            // assumption, the number of things to insert per partition should be roughly the same. Note that
            // the contents of bundle_indices is always sorted (increasing order).
            set<size_t> bundle_indices;
            for (auto &data_with_idx : data_with_indices)
            {
                size_t cuckoo_idx = data_with_idx.second;
                size_t bin_idx = cuckoo_idx % bins_per_bundle;
                size_t bundle_idx = (cuckoo_idx - bin_idx) / bins_per_bundle;
                bundle_indices.push(bundle_idx);
            }
            // Partition the bundles appropriately
            vector<pair<size_t, size_t> > partitions = partition_evenly(bundle_indices.size(), thread_count);

            // Run the threads on the partitions
            vector<thread> threads;
            size_t last_partition_cutoff = 0;
            for (auto &partition : partitions)
            {
                threads.emplace_back([&, t]() { add_data_worker(data_with_indices, partition); });
                last_partition_cutoff = partition_cutoff;
            }

            // Wait for the threads to finish
            for (auto &t : threads)
            {
                t.join();
            }
        }

        /**
        Inserts the given items and corresponding labels into bin_bundles at their respective cuckoo indices. It will
        only insert the data with bundle index in the half-open range range [begin_bundle_idx, end_bundle_idx). If
        inserting into a BinBundle would make the number of items in a bin larger than bin_size_threshold, this function
        will create and insert a new BinBundle.
        */
        template<typename L>
        void add_data_worker(
            vector<pair<AlgItemLabel<L>, size_t> > &data_with_indices,
            vector<set<BinBundle<L>> > &bin_bundles,
            size_t bin_size_threshold,
            size_t begin_bundle_idx,
            size_t end_bundle_idx,
        ) {
            STOPWATCH(sender_stop_watch, "LabeledSenderDB::add_data_worker");

            // Iteratively insert each item-label pair at the given cuckoo index
            for (auto &data_with_idx : data_with_indices)
            {
                auto &data = data_with_idx.first;

                // Get the bundle index
                size_t cuckoo_idx = data_with_indices.second;
                size_t bin_idx = cuckoo_idx % bins_per_bundle;
                size_t bundle_idx = (cuckoo_idx - bin_idx) / bins_per_bundle;

                // If the bundle_idx isn't in the prescribed range, don't try to insert this data
                if (bundle_idx < begin_bundle_idx || bundle_idx >= end_bundle_idx)
                {
                    continue;
                }

                // Get the bundle set at the given bundle index
                vector<BinBundle> &bundle_set = bin_bundles_.at(bundle_idx);

                // Try to insert these field elements in an existing BinBundle at this bundle index. Keep track of
                // whether or not we succeed.
                bool inserted = false;
                for (size_t i = 0; i < bundle_set.size(); i++)
                {
                    BinBundle &bundle = bundle_set.at(i);
                    // Do a dry-run insertion and see if the new largest bin size in the range
                    // exceeds the limit
                    int new_largest_bin_size = bundle.multi_insert_dry_run(data, bin_idx);

                    // Check if inserting would violate the max bin size constraint
                    if (new_largest_bin_size > 0 && new_largest_bin_size < bin_size_threshold)
                    {
                        // All good
                        bundle.multi_insert_for_real(data, bin_idx);
                        inserted = true;
                        break;
                    }
                }

                // If we had conflicts everywhere, then we need to make a new BinBundle and insert the data there
                if (!inserted)
                {
                    // Make a fresh BinBundle and insert
                    BinBundle new_bin_bundle(bins_per_bundle, crypto_context_);
                    int res = new_bin_bundle.multi_insert_for_real(data, bin_idx);

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
