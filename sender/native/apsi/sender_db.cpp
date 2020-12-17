// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <memory>
#include <thread>
#include <iterator>
#include <algorithm>

// APSI
#include "apsi/psi_params.h"
#include "apsi/sender_db.h"
#include "apsi/util/db_encoding.h"

// Kuku
#include "kuku/locfunc.h"

// SEAL
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace kuku;

namespace apsi
{
    using namespace util;
    using namespace logging;

    namespace sender
    {
        namespace
        {
            /**
            Creates and returns the vector of hash functions similarly to how Kuku 2.0 sets them internally.
            */
            vector<LocFunc> hash_functions(const PSIParams &params)
            {
                vector<LocFunc> result;
                for (uint32_t i = 0; i < params.table_params().hash_func_count; i++)
                {
                    result.emplace_back(params.table_params().table_size, make_item(i, 0));
                }

                return result;
            }

            /**
            Computes all cuckoo hash table locations for a given item.
            */
            unordered_set<location_type> all_locations(
                const vector<LocFunc> &hash_funcs,
                const HashedItem &item
            ) {
                unordered_set<location_type> result;
                for (auto &hf : hash_funcs)
                {
                    result.emplace(hf(item.value()));
                }

                return result;
            }

            /**
            Unpacks a cuckoo idx into its bin and bundle indices
            */
            pair<size_t, size_t> unpack_cuckoo_idx(size_t cuckoo_idx, size_t bins_per_bundle)
            {
                // Recall that bin indices are relative to the bundle index. That is, the first bin index of a bundle at
                // bundle index 5 is 0. A cuckoo index is similar, except it is not relative to the bundle index. It just
                // keeps counting past bundle boundaries. So in order to get the bin index from the cuckoo index, just
                // compute cuckoo_idx (mod bins_per_bundle).
                size_t bin_idx = cuckoo_idx % bins_per_bundle;

                // Compute which bundle index this cuckoo index belongs to
                size_t bundle_idx = (cuckoo_idx - bin_idx) / bins_per_bundle;

                return { bin_idx, bundle_idx };
            }

            /**
            Converts each given Item-Label pair in between the given iterators into its algebraic form, i.e., a sequence
            of felt-felt pairs. Also computes each Item's cuckoo index.
            */
            vector<pair<AlgItemLabel<felt_t>, size_t> > preprocess_labeled_data(
                const unordered_map<HashedItem, FullWidthLabel>::const_iterator begin,
                const unordered_map<HashedItem, FullWidthLabel>::const_iterator end,
                const PSIParams &params
            ) {
                STOPWATCH(sender_stopwatch, "preprocess_labeled_data");
                APSI_LOG_DEBUG("Start preprocessing " << distance(begin, end) << " labeled items");

                // Some variables we'll need
                size_t bins_per_item = params.item_params().felts_per_item;
                size_t item_bit_count = params.item_bit_count();
                const Modulus &mod = params.seal_params().plain_modulus();

                // Set up Kuku hash functions
                auto hash_funcs = hash_functions(params);

                // Calculate the cuckoo indices for each item. Store every pair of (item-label, cuckoo_idx) in a vector.
                // Later, we're gonna sort this vector by cuckoo_idx and use the result to parallelize the work of
                // inserting the items into BinBundles.
                vector<pair<AlgItemLabel<felt_t>, size_t> > data_with_indices;
                for (auto it = begin; it != end; it++)
                {
                    const pair<HashedItem, FullWidthLabel> &item_label_pair = *it;
                    // Serialize the data into field elements
                    const HashedItem &item = item_label_pair.first;
                    const FullWidthLabel &label = item_label_pair.second;
                    AlgItemLabel<felt_t> alg_item_label = algebraize_item_label(item, label, item_bit_count, mod);

                    // Get the cuckoo table locations for this item and add to data_with_indices
                    for (auto location : all_locations(hash_funcs, item))
                    {
                        // The current hash value is an index into a table of Items. In reality our BinBundles are
                        // tables of bins, which contain chunks of items. How many chunks? bins_per_item many chunks
                        size_t bin_idx = location * bins_per_item;

                        // Store the data along with its index
                        pair<AlgItemLabel<felt_t>, size_t> data_with_idx = { alg_item_label, bin_idx };
                        data_with_indices.push_back(move(data_with_idx));
                    }
                }

                APSI_LOG_DEBUG("Finished preprocessing " << distance(begin, end) << " labeled items");

                return data_with_indices;
            }

            /**
            Converts given Item-Label pair into its algebraic form, i.e., a sequence of felt-felt pairs. Also computes
            the Item's cuckoo index.
            */
            vector<pair<AlgItemLabel<felt_t>, size_t>> preprocess_labeled_data(
                const pair<HashedItem, FullWidthLabel> &item_label,
                const PSIParams &params
            ) {
                unordered_map<HashedItem, FullWidthLabel> item_label_singleton{ item_label };
                return preprocess_labeled_data(
                    item_label_singleton.begin(),
                    item_label_singleton.end(),
                    params);
            }

            /**
            Converts each given Item into its algebraic form, i.e., a sequence of felt-monostate pairs. Also computes
            each Item's cuckoo index.
            */
            vector<pair<AlgItemLabel<monostate>, size_t> > preprocess_unlabeled_data(
                const unordered_set<HashedItem>::const_iterator begin,
                const unordered_set<HashedItem>::const_iterator end,
                const PSIParams &params
            ) {
                STOPWATCH(sender_stopwatch, "preprocess_unlabeled_data");
                APSI_LOG_DEBUG("Start preprocessing " << distance(begin, end) << " unlabeled items");

                // Some variables we'll need
                size_t bins_per_item = params.item_params().felts_per_item;
                size_t item_bit_count = params.item_bit_count();
                const Modulus &mod = params.seal_params().plain_modulus();

                // Set up Kuku hash functions
                auto hash_funcs = hash_functions(params);

                // Calculate the cuckoo indices for each item. Store every pair of (item-label, cuckoo_idx) in a vector.
                // Later, we're gonna sort this vector by cuckoo_idx and use the result to parallelize the work of
                // inserting the items into BinBundles.
                vector<pair<AlgItemLabel<monostate>, size_t> > data_with_indices;
                for (auto it = begin; it != end; it++)
                {
                    const HashedItem &item = *it;

                    // Serialize the data into field elements
                    AlgItemLabel<monostate> alg_item = algebraize_item(item, item_bit_count, mod);

                    // Get the cuckoo table locations for this item and add to data_with_indices
                    for (auto location : all_locations(hash_funcs, item))
                    {
                        // The current hash value is an index into a table of Items. In reality our BinBundles are
                        // tables of bins, which contain chunks of items. How many chunks? bins_per_item many chunks
                        size_t bin_idx = location * bins_per_item;

                        // Store the data along with its index
                        pair<AlgItemLabel<monostate>, size_t> data_with_idx = { alg_item, bin_idx };
                        data_with_indices.push_back(move(data_with_idx));
                    }
                }

                APSI_LOG_DEBUG("Finished preprocessing " << distance(begin, end) << " labeled items");

                return data_with_indices;
            }

            /**
            Converts given Item into its algebraic form, i.e., a sequence of felt-monostate pairs. Also computes the
            Item's cuckoo index.
            */
            vector<pair<AlgItemLabel<monostate>, size_t>> preprocess_unlabeled_data(
                const HashedItem &item,
                const PSIParams &params
            ) {
                unordered_set<HashedItem> item_singleton{ item };
                return preprocess_unlabeled_data(
                    item_singleton.begin(),
                    item_singleton.end(),
                    params);
            }

            /**
            Inserts the given items and corresponding labels into bin_bundles at their respective cuckoo indices. It
            will only insert the data with bundle index in the half-open range range indicated by work_range. If
            inserting into a BinBundle would make the number of items in a bin larger than max_bin_size, this function
            will create and insert a new BinBundle. If overwrite is set, this will overwrite the labels if it finds an
            AlgItemLabel that matches the input perfectly.
            */
            template<typename L>
            void insert_or_assign_worker(
                const vector<pair<AlgItemLabel<L>, size_t> > &data_with_indices,
                vector<vector<BinBundle<L> > > &bin_bundles,
                CryptoContext &crypto_context,
                pair<size_t, size_t> work_range,
                uint32_t bins_per_bundle,
                size_t max_bin_size,
                bool overwrite,
                bool compressed)
            {
                stringstream sw_ss;
                sw_ss << "insert_or_assign_worker [" << this_thread::get_id() << "]";
                STOPWATCH(sender_stopwatch, sw_ss.str());

                uint32_t bundle_idx_start = work_range.first;
                uint32_t bundle_idx_end = work_range.second;

                APSI_LOG_DEBUG("Insert-or-Assign worker [" << this_thread::get_id() << "]: "
                    "start processing bundle indices in [" << bundle_idx_start << ", " << bundle_idx_end << ")");
                APSI_LOG_DEBUG("Insert-or-Assign worker [" << this_thread::get_id() << "]: "
                    "mode of operation: " << (overwrite ? "overwriting existing" : "inserting new"));

                // Keep track of the bundle indices we look at. These will be the ones whose cache we have to regen.
                unordered_set<size_t> bundle_indices;

                // Iteratively insert each item-label pair at the given cuckoo index
                for (auto &data_with_idx : data_with_indices)
                {
                    auto &data = data_with_idx.first;

                    // Get the bundle index
                    size_t cuckoo_idx = data_with_idx.second;
                    size_t bin_idx, bundle_idx;
                    tie(bin_idx, bundle_idx) = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);

                    // If the bundle_idx isn't in the prescribed range, don't try to insert this data
                    if (bundle_idx < bundle_idx_start || bundle_idx >= bundle_idx_end)
                    {
                        // Dealing with this bundle index is not our job
                        continue;
                    }

                    // We are inserting an item so mark the bundle index for cache regen
                    bundle_indices.insert(bundle_idx);

                    // Get the bundle set at the given bundle index
                    vector<BinBundle<L> > &bundle_set = bin_bundles.at(bundle_idx);

                    // Try to insert or overwrite these field elements in an existing BinBundle at this bundle index.
                    // Keep track of whether or not we succeed.
                    bool written = false;
                    for (BinBundle<L> &bundle : bundle_set)
                    {
                        // If we're supposed to overwrite, try to overwrite. One of these BinBundles has to have the
                        // data we're trying to overwrite.
                        if (overwrite)
                        {
                            // If we successfully overwrote, we're done with this bundle
                            written = bundle.try_multi_overwrite(data, bin_idx);
                            if (written)
                            {
                                break;
                            }
                        }

                        // Do a dry-run insertion and see if the new largest bin size in the range
                        // exceeds the limit
                        int new_largest_bin_size = bundle.multi_insert_dry_run(data, bin_idx);

                        // Check if inserting would violate the max bin size constraint
                        if (new_largest_bin_size > 0 && new_largest_bin_size < max_bin_size)
                        {
                            // All good
                            bundle.multi_insert_for_real(data, bin_idx);
                            written = true;
                            break;
                        }
                    }

                    // We tried to overwrite an item that doesn't exist. This should never happen
                    if (overwrite && !written)
                    {
                        APSI_LOG_ERROR("Insert-or-Assign worker [" << this_thread::get_id() << "]: "
                            "failed to overwrite item at bundle index " << bundle_idx << " "
                            "because the item was not found");
                        throw logic_error("tried to overwrite non-existent item");
                    }

                    // If we had conflicts everywhere when trying to insert, then we need to make a new BinBundle and
                    // insert the data there
                    if (!written)
                    {
                        // Make a fresh BinBundle and insert
                        BinBundle<L> new_bin_bundle(crypto_context, compressed);
                        int res = new_bin_bundle.multi_insert_for_real(data, bin_idx);

                        // If even that failed, I don't know what could've happened
                        if (res < 0)
                        {
                            APSI_LOG_ERROR("Insert-or-Assign worker [" << this_thread::get_id() << "]: "
                                "failed to insert item into a new BinBundle at bundle index " << bundle_idx);
                            throw logic_error("failed to insert item into a new BinBundle");
                        }

                        // Push a new BinBundle to the set of BinBundles at this bundle index
                        bundle_set.push_back(move(new_bin_bundle));
                    }
                }

                APSI_LOG_DEBUG("Insert-or-Assign worker [" << this_thread::get_id() << "]: "
                    "starting cache regeneration for " << bundle_indices.size() << " bundle indices");

                // Now it's time to regenerate the caches of all the modified BinBundles. We'll just go through all the
                // bundle indices we touched and lazily regenerate the caches of all the BinBundles at those indices.
                for (const size_t &bundle_idx : bundle_indices)
                {
                    // Get the set of BinBundles at this bundle index
                    vector<BinBundle<L> > &bundle_set = bin_bundles.at(bundle_idx);

                    APSI_LOG_DEBUG("Insert-or-Assign worker [" << this_thread::get_id() << "]: "
                        "regenerating cache for bundle index " << bundle_idx << " "
                        "with " << bundle_set.size() << " BinBundles");

                    // Regenerate the cache of every BinBundle in the set
                    for (BinBundle<L> &bundle : bundle_set)
                    {
                        // Don't worry, this doesn't do anything unless the BinBundle was actually modified
                        bundle.regen_cache();
                    }

                    APSI_LOG_DEBUG("Insert-or-Assign worker [" << this_thread::get_id() << "]: "
                        "finished regenerating cache for bundle index " << bundle_idx);
                }

                APSI_LOG_DEBUG("Insert-or-Assign worker [" << this_thread::get_id() << "]: "
                    "finished processing bundle indices [" << bundle_idx_start << ", " << bundle_idx_end << ")");
            }

            /**
            Takes algebraized data to be inserted, splits it up, and distributes it so that thread_count many threads
            can all insert in parallel. If overwrite is set, this will overwrite the labels if it finds an AlgItemLabel
            that matches the input perfectly.
            */
            template<typename L>
            void dispatch_insert_or_assign(
                vector<pair<AlgItemLabel<L>, size_t > > &data_with_indices,
                vector<vector<BinBundle<L> > > &bin_bundles,
                CryptoContext &crypto_context,
                uint32_t bins_per_bundle,
                uint32_t max_bin_size,
                size_t thread_count,
                bool overwrite,
                bool compressed
            ) {
                // Collect the bundle indices and partition them into thread_count many partitions. By some uniformity
                // assumption, the number of things to insert per partition should be roughly the same. Note that
                // the contents of bundle_indices is always sorted (increasing order).
                set<size_t> bundle_indices_set;
                for (auto &data_with_idx : data_with_indices)
                {
                    size_t cuckoo_idx = data_with_idx.second;
                    size_t bin_idx, bundle_idx;
                    tie(bin_idx, bundle_idx) = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);
                    bundle_indices_set.insert(bundle_idx);
                }

                // Copy the set of indices into a vector and sort so each thread processes a range of indices
                vector<size_t> bundle_indices;
                bundle_indices.reserve(bundle_indices_set.size());
                copy(bundle_indices_set.begin(), bundle_indices_set.end(), back_inserter(bundle_indices));
                sort(bundle_indices.begin(), bundle_indices.end());

                // Partition the bundle indices appropriately
                vector<pair<size_t, size_t> > partitions = partition_evenly(bundle_indices.size(), thread_count);

                // Insert one larger "end" value to the bundle_indices vector; this represents one-past upper bound for
                // the bundle indices that need to be processed.
                if (!bundle_indices.empty())
                {
                    bundle_indices.push_back(bundle_indices.back() + 1);
                }

                // Run the threads on the partitions
                vector<thread> threads;
                APSI_LOG_INFO("Launching " << partitions.size() << " insert-or-assign worker threads");
                for (auto &partition : partitions)
                {
                    threads.emplace_back([&, partition]() {
                        insert_or_assign_worker(
                            data_with_indices,
                            bin_bundles,
                            crypto_context,
                            make_pair(bundle_indices[partition.first], bundle_indices[partition.second]),
                            bins_per_bundle,
                            max_bin_size,
                            overwrite,
                            compressed
                        );
                    });
                }

                // Wait for the threads to finish
                for (auto &t : threads)
                {
                    t.join();
                }
            }

            /**
            Removes the given items and corresponding labels from bin_bundles at their respective cuckoo indices.
            */
            template<typename L>
            void remove_worker(
                const vector<pair<AlgItemLabel<monostate>, size_t> > &data_with_indices,
                vector<vector<BinBundle<L> > > &bin_bundles,
                CryptoContext &crypto_context,
                pair<size_t, size_t> work_range,
                uint32_t bins_per_bundle)
            {
                stringstream sw_ss;
                sw_ss << "remove_worker [" << this_thread::get_id() << "]";
                STOPWATCH(sender_stopwatch, sw_ss.str());

                uint32_t bundle_idx_start = work_range.first;
                uint32_t bundle_idx_end = work_range.second;

                APSI_LOG_INFO("Remove worker [" << this_thread::get_id() << "]: "
                    "start processing bundle indices in [" << bundle_idx_start << ", " << bundle_idx_end << ")");

                // Keep track of the bundle indices we look at. These will be the ones whose cache we have to regen.
                unordered_set<size_t> bundle_indices;

                // Iteratively remove each item-label pair at the given cuckoo index
                for (auto &data_with_idx : data_with_indices)
                {
                    // Convert the vector [(felt, ()), (felt, ()), ..., ] to [felt, felt, felt, ...]
                    vector<felt_t> algebraized_item;
                    algebraized_item.reserve(data_with_idx.first.size());
                    for (auto &item_label : data_with_idx.first)
                    {
                        algebraized_item.push_back(item_label.first);
                    }

                    // Get the bundle index
                    size_t cuckoo_idx = data_with_idx.second;
                    size_t bin_idx, bundle_idx;
                    tie(bin_idx, bundle_idx) = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);

                    // If the bundle_idx isn't in the prescribed range, don't try to remove this data
                    if (bundle_idx < bundle_idx_start || bundle_idx >= bundle_idx_end)
                    {
                        // Dealing with this bundle index is not our job
                        continue;
                    }

                    // We are removing an item so mark the bundle index for cache regen
                    bundle_indices.insert(bundle_idx);

                    // Get the bundle set at the given bundle index
                    vector<BinBundle<L> > &bundle_set = bin_bundles.at(bundle_idx);

                    // Try to remove these field elements from an existing BinBundle at this bundle index. Keep track
                    // of whether or not we succeed.
                    bool removed = false;
                    for (BinBundle<L> &bundle : bundle_set)
                    {
                        // If we successfully removed, we're done with this bundle
                        removed = bundle.try_multi_remove(algebraized_item, bin_idx);
                        if (removed)
                        {
                            break;
                        }
                    }

                    // We may have produced some empty BinBundles so just remove them all
                    auto rem_it = remove_if(bundle_set.begin(), bundle_set.end(), [](auto &bundle) { return bundle.empty(); });
                    bundle_set.erase(rem_it, bundle_set.end());

                    // We tried to remove an item that doesn't exist. This should never happen
                    if (!removed)
                    {
                        APSI_LOG_ERROR("Remove worker [" << this_thread::get_id() << "]: "
                            "failed to remove item at bundle index " << bundle_idx << " "
                            "because the item was not found");
                        throw logic_error("failed to remove item");
                    }
                }

                APSI_LOG_DEBUG("Remove worker [" << this_thread::get_id() << "]: "
                    "starting cache regeneration for " << bundle_indices.size() << " bundle indices");

                // Now it's time to regenerate the caches of all the modified BinBundles. We'll just go through all the
                // bundle indices we touched and lazily regenerate the caches of all the BinBundles at those indices.
                for (const size_t &bundle_idx : bundle_indices)
                {
                    // Get the set of BinBundles at this bundle index
                    vector<BinBundle<L> > &bundle_set = bin_bundles.at(bundle_idx);

                    APSI_LOG_DEBUG("Remove worker [" << this_thread::get_id() << "]: "
                        "regenerating cache for bundle index " << bundle_idx << " "
                        "with " << bundle_set.size() << " BinBundles");

                    // Regenerate the cache of every BinBundle in the set
                    for (BinBundle<L> &bundle : bundle_set)
                    {
                        // Don't worry, this doesn't do anything unless the BinBundle was actually modified
                        bundle.regen_cache();
                    }

                    APSI_LOG_DEBUG("Remove worker [" << this_thread::get_id() << "]: "
                        "finished regenerating cache for bundle index " << bundle_idx);
                }

                APSI_LOG_INFO("Remove worker [" << this_thread::get_id() << "]: "
                    "finished processing bundle indices [" << bundle_idx_start << ", " << bundle_idx_end << ")");
            }

            /**
            Takes algebraized data to be removed, splits it up, and distributes it so that thread_count many threads
            can all remove in parallel.
            */
            template <typename L>
            void dispatch_remove(
                const vector<pair<AlgItemLabel<monostate>, size_t >> &data_with_indices,
                vector<vector<BinBundle<L> > > &bin_bundles,
                CryptoContext &crypto_context,
                uint32_t bins_per_bundle,
                size_t thread_count
            ) {
                // Collect the bundle indices and partition them into thread_count many partitions. By some uniformity
                // assumption, the number of things to remove per partition should be roughly the same. Note that the
                // contents of bundle_indices is always sorted (increasing order).
                set<size_t> bundle_indices_set;
                for (auto &data_with_idx : data_with_indices)
                {
                    size_t cuckoo_idx = data_with_idx.second;
                    size_t bin_idx, bundle_idx;
                    tie(bin_idx, bundle_idx) = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);
                    bundle_indices_set.insert(bundle_idx);
                }

                // Copy the set of indices into a vector and sort so each thread processes a range of indices
                vector<size_t> bundle_indices;
                bundle_indices.reserve(bundle_indices_set.size());
                copy(bundle_indices_set.begin(), bundle_indices_set.end(), back_inserter(bundle_indices));
                sort(bundle_indices.begin(), bundle_indices.end());

                // Partition the bundle indices appropriately
                vector<pair<size_t, size_t> > partitions = partition_evenly(bundle_indices.size(), thread_count);

                // Insert one larger "end" value to the bundle_indices vector; this represents one-past upper bound for
                // the bundle indices that need to be processed.
                if (!bundle_indices.empty())
                {
                    bundle_indices.push_back(bundle_indices.back() + 1);
                }

                // Run the threads on the partitions
                vector<thread> threads;
                APSI_LOG_INFO("Launching " << partitions.size() << " remove worker threads");
                for (auto &partition : partitions)
                {
                    threads.emplace_back([&, partition]() {
                        remove_worker(
                            data_with_indices,
                            bin_bundles,
                            crypto_context,
                            make_pair(bundle_indices[partition.first], bundle_indices[partition.second]),
                            bins_per_bundle
                        );
                    });
                }

                // Wait for the threads to finish
                for (auto &t : threads)
                {
                    t.join();
                }
            }

            /**
            Returns a set of DB cache references corresponding to the bundles in the given set
            */
            template<typename L>
            vector<reference_wrapper<const BinBundleCache> > collect_caches(vector<BinBundle<L> > &bin_bundles)
            {
                vector<reference_wrapper<const BinBundleCache> > result;
                for (const auto &bundle : bin_bundles)
                {
                    result.emplace_back(cref(bundle.get_cache()));
                }

                return result;
            }
        }

        SenderDB::SenderDB(PSIParams params, bool compressed) :
            params_(params), crypto_context_(params_.seal_params()), compressed_(compressed)
        {
            if (!get_seal_context()->parameters_set())
            {
                APSI_LOG_ERROR("Given SEALParams are invalid: "
                    << get_seal_context()->parameter_error_message());
                throw logic_error("SEALParams are invalid");
            }
            if (!get_seal_context()->first_context_data()->qualifiers().using_batching)
            {
                APSI_LOG_ERROR("Given SEALParams do not support batching");
                throw logic_error("given SEALParams do not support batching");
            }

            // Make sure the evaluator is set. This will be used for BatchedPlaintextPolyn::eval.
            crypto_context_.set_evaluator();
        }

        /**
        Returns the total number of bin bundles.
        */
        size_t LabeledSenderDB::get_bin_bundle_count()
        {
            // Lock the database for reading
            auto lock = get_reader_lock();

            // Compute the total number of bin bundles
            return accumulate(bin_bundles_.cbegin(), bin_bundles_.cend(), size_t(0),
                [&](auto &a, auto &b) { return a + b.size(); });
        }

        /**
        Returns the total number of bin bundles.
        */
        size_t UnlabeledSenderDB::get_bin_bundle_count()
        {
            // Lock the database for reading
            auto lock = get_reader_lock();

            // Compute the total number of bin bundles
            return accumulate(bin_bundles_.cbegin(), bin_bundles_.cend(), size_t(0),
                [&](auto &a, auto &b) { return a + b.size(); });
        }

        /**
        Clears the database
        */
        void LabeledSenderDB::clear_db()
        {
            if (items_.size())
            {
                APSI_LOG_INFO("Removing " << items_.size() << " item-label pairs from SenderDB");
            }

            // Lock the database for writing
            auto lock = db_lock_.acquire_write();

            // Clear the set of inserted items
            items_.clear();

            // Clear the BinBundles
            bin_bundles_.clear();
            bin_bundles_.resize(params_.bundle_idx_count());
        }

        /**
        Clears the database
        */
        void UnlabeledSenderDB::clear_db()
        {
            if (items_.size())
            {
                APSI_LOG_INFO("Removing " << items_.size() << " items from SenderDB");
            }

            // Lock the database for writing
            auto lock = db_lock_.acquire_write();

            // Clear the set of inserted items
            items_.clear();

            // Clear the BinBundles
            bin_bundles_.clear();
            bin_bundles_.resize(params_.bundle_idx_count());
        }

        /**
        Returns a set of DB cache references corresponding to the bundles at the given bundle index.
        */
        vector<reference_wrapper<const BinBundleCache> > LabeledSenderDB::get_cache_at(uint32_t bundle_idx)
        {
            return collect_caches(bin_bundles_.at(safe_cast<size_t>(bundle_idx)));
        }

        /**
        Returns a set of DB cache references corresponding to the bundles at the given bundle index.
        */
        vector<reference_wrapper<const BinBundleCache> > UnlabeledSenderDB::get_cache_at(uint32_t bundle_idx)
        {
            return collect_caches(bin_bundles_.at(safe_cast<size_t>(bundle_idx)));
        }

        /**
        Inserts the given data into the database, using at most thread_count threads.
        */
        void LabeledSenderDB::insert_or_assign(const unordered_map<HashedItem, FullWidthLabel> &data, size_t thread_count)
        {
            thread_count = thread_count < 1 ? thread::hardware_concurrency() : thread_count;

            STOPWATCH(sender_stopwatch, "LabeledSenderDB::insert_or_assign");
            APSI_LOG_INFO("Start inserting " << data.size() << " items in SenderDB");

            // Lock the database for writing
            auto lock = db_lock_.acquire_write();

            // We need to know which items are new and which are old, since we have to tell dispatch_insert_or_assign
            // when to have an overwrite-on-collision versus add-binbundle-on-collision policy.
            unordered_map<HashedItem, FullWidthLabel> new_data, existing_data;
            for (auto item_label_pair : data)
            {
                const HashedItem &item = item_label_pair.first;

                if (items_.find(item) == items_.end())
                {
                    // Item is not already in items_, i.e., if this is a new item
                    new_data.emplace(move(item_label_pair));
                }
                else
                {
                    // Replacing an existing item 
                    existing_data.emplace(move(item_label_pair));
                }
            }

            APSI_LOG_INFO("Found " << new_data.size() << " new items to insert in SenderDB");
            APSI_LOG_INFO("Found " << existing_data.size() << " existing items to replace in SenderDB");

            // Break the new data down into its field element representation. Also compute the items' cuckoo indices.
            vector<pair<AlgItemLabel<felt_t>, size_t> > new_data_with_indices
                = preprocess_labeled_data(new_data.begin(), new_data.end(), params_);

            // Now do the same for the data we're going to overwrite
            vector<pair<AlgItemLabel<felt_t>, size_t> > overwritable_data_with_indices
                = preprocess_labeled_data(existing_data.begin(), existing_data.end(), params_);

            // Dispatch the insertion, first for the new data, then for the data we're gonna overwrite
            uint32_t bins_per_bundle = params_.bins_per_bundle();
            uint32_t max_bin_size = params_.table_params().max_items_per_bin;

            dispatch_insert_or_assign(
                new_data_with_indices,
                bin_bundles_,
                crypto_context_,
                bins_per_bundle,
                max_bin_size,
                thread_count,
                false, /* don't overwrite items */
                compressed_
            );

            dispatch_insert_or_assign(
                overwritable_data_with_indices,
                bin_bundles_,
                crypto_context_,
                bins_per_bundle,
                max_bin_size,
                thread_count,
                true, /* overwrite items */
                compressed_
            );

            // Now that everything is inserted, add the new items to the cache of all inserted items
            for (const auto &it : new_data)
            {
                items_.insert(it.first);
            }

            APSI_LOG_INFO("Finished inserting " << data.size() << " items in SenderDB");
        }

        /**
        Throws an error. This should never be called. The only reason this exists is because SenderDB is an interface
        that needs to support both labeled and unlabeled insertion. A LabeledSenderDB does not do unlabeled insertion.
        */
        void LabeledSenderDB::insert_or_assign(const unordered_set<HashedItem> &data, size_t thread_count)
        {
            APSI_LOG_ERROR("Attempted to insert unlabeled data but this is a LabeledSenderDB instance")
            throw logic_error("cannot do unlabeled insertion on a LabeledSenderDB");
        }

        /**
        Inserts the given data into the database, using at most thread_count threads.
        */
        void UnlabeledSenderDB::insert_or_assign(const unordered_set<HashedItem> &data, size_t thread_count)
        {
            thread_count = thread_count < 1 ? thread::hardware_concurrency() : thread_count;

            STOPWATCH(sender_stopwatch, "UnlabeledSenderDB::insert_or_assign");
            APSI_LOG_INFO("Start inserting " << data.size() << " items in SenderDB");

            // Lock the database for writing
            auto lock = db_lock_.acquire_write();

            // We are not going to insert items that already appear in the database.
            unordered_set<HashedItem> new_data;
            for (auto item : data)
            {
                if (items_.find(item) == items_.end())
                {
                    // Item is not already in items_, i.e., if this is a new item
                    new_data.emplace(move(item));
                }
            }

            // Break the new data down into its field element representation. Also compute the items' cuckoo indices.
            vector<pair<AlgItemLabel<monostate>, size_t> > data_with_indices
                = preprocess_unlabeled_data(new_data.begin(), new_data.end(), params_);

            // Dispatch the insertion
            uint32_t bins_per_bundle = params_.bins_per_bundle();
            uint32_t max_bin_size = params_.table_params().max_items_per_bin;

            dispatch_insert_or_assign(
                data_with_indices,
                bin_bundles_,
                crypto_context_,
                bins_per_bundle,
                max_bin_size,
                thread_count,
                false, /* don't overwrite items */
                compressed_
            );

            // Now that everything is inserted, add the new items to the cache of all inserted items. Some of these may
            // be repeats but it doesn't matter because set insertion is idempotent.
            items_.insert(data.begin(), data.end());

            APSI_LOG_INFO("Finished inserting " << data.size() << " items in SenderDB");
        }

        /**
        Throws an error. This should never be called. The only reason this exists is because SenderDB is an interface
        that needs to support both labeled and unlabeled insertion. An UnlabeledSenderDB does not do labeled insertion.
        */
        void UnlabeledSenderDB::insert_or_assign(
            const unordered_map<HashedItem, FullWidthLabel> &data,
            size_t thread_count
        ) {
            APSI_LOG_ERROR("Attempted to insert labeled data but this is an UnlabeledSenderDB instance")
            throw logic_error("cannot do labeled insertion on an UnlabeledSenderDB");
        }

        /**
        Removes the given data from the database, using at most thread_count threads.
        */
        void LabeledSenderDB::remove(
            const unordered_set<HashedItem> &data,
            size_t thread_count
        ) {
            thread_count = thread_count < 1 ? thread::hardware_concurrency() : thread_count;

            STOPWATCH(sender_stopwatch, "LabeledSenderDB::remove");
            APSI_LOG_INFO("Start removing " << data.size() << " items-label pairs from SenderDB");

            // Lock the database for writing
            auto lock = db_lock_.acquire_write();

            // We need to check that all the items actually are in the database.
            for (auto item : data)
            {
                if (items_.find(item) == items_.end())
                {
                    // Item is not in items_; cannot remove it
                    throw invalid_argument("item to be removed was not found in SenderDB");
                }
            }

            // Break the data to be removed down into its field element representation. Also compute the items' cuckoo
            // indices.
            vector<pair<AlgItemLabel<monostate>, size_t> > data_with_indices
                = preprocess_unlabeled_data(data.begin(), data.end(), params_);

            // Dispatch the removal 
            uint32_t bins_per_bundle = params_.bins_per_bundle();

            dispatch_remove(
                data_with_indices,
                bin_bundles_,
                crypto_context_,
                bins_per_bundle,
                thread_count
            );

            // Now that everything is removed, clear these items from the cache of all inserted items.
            for (auto &item : data)
            {
                items_.erase(item);
            }

            APSI_LOG_INFO("Finished removing " << data.size() << " item-label pairs from SenderDB");
        }

        /**
        Removes the given data from the database, using at most thread_count threads.
        */
        void UnlabeledSenderDB::remove(
            const unordered_set<HashedItem> &data,
            size_t thread_count
        ) {
            thread_count = thread_count < 1 ? thread::hardware_concurrency() : thread_count;

            STOPWATCH(sender_stopwatch, "UnlabeledSenderDB::remove");
            APSI_LOG_INFO("Start removing " << data.size() << " items from SenderDB");

            // Lock the database for writing
            auto lock = db_lock_.acquire_write();

            // We need to check that all the items actually are in the database.
            for (auto item : data)
            {
                if (items_.find(item) == items_.end())
                {
                    // Item is not in items_; cannot remove it
                    throw invalid_argument("item to be removed was not found in SenderDB");
                }
            }

            // Break the data to be removed down into its field element representation. Also compute the items' cuckoo
            // indices.
            vector<pair<AlgItemLabel<monostate>, size_t> > data_with_indices
                = preprocess_unlabeled_data(data.begin(), data.end(), params_);

            // Dispatch the removal 
            uint32_t bins_per_bundle = params_.bins_per_bundle();

            dispatch_remove(
                data_with_indices,
                bin_bundles_,
                crypto_context_,
                bins_per_bundle,
                thread_count
            );

            // Now that everything is removed, clear these items from the cache of all inserted items.
            for (auto &item : data)
            {
                items_.erase(item);
            }

            APSI_LOG_INFO("Finished removing " << data.size() << " items from SenderDB");
        }

        /**
        Clears the database and inserts the given data, using at most thread_count threads
        */
        void LabeledSenderDB::set_data(
            const unordered_map<HashedItem, FullWidthLabel> &data,
            size_t thread_count
        ) {
            clear_db();
            insert_or_assign(data, thread_count);
        }

        /**
        This does not and should not work. See LabeledSenderDB::insert_or_assign
        */
        void LabeledSenderDB::set_data(const unordered_set<HashedItem> &data, size_t thread_count) {
            APSI_LOG_ERROR("Attempted to set unlabeled data but this is a LabeledSenderDB instance")
            throw logic_error("cannot do unlabeled insertion on a LabeledSenderDB");
        }

        /**
        Clears the database and inserts the given data, using at most thread_count threads
        */
        void UnlabeledSenderDB::set_data(const unordered_set<HashedItem> &data, size_t thread_count) {
            clear_db();
            insert_or_assign(data, thread_count);
        }

        /**
        This does not and should not work. See UnlabeledSenderDB::insert_or_assign
        */
        void UnlabeledSenderDB::set_data(const unordered_map<HashedItem, FullWidthLabel> &data, size_t thread_count)
        {
            APSI_LOG_ERROR("Attempted to set labeled data but this is an UnlabeledSenderDB instance")
            throw logic_error("cannot do labeled insertion on an UnlabeledSenderDB");
        }

        /**
        Returns the label associated to the given item in the database. Throws invalid_argument if the item does
        not appear in the database.
        */
        FullWidthLabel LabeledSenderDB::get_label(const HashedItem &item) const
        {
            // Check if this item is in the DB. If not, throw an exception
            if (items_.count(item) == 0)
            {
                APSI_LOG_ERROR("Cannot retrieve label for an item that is not in the SenderDB")
                throw invalid_argument("item was not found in SenderDB");
            }

            APSI_LOG_DEBUG("Start retrieving label for " << item.to_string());

            uint32_t bins_per_bundle = params_.bins_per_bundle();

            // Preprocess a single element. This algebraizes the item and gives back its field element representation
            // as well as its cuckoo hash. We only read one of the locations because the labels are the same in each
            // location.
            AlgItemLabel<monostate> algebraized_item_label;
            size_t cuckoo_idx;
            tie(algebraized_item_label, cuckoo_idx) = preprocess_unlabeled_data(item, params_)[0];

            // Convert the vector [(felt, ()), (felt, ()), ..., ] to [felt, felt, felt, ...]
            vector<felt_t> algebraized_item;
            algebraized_item.reserve(algebraized_item_label.size());
            for (auto &item_label : algebraized_item_label)
            {
                algebraized_item.push_back(item_label.first);
            }

            // Now figure out where to look to get the label
            size_t bin_idx, bundle_idx;
            tie(bin_idx, bundle_idx) = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);

            // Retrieve the algebraic labels from one of the BinBundles at this index
            const vector<BinBundle<felt_t> > &bundle_set = bin_bundles_.at(bundle_idx);
            vector<felt_t> alg_labels;
            bool got_labels = false;
            for (const BinBundle<felt_t> &bundle : bundle_set)
            {
                // Try to retrieve the contiguous labels from this BinBundle
                if (bundle.try_get_multi_label(algebraized_item, bin_idx, alg_labels))
                {
                    got_labels = true;
                    break;
                }
            }

            // It shouldn't be possible to have items in your set but be unable to retrieve the associated label. Throw
            // an exception because something is terribly wrong.
            if (!got_labels)
            {
                APSI_LOG_ERROR("Failed to retrieve label for an item that was supposed to be in the SenderDB")
                throw logic_error("item is in set but labels could not be found in any BinBundle");
            }

            // All good. Now just reconstruct the big label from its split-up parts and return it
            size_t item_bit_count = params_.item_bit_count();
            const Modulus &mod = params_.seal_params().plain_modulus();

            // We can use dealgebraize_item because items and labels are the same size
            auto result = dealgebraize_item(alg_labels, item_bit_count, mod);

            APSI_LOG_DEBUG("Finished retrieving label for " << item.to_string());

            return result;
        }
    } // namespace sender
} // namespace apsi
