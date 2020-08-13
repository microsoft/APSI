// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <numeric>

// APSI
#include "apsi/psiparams.h"
#include "apsi/senderdb.h"
#include "apsi/util/db_encoding.cpp"

using namespace std;
using namespace seal;

namespace apsi
{
    using namespace util;
    using namespace logging;

    namespace sender
    {
        namespace
        {
            /**
            Converts each given Item-Label pair into its algebraic form, i.e., a sequence of felt-felt pairs. Also computes
            each Item's cuckoo index.
            */
            vector<pair<AlgItemLabel<felt_t>, size_t> > preprocess_labeled_data(
                const std::map<Item, FullWidthLabel> &data,
                PSIParams &params
            ) {
                // Some variables we'll need
                size_t bins_per_item = params.bins_per_item();
                size_t item_bit_count = params.item_bit_count();
                const Modulus &mod = params.seal_params().plain_modulus();

                // Construct the cuckoo hash functions
                vector<kuku::LocFunc> normal_loc_funcs;
                for (size_t i = 0; i < params.hash_func_count(); i++)
                {
                    kuku::LocFunc f = kuku::LocFunc(
                        params.table_size(),
                        kuku::make_item(i, 0)
                    );
                    normal_loc_funcs.push_back(f);
                }

                // Calculate the cuckoo indices for each item. Store every pair of (&item-label, cuckoo_idx) in a vector.
                // Later, we're gonna sort this vector by cuckoo_idx and use the result to parallelize the work of inserting
                // the items into BinBundles
                vector<pair<AlgItemLabel<felt_t>, size_t> > data_with_indices;
                for (auto &item_label_pair : data)
                {
                    // Serialize the data into field elements
                    Item &item = item_label_pair.first;
                    FullWidthLabel &label = item_label_pair.second;
                    AlgItemLabel<felt_t> alg_item_label = algebraize_item_label(item, label, item_bit_count, mod);

                    // Collect the cuckoo indices, ignoring duplicates
                    std::set<size_t> cuckoo_indices;
                    for (kuku::LocFunc &hash_func : normal_loc_funcs)
                    {
                        // The current hash value is an index into a table of Items. In reality our BinBundles are tables of
                        // bins, which contain chunks of items. How many chunks? bins_per_item many chunks
                        size_t cuckoo_idx = hash_func(item) * bins_per_item;

                        // Store the data along with its index
                        data_with_indices.push_back({ alg_item_label, cuckoo_idx });
                    }
                }
            }

            /*
            Converts each given Item into its algebraic form, i.e., a sequence of felt-monostate pairs. Also computes each
            Item's cuckoo index.
            */
            vector<pair<AlgItemLabel<monostate>, size_t> > preprocess_unlabeled_data(
                const std::map<Item, monostate> &data,
                PSIParams &params
            ) {
                // Some variables we'll need
                size_t bins_per_item = params.bins_per_item();
                size_t item_bit_count = params.item_bit_count();
                const Modulus &mod = params.seal_params().plain_modulus();

                // Construct the cuckoo hash functions
                vector<kuku::LocFunc> normal_loc_funcs;
                for (size_t i = 0; i < params.hash_func_count(); i++)
                {
                    kuku::LocFunc f = kuku::LocFunc(
                        params.table_size(),
                        kuku::make_item(i, 0)
                    );
                    normal_loc_funcs.push_back(f);
                }

                // Calculate the cuckoo indices for each item. Store every pair of (&item-label, cuckoo_idx) in a vector.
                // Later, we're gonna sort this vector by cuckoo_idx and use the result to parallelize the work of inserting
                // the items into BinBundles
                vector<pair<AlgItemLabel<felt_t>, size_t> > data_with_indices;
                for (auto &item_label_pair : data)
                {
                    // Serialize the data into field elements
                    Item &item = item_label_pair.first;
                    AlgItemLabel<monostate> alg_item = algebraize_item(item, item_bit_count, mod);

                    // Collect the cuckoo indices, ignoring duplicates
                    std::set<size_t> cuckoo_indices;
                    for (kuku::LocFunc &hash_func : normal_loc_funcs)
                    {
                        // The current hash value is an index into a table of Items. In reality our BinBundles are tables of
                        // bins, which contain chunks of items. How many chunks? bins_per_item many chunks
                        size_t cuckoo_idx = hash_func(item) * bins_per_item;

                        // Store the data along with its index
                        data_with_indices.push_back({ alg_item, cuckoo_idx });
                    }
                }
            }

            /**
            Returns the bundle idx that the given cuckoo idx belongs to
            */
            size_t cuckoo_idx_to_bundle_idx(size_t cuckoo_idx, size_t bins_per_bundle)
            {
                // Recall that bin indices are relative to the bundle index. That is, the first bin index of a bundle at
                // bundle index 5 is 0. A cuckoo index is similar, except it is not relative to the bundle index. It just
                // keeps counting past bundle boundaries. So in order to get the bin index from the cuckoo index, just
                // compute cuckoo_idx (mod bins_per_bundle).
                size_t bin_idx = cuckoo_idx % bins_per_bundle;
                // Now compute which bundle index this cuckoo index belongs to
                size_t bundle_idx = (cuckoo_idx - bin_idx) / bins_per_bundle;

                return bundle_idx;
            }

            /**
            Takes algebraized data to be inserted, splits it up, and distributes it so that thread_count many threads can
            all insert in parallel
            */
            template<L>
            void dispatch_add_data(
                vector<pair<AlgItemLabel<L>, size_t > > &data_with_indices
                vector<set<BinBundle<L>> > &bin_bundles,
                uint32_t bins_per_bundle,
                size_t thread_count
            ) {

                // Collect the bundle indices and partition them into thread_count many partitions. By some uniformity
                // assumption, the number of things to insert per partition should be roughly the same. Note that
                // the contents of bundle_indices is always sorted (increasing order).
                set<size_t> bundle_indices;
                for (auto &data_with_idx : data_with_indices)
                {
                    size_t cuckoo_idx = data_with_idx.second;
                    size_t bundle_idx = cuckoo_idx_to_bundle_idx(cuckoo_idx, bins_per_bundle);
                    bundle_indices.insert(bundle_idx);
                }

                // Partition the bundle indices appropriately
                vector<pair<size_t, size_t> > partitions = partition_evenly(bundle_indices.size(), thread_count);

                // Run the threads on the partitions
                vector<thread> threads;
                uint32_t max_bin_size = params_.table_params().max_bin_size;
                for (auto &partition : partitions)
                {
                    threads.emplace_back([&, t]() {
                        size_t start_idx = partition.first;
                        size_t end_idx = partition.second;
                        add_data_worker(data_with_indices, bin_bundles, bins_per_bundle, max_bin_size, start_idx, end_idx);
                    });
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
            inserting into a BinBundle would make the number of items in a bin larger than max_bin_size, this function
            will create and insert a new BinBundle.
            */
            template<typename L>
            void add_data_worker(
                vector<pair<AlgItemLabel<L>, size_t> > &data_with_indices,
                vector<set<BinBundle<L>> > &bin_bundles,
                uint32_t bins_per_bundle,
                size_t max_bin_size,
                size_t begin_bundle_idx,
                size_t end_bundle_idx,
            ) {
                STOPWATCH(sender_stopwatch, "LabeledSenderDB::add_data_worker");

                // Iteratively insert each item-label pair at the given cuckoo index
                for (auto &data_with_idx : data_with_indices)
                {
                    auto &data = data_with_idx.first;

                    // Get the bundle index
                    size_t cuckoo_idx = data_with_indices.second;
                    size_t bundle_idx = cuckoo_idx_to_bundle_idx(cuckoo_idx, bins_per_bundle);

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
                        if (new_largest_bin_size > 0 && new_largest_bin_size < max_bin_size)
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
        }

        LabeledSenderDB::LabeledSenderDB(PSIParams params) :
            params_(params),
            crypto_context_(SEALContext::Create(params.encryption_params()))
        {
            // What is the actual length of strings stored in the hash table
            encoding_bit_length_ = params.item_bit_length_used_after_oprf();
            Log::debug("encoding bit length = %i", encoding_bit_length_);
        }

        /**
        Clears the database
        */
        void LabeledSenderDB::clear_db()
        {
            // Lock the database for writing
            auto lock = db_lock_.acquire_write();

            bin_bundles_.clear();
        }

        template<typename L>
        Modulus& BinBundle<L>::field_mod()
        {
            return params_.seal_params().plain_modulus();
        }

        /**
        Inserts the given data into the database, using at most thread_count threads
        */
        void LabeledSenderDB::add_data(const std::map<Item, FullWidthLabel> &data, size_t thread_count)
        {
            STOPWATCH(sender_stopwatch, "LabeledSenderDB::add_data");

            // Lock the database for writing
            auto lock = db_lock_.acquire_write();

            // Break the data down into its field element representation. Also compute the items' cuckoo indices.
            vector<pair<AlgItemLabel<felt_t>, size_t> > data_with_indices
                = preprocess_labeled_data(data, params_);

            // Dispatch the insertion
            uint32_t bins_per_bundle = params_.bins_per_bundle();
            dispatch_add_data(data_with_indices, bin_bundles_, bins_per_bundle);
        }

        /**
        Throws an error. This should never ever be called. The only reason this exists is because SenderDB is an
        interface that needs to support both labeled and unlabeled insertion. A LabeledSenderDB does not do unlabeled
        insertion. If you can think of a better way to structure this, keep it to yourself.
        */
        void LabeledSenderDB::add_data(const std::map<Item, FullWidthLabel> &data, size_t thread_count)
        {
            throw logic_error("Cannot do unlabeled insertion on a LabeledSenderDB");
        }

        /**
        Inserts the given data into the database, using at most thread_count threads
        */
        void UnlabeledSenderDB::add_data(const std::map<Item, monostate> &data, size_t thread_count)
        {
            STOPWATCH(sender_stopwatch, "LabeledSenderDB::add_data");

            // Lock the database for writing
            auto lock = db_lock_.acquire_write();

            // Break the data down into its field element representation. Also compute the items' cuckoo indices.
            vector<pair<AlgItemLabel<felt_t>, size_t> > data_with_indices
                = preprocess_unlabeled_data(data, params_);

            // Dispatch the insertion
            uint32_t bins_per_bundle = params_.bins_per_bundle();
            dispatch_add_data(data_with_indices, bin_bundles_, bins_per_bundle);
        }

        /**
        Throws an error. This should never ever be called. The only reason this exists is because SenderDB is an
        interface that needs to support both labeled and unlabeled insertion. An UnlabeledSenderDB does not do labeled
        insertion. If you can think of a better way to structure this, keep it to yourself.
        */
        void UnlabeledSenderDB::add_data(const std::map<Item, FullWidthLabel> &data, size_t thread_count)
        {
            throw logic_error("Cannot do labeled insertion on an UnlabeledSenderDB");
        }

        /**
        Clears the database and inserts the given data, using at most thread_count threads
        */
        void LabeledSenderDB::set_data(const std::map<Item, FullWidthLabel> &data, size_t thread_count) {
            clear_db();
            add_data(data, thread_count);
        }

        /**
        This does not and should not work. See LabeledSenderDB::add_data
        */
        void LabeledSenderDB::set_data(const std::map<Item, monostate> &data, size_t thread_count) {
            throw logic_error("Cannot do unlabeled insertion on a LabeledSenderDB");
        }

        /**
        Clears the database and inserts the given data, using at most thread_count threads
        */
        void UnlabeledSenderDB::set_data(const std::map<Item, monostate> &data, size_t thread_count) {
            clear_db();
            add_data(data, thread_count);
        }

        /**
        This does not and should not work. See UnlabeledSenderDB::add_data
        */
        void UnlabeledSenderDB::set_data(const std::map<Item, FullWidthLabel> &data, size_t thread_count) {
            throw logic_error("Cannot do labeled insertion on an UnlabeledSenderDB");
        }

        /**
        Returns a set of DB cache references corresponding to the bundles at the given bundle index.
        */
        template<typename L>
        set<const BinBundleCache&> SenderDB<L>::get_cache(std::uint32_t bundle_idx)
        {
            if (bundle_idx >= bin_bundles_.size())
            {
                throw out_of_range("bundle_idx is out of range");
            }

            set<const BinBundleCache&> result;
            for (const auto &bundle : bin_bundles_[bundle_idx])
            {
                result.insert(bundle.get_cache());
            }

            return result;
        }

        std::size_t SenderDB::bin_bundle_count() const
        {
            // Lock the database for reading 
            auto lock = db_lock_.acquire_read();

            // Compute the total number of bin bundles
            return accumulate(bin_bundles_.cbegin(), bin_bundles_.cend(), size_t(0),
                [&](auto &a, auto &b) { return a + b.size(); });
        }
    } // namespace sender
} // namespace apsi
