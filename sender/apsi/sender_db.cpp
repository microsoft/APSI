// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <future>
#include <iterator>
#include <memory>
#include <mutex>
#include <sstream>

// APSI
#include "apsi/psi_params.h"
#include "apsi/sender_db.h"
#include "apsi/sender_db_generated.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/db_encoding.h"
#include "apsi/util/label_encryptor.h"
#include "apsi/util/utils.h"

// Kuku
#include "kuku/locfunc.h"

// SEAL
#include "seal/util/common.h"
#include "seal/util/streambuf.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace kuku;

namespace apsi {
    using namespace util;
    using namespace oprf;

    namespace sender {
        namespace {
            /**
            Creates and returns the vector of hash functions similarly to how Kuku 2.x sets them
            internally.
            */
            vector<LocFunc> hash_functions(const PSIParams &params)
            {
                vector<LocFunc> result;
                for (uint32_t i = 0; i < params.table_params().hash_func_count; i++) {
                    result.emplace_back(params.table_params().table_size, make_item(i, 0));
                }

                return result;
            }

            /**
            Computes all cuckoo hash table locations for a given item.
            */
            unordered_set<location_type> all_locations(
                const vector<LocFunc> &hash_funcs, const HashedItem &item)
            {
                unordered_set<location_type> result;
                for (auto &hf : hash_funcs) {
                    result.emplace(hf(item.get_as<kuku::item_type>().front()));
                }

                return result;
            }

            /**
            Compute the label size in multiples of item-size chunks.
            */
            size_t compute_label_size(size_t label_byte_count, const PSIParams &params)
            {
                return (label_byte_count * 8 + params.item_bit_count() - 1) /
                       params.item_bit_count();
            }

            /**
            Unpacks a cuckoo idx into its bin and bundle indices
            */
            pair<size_t, size_t> unpack_cuckoo_idx(size_t cuckoo_idx, size_t bins_per_bundle)
            {
                // Recall that bin indices are relative to the bundle index. That is, the first bin
                // index of a bundle at bundle index 5 is 0. A cuckoo index is similar, except it is
                // not relative to the bundle index. It just keeps counting past bundle boundaries.
                // So in order to get the bin index from the cuckoo index, just compute cuckoo_idx
                // (mod bins_per_bundle).
                size_t bin_idx = cuckoo_idx % bins_per_bundle;

                // Compute which bundle index this cuckoo index belongs to
                size_t bundle_idx = (cuckoo_idx - bin_idx) / bins_per_bundle;

                return { bin_idx, bundle_idx };
            }

            /**
            Converts each given Item-Label pair in between the given iterators into its algebraic
            form, i.e., a sequence of felt-felt pairs. Also computes each Item's cuckoo index.
            */
            vector<pair<AlgItemLabel, size_t>> preprocess_labeled_data(
                const vector<pair<HashedItem, EncryptedLabel>>::const_iterator begin,
                const vector<pair<HashedItem, EncryptedLabel>>::const_iterator end,
                const PSIParams &params)
            {
                STOPWATCH(sender_stopwatch, "preprocess_labeled_data");
                APSI_LOG_DEBUG("Start preprocessing " << distance(begin, end) << " labeled items");

                // Some variables we'll need
                size_t bins_per_item = params.item_params().felts_per_item;
                size_t item_bit_count = params.item_bit_count();

                // Set up Kuku hash functions
                auto hash_funcs = hash_functions(params);

                // Calculate the cuckoo indices for each item. Store every pair of (item-label,
                // cuckoo_idx) in a vector. Later, we're gonna sort this vector by cuckoo_idx and
                // use the result to parallelize the work of inserting the items into BinBundles.
                vector<pair<AlgItemLabel, size_t>> data_with_indices;
                for (auto it = begin; it != end; it++) {
                    const pair<HashedItem, EncryptedLabel> &item_label_pair = *it;

                    // Serialize the data into field elements
                    const HashedItem &item = item_label_pair.first;
                    const EncryptedLabel &label = item_label_pair.second;
                    AlgItemLabel alg_item_label = algebraize_item_label(
                        item, label, item_bit_count, params.seal_params().plain_modulus());

                    // Get the cuckoo table locations for this item and add to data_with_indices
                    for (auto location : all_locations(hash_funcs, item)) {
                        // The current hash value is an index into a table of Items. In reality our
                        // BinBundles are tables of bins, which contain chunks of items. How many
                        // chunks? bins_per_item many chunks
                        size_t bin_idx = location * bins_per_item;

                        // Store the data along with its index
                        data_with_indices.push_back(make_pair(alg_item_label, bin_idx));
                    }
                }

                APSI_LOG_DEBUG(
                    "Finished preprocessing " << distance(begin, end) << " labeled items");

                return data_with_indices;
            }

            /**
            Converts each given Item into its algebraic form, i.e., a sequence of felt-monostate
            pairs. Also computes each Item's cuckoo index.
            */
            vector<pair<AlgItem, size_t>> preprocess_unlabeled_data(
                const vector<HashedItem>::const_iterator begin,
                const vector<HashedItem>::const_iterator end,
                const PSIParams &params)
            {
                STOPWATCH(sender_stopwatch, "preprocess_unlabeled_data");
                APSI_LOG_DEBUG(
                    "Start preprocessing " << distance(begin, end) << " unlabeled items");

                // Some variables we'll need
                size_t bins_per_item = params.item_params().felts_per_item;
                size_t item_bit_count = params.item_bit_count();

                // Set up Kuku hash functions
                auto hash_funcs = hash_functions(params);

                // Calculate the cuckoo indices for each item. Store every pair of (item-label,
                // cuckoo_idx) in a vector. Later, we're gonna sort this vector by cuckoo_idx and
                // use the result to parallelize the work of inserting the items into BinBundles.
                vector<pair<AlgItem, size_t>> data_with_indices;
                for (auto it = begin; it != end; it++) {
                    const HashedItem &item = *it;

                    // Serialize the data into field elements
                    AlgItem alg_item =
                        algebraize_item(item, item_bit_count, params.seal_params().plain_modulus());

                    // Get the cuckoo table locations for this item and add to data_with_indices
                    for (auto location : all_locations(hash_funcs, item)) {
                        // The current hash value is an index into a table of Items. In reality our
                        // BinBundles are tables of bins, which contain chunks of items. How many
                        // chunks? bins_per_item many chunks
                        size_t bin_idx = location * bins_per_item;

                        // Store the data along with its index
                        data_with_indices.emplace_back(make_pair(alg_item, bin_idx));
                    }
                }

                APSI_LOG_DEBUG(
                    "Finished preprocessing " << distance(begin, end) << " unlabeled items");

                return data_with_indices;
            }

            /**
            Converts given Item into its algebraic form, i.e., a sequence of felt-monostate pairs.
            Also computes the Item's cuckoo index.
            */
            vector<pair<AlgItem, size_t>> preprocess_unlabeled_data(
                const HashedItem &item, const PSIParams &params)
            {
                vector<HashedItem> item_singleton{ item };
                return preprocess_unlabeled_data(
                    item_singleton.begin(), item_singleton.end(), params);
            }

            /**
            Inserts the given items and corresponding labels into bin_bundles at their respective
            cuckoo indices. It will only insert the data with bundle index in the half-open range
            range indicated by work_range. If inserting into a BinBundle would make the number of
            items in a bin larger than max_bin_size, this function will create and insert a new
            BinBundle. If overwrite is set, this will overwrite the labels if it finds an
            AlgItemLabel that matches the input perfectly.
            */
            template <typename T>
            void insert_or_assign_worker(
                const vector<pair<T, size_t>> &data_with_indices,
                vector<vector<BinBundle>> &bin_bundles,
                CryptoContext &crypto_context,
                uint32_t bundle_index,
                uint32_t bins_per_bundle,
                size_t label_size,
                size_t max_bin_size,
                size_t ps_low_degree,
                bool overwrite,
                bool compressed)
            {
                STOPWATCH(sender_stopwatch, "insert_or_assign_worker");
                APSI_LOG_DEBUG(
                    "Insert-or-Assign worker for bundle index "
                    << bundle_index << "; mode of operation: "
                    << (overwrite ? "overwriting existing" : "inserting new"));

                // Iteratively insert each item-label pair at the given cuckoo index
                for (auto &data_with_idx : data_with_indices) {
                    const T &data = data_with_idx.first;

                    // Get the bundle index
                    size_t cuckoo_idx = data_with_idx.second;
                    size_t bin_idx, bundle_idx;
                    tie(bin_idx, bundle_idx) = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);

                    // If the bundle_idx isn't in the prescribed range, don't try to insert this
                    // data
                    if (bundle_idx != bundle_index) {
                        // Dealing with this bundle index is not our job
                        continue;
                    }

                    // Get the bundle set at the given bundle index
                    vector<BinBundle> &bundle_set = bin_bundles[bundle_idx];

                    // Try to insert or overwrite these field elements in an existing BinBundle at
                    // this bundle index. Keep track of whether or not we succeed.
                    bool written = false;
                    for (auto bundle_it = bundle_set.rbegin(); bundle_it != bundle_set.rend();
                         bundle_it++) {
                        // If we're supposed to overwrite, try to overwrite. One of these BinBundles
                        // has to have the data we're trying to overwrite.
                        if (overwrite) {
                            // If we successfully overwrote, we're done with this bundle
                            written = bundle_it->try_multi_overwrite(data, bin_idx);
                            if (written) {
                                break;
                            }
                        }

                        // Do a dry-run insertion and see if the new largest bin size in the range
                        // exceeds the limit
                        int32_t new_largest_bin_size =
                            bundle_it->multi_insert_dry_run(data, bin_idx);

                        // Check if inserting would violate the max bin size constraint
                        if (new_largest_bin_size > 0 &&
                            safe_cast<size_t>(new_largest_bin_size) < max_bin_size) {
                            // All good
                            bundle_it->multi_insert_for_real(data, bin_idx);
                            written = true;
                            break;
                        }
                    }

                    // We tried to overwrite an item that doesn't exist. This should never happen
                    if (overwrite && !written) {
                        APSI_LOG_ERROR(
                            "Insert-or-Assign worker: "
                            "failed to overwrite item at bundle index "
                            << bundle_idx
                            << " "
                               "because the item was not found");
                        throw logic_error("tried to overwrite non-existent item");
                    }

                    // If we had conflicts everywhere when trying to insert, then we need to make a
                    // new BinBundle and insert the data there
                    if (!written) {
                        // Make a fresh BinBundle and insert
                        BinBundle new_bin_bundle(
                            crypto_context,
                            label_size,
                            max_bin_size,
                            ps_low_degree,
                            bins_per_bundle,
                            compressed,
                            false);
                        int res = new_bin_bundle.multi_insert_for_real(data, bin_idx);

                        // If even that failed, I don't know what could've happened
                        if (res < 0) {
                            APSI_LOG_ERROR(
                                "Insert-or-Assign worker: "
                                "failed to insert item into a new BinBundle at bundle index "
                                << bundle_idx);
                            throw logic_error("failed to insert item into a new BinBundle");
                        }

                        // Push a new BinBundle to the set of BinBundles at this bundle index
                        bundle_set.push_back(move(new_bin_bundle));
                    }
                }

                APSI_LOG_DEBUG(
                    "Insert-or-Assign worker: finished processing bundle index " << bundle_index);
            }

            /**
            Takes algebraized data to be inserted, splits it up, and distributes it so that
            thread_count many threads can all insert in parallel. If overwrite is set, this will
            overwrite the labels if it finds an AlgItemLabel that matches the input perfectly.
            */
            template <typename T>
            void dispatch_insert_or_assign(
                vector<pair<T, size_t>> &data_with_indices,
                vector<vector<BinBundle>> &bin_bundles,
                CryptoContext &crypto_context,
                uint32_t bins_per_bundle,
                size_t label_size,
                uint32_t max_bin_size,
                uint32_t ps_low_degree,
                bool overwrite,
                bool compressed)
            {
                ThreadPoolMgr tpm;

                // Collect the bundle indices and partition them into thread_count many partitions.
                // By some uniformity assumption, the number of things to insert per partition
                // should be roughly the same. Note that the contents of bundle_indices is always
                // sorted (increasing order).
                set<size_t> bundle_indices_set;
                for (auto &data_with_idx : data_with_indices) {
                    size_t cuckoo_idx = data_with_idx.second;
                    size_t bin_idx, bundle_idx;
                    tie(bin_idx, bundle_idx) = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);
                    bundle_indices_set.insert(bundle_idx);
                }

                // Copy the set of indices into a vector and sort so each thread processes a range
                // of indices
                vector<size_t> bundle_indices;
                bundle_indices.reserve(bundle_indices_set.size());
                copy(
                    bundle_indices_set.begin(),
                    bundle_indices_set.end(),
                    back_inserter(bundle_indices));
                sort(bundle_indices.begin(), bundle_indices.end());

                // Run the threads on the partitions
                vector<future<void>> futures(bundle_indices.size());
                APSI_LOG_INFO(
                    "Launching " << bundle_indices.size() << " insert-or-assign worker tasks");
                size_t future_idx = 0;
                for (auto &bundle_idx : bundle_indices) {
                    futures[future_idx++] = tpm.thread_pool().enqueue([&, bundle_idx]() {
                        insert_or_assign_worker(
                            data_with_indices,
                            bin_bundles,
                            crypto_context,
                            static_cast<uint32_t>(bundle_idx),
                            bins_per_bundle,
                            label_size,
                            max_bin_size,
                            ps_low_degree,
                            overwrite,
                            compressed);
                    });
                }

                // Wait for the tasks to finish
                for (auto &f : futures) {
                    f.get();
                }

                APSI_LOG_INFO("Finished insert-or-assign worker tasks");
            }

            /**
            Removes the given items and corresponding labels from bin_bundles at their respective
            cuckoo indices.
            */
            void remove_worker(
                const vector<pair<AlgItem, size_t>> &data_with_indices,
                vector<vector<BinBundle>> &bin_bundles,
                uint32_t bundle_index,
                uint32_t bins_per_bundle)
            {
                STOPWATCH(sender_stopwatch, "remove_worker");
                APSI_LOG_INFO("Remove worker [" << bundle_index << "]");

                // Iteratively remove each item-label pair at the given cuckoo index
                for (auto &data_with_idx : data_with_indices) {
                    // Get the bundle index
                    size_t cuckoo_idx = data_with_idx.second;
                    size_t bin_idx, bundle_idx;
                    tie(bin_idx, bundle_idx) = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);

                    // If the bundle_idx isn't in the prescribed range, don't try to remove this
                    // data
                    if (bundle_idx != bundle_index) {
                        // Dealing with this bundle index is not our job
                        continue;
                    }

                    // Get the bundle set at the given bundle index
                    vector<BinBundle> &bundle_set = bin_bundles[bundle_idx];

                    // Try to remove these field elements from an existing BinBundle at this bundle
                    // index. Keep track of whether or not we succeed.
                    bool removed = false;
                    for (BinBundle &bundle : bundle_set) {
                        // If we successfully removed, we're done with this bundle
                        removed = bundle.try_multi_remove(data_with_idx.first, bin_idx);
                        if (removed) {
                            break;
                        }
                    }

                    // We may have produced some empty BinBundles so just remove them all
                    auto rem_it = remove_if(bundle_set.begin(), bundle_set.end(), [](auto &bundle) {
                        return bundle.empty();
                    });
                    bundle_set.erase(rem_it, bundle_set.end());

                    // We tried to remove an item that doesn't exist. This should never happen
                    if (!removed) {
                        APSI_LOG_ERROR(
                            "Remove worker: "
                            "failed to remove item at bundle index "
                            << bundle_idx
                            << " "
                               "because the item was not found");
                        throw logic_error("failed to remove item");
                    }
                }

                APSI_LOG_INFO("Remove worker: finished processing bundle index " << bundle_index);
            }

            /**
            Takes algebraized data to be removed, splits it up, and distributes it so that
            thread_count many threads can all remove in parallel.
            */
            void dispatch_remove(
                const vector<pair<AlgItem, size_t>> &data_with_indices,
                vector<vector<BinBundle>> &bin_bundles,
                uint32_t bins_per_bundle)
            {
                ThreadPoolMgr tpm;

                // Collect the bundle indices and partition them into thread_count many partitions.
                // By some uniformity assumption, the number of things to remove per partition
                // should be roughly the same. Note that the contents of bundle_indices is always
                // sorted (increasing order).
                set<size_t> bundle_indices_set;
                for (auto &data_with_idx : data_with_indices) {
                    size_t cuckoo_idx = data_with_idx.second;
                    size_t bin_idx, bundle_idx;
                    tie(bin_idx, bundle_idx) = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);
                    bundle_indices_set.insert(bundle_idx);
                }

                // Copy the set of indices into a vector and sort so each thread processes a range
                // of indices
                vector<size_t> bundle_indices;
                bundle_indices.reserve(bundle_indices_set.size());
                copy(
                    bundle_indices_set.begin(),
                    bundle_indices_set.end(),
                    back_inserter(bundle_indices));
                sort(bundle_indices.begin(), bundle_indices.end());

                // Run the threads on the partitions
                vector<future<void>> futures(bundle_indices.size());
                APSI_LOG_INFO("Launching " << bundle_indices.size() << " remove worker tasks");
                size_t future_idx = 0;
                for (auto &bundle_idx : bundle_indices) {
                    futures[future_idx++] = tpm.thread_pool().enqueue([&]() {
                        remove_worker(
                            data_with_indices,
                            bin_bundles,
                            static_cast<uint32_t>(bundle_idx),
                            bins_per_bundle);
                    });
                }

                // Wait for the tasks to finish
                for (auto &f : futures) {
                    f.get();
                }
            }

            /**
            Returns a set of DB cache references corresponding to the bundles in the given set
            */
            vector<reference_wrapper<const BinBundleCache>> collect_caches(
                vector<BinBundle> &bin_bundles)
            {
                vector<reference_wrapper<const BinBundleCache>> result;
                for (const auto &bundle : bin_bundles) {
                    result.emplace_back(cref(bundle.get_cache()));
                }

                return result;
            }
        } // namespace

        SenderDB::SenderDB(
            PSIParams params, size_t label_byte_count, size_t nonce_byte_count, bool compressed)
            : params_(params), crypto_context_(params_), label_byte_count_(label_byte_count),
              nonce_byte_count_(label_byte_count_ ? nonce_byte_count : 0), item_count_(0),
              compressed_(compressed)
        {
            // The labels cannot be more than 1 KB.
            if (label_byte_count_ > 1024) {
                APSI_LOG_ERROR(
                    "Requested label byte count " << label_byte_count_
                                                  << " exceeds the maximum (1024)");
                throw invalid_argument("label_byte_count is too large");
            }

            if (nonce_byte_count_ > max_nonce_byte_count) {
                APSI_LOG_ERROR(
                    "Request nonce byte count " << nonce_byte_count_ << " exceeds the maximum ("
                                                << max_nonce_byte_count << ")");
                throw invalid_argument("nonce_byte_count is too large");
            }

            // If the nonce byte count is less than max_nonce_byte_count, print a warning; this is a
            // labeled SenderDB but may not be safe to use for arbitrary label changes.
            if (label_byte_count_ && nonce_byte_count_ < max_nonce_byte_count) {
                APSI_LOG_WARNING(
                    "You have instantiated a labeled SenderDB instance with a nonce byte count "
                    << nonce_byte_count_ << ", which is less than the safe default value "
                    << max_nonce_byte_count
                    << ". Updating labels for existing items in the SenderDB or removing and "
                       "reinserting items with "
                       "different labels may leak information about the labels.");
            }

            // Set the evaluator. This will be used for BatchedPlaintextPolyn::eval.
            crypto_context_.set_evaluator();

            // Reset the SenderDB data structures
            clear();
        }

        SenderDB::SenderDB(
            PSIParams params,
            OPRFKey oprf_key,
            size_t label_byte_count,
            size_t nonce_byte_count,
            bool compressed)
            : SenderDB(params, label_byte_count, nonce_byte_count, compressed)
        {
            // Initialize oprf key with the one given to this constructor
            oprf_key_ = move(oprf_key);
        }

        SenderDB::SenderDB(SenderDB &&source)
            : params_(source.params_), crypto_context_(source.crypto_context_),
              label_byte_count_(source.label_byte_count_),
              nonce_byte_count_(source.nonce_byte_count_), item_count_(source.item_count_),
              compressed_(source.compressed_), stripped_(source.stripped_)
        {
            // Lock the source before moving stuff over
            auto lock = source.get_writer_lock();

            hashed_items_ = move(source.hashed_items_);
            bin_bundles_ = move(source.bin_bundles_);
            oprf_key_ = move(source.oprf_key_);
            source.oprf_key_ = OPRFKey();

            // Reset the source data structures
            source.clear_internal();
        }

        SenderDB &SenderDB::operator=(SenderDB &&source)
        {
            // Do nothing if moving to self
            if (&source == this) {
                return *this;
            }

            // Lock the current SenderDB
            auto this_lock = get_writer_lock();

            params_ = source.params_;
            crypto_context_ = source.crypto_context_;
            label_byte_count_ = source.label_byte_count_;
            nonce_byte_count_ = source.nonce_byte_count_;
            item_count_ = source.item_count_;
            compressed_ = source.compressed_;
            stripped_ = source.stripped_;

            // Lock the source before moving stuff over
            auto source_lock = source.get_writer_lock();

            hashed_items_ = move(source.hashed_items_);
            bin_bundles_ = move(source.bin_bundles_);
            oprf_key_ = move(source.oprf_key_);
            source.oprf_key_ = OPRFKey();

            // Reset the source data structures
            source.clear_internal();

            return *this;
        }

        size_t SenderDB::get_bin_bundle_count(uint32_t bundle_idx) const
        {
            // Lock the database for reading
            auto lock = get_reader_lock();

            return bin_bundles_.at(safe_cast<size_t>(bundle_idx)).size();
        }

        size_t SenderDB::get_bin_bundle_count() const
        {
            // Lock the database for reading
            auto lock = get_reader_lock();

            // Compute the total number of BinBundles
            return accumulate(
                bin_bundles_.cbegin(), bin_bundles_.cend(), size_t(0), [&](auto &a, auto &b) {
                    return a + b.size();
                });
        }

        double SenderDB::get_packing_rate() const
        {
            // Lock the database for reading
            auto lock = get_reader_lock();

            uint64_t item_count = mul_safe(
                static_cast<uint64_t>(get_item_count()),
                static_cast<uint64_t>(params_.table_params().hash_func_count));
            uint64_t max_item_count = mul_safe(
                static_cast<uint64_t>(get_bin_bundle_count()),
                static_cast<uint64_t>(params_.items_per_bundle()),
                static_cast<uint64_t>(params_.table_params().max_items_per_bin));

            return max_item_count
                       ? static_cast<double>(item_count) / static_cast<double>(max_item_count)
                       : 0.0;
        }

        void SenderDB::clear_internal()
        {
            // Assume the SenderDB is already locked for writing

            // Clear the set of inserted items
            hashed_items_.clear();
            item_count_ = 0;

            // Clear the BinBundles
            bin_bundles_.clear();
            bin_bundles_.resize(params_.bundle_idx_count());

            // Reset the stripped_ flag
            stripped_ = false;
        }

        void SenderDB::clear()
        {
            if (hashed_items_.size()) {
                APSI_LOG_INFO("Removing " << hashed_items_.size() << " items pairs from SenderDB");
            }

            // Lock the database for writing
            auto lock = get_writer_lock();

            clear_internal();
        }

        void SenderDB::generate_caches()
        {
            STOPWATCH(sender_stopwatch, "SenderDB::generate_caches");
            APSI_LOG_INFO("Start generating bin bundle caches");

            for (auto &bundle_idx : bin_bundles_) {
                for (auto &bb : bundle_idx) {
                    bb.regen_cache();
                }
            }

            APSI_LOG_INFO("Finished generating bin bundle caches");
        }

        vector<reference_wrapper<const BinBundleCache>> SenderDB::get_cache_at(uint32_t bundle_idx)
        {
            return collect_caches(bin_bundles_.at(safe_cast<size_t>(bundle_idx)));
        }

        OPRFKey SenderDB::strip()
        {
            // Lock the database for writing
            auto lock = get_writer_lock();

            stripped_ = true;

            OPRFKey oprf_key_copy = move(oprf_key_);
            oprf_key_.clear();
            hashed_items_.clear();

            ThreadPoolMgr tpm;

            vector<future<void>> futures;
            for (auto &bundle_idx : bin_bundles_) {
                for (auto &bb : bundle_idx) {
                    futures.push_back(tpm.thread_pool().enqueue([&bb]() { bb.strip(); }));
                }
            }

            // Wait for the tasks to finish
            for (auto &f : futures) {
                f.get();
            }

            APSI_LOG_INFO("SenderDB has been stripped");

            return oprf_key_copy;
        }

        OPRFKey SenderDB::get_oprf_key() const
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot return the OPRF key from a stripped SenderDB");
                throw logic_error("failed to return OPRF key");
            }
            return oprf_key_;
        }

        void SenderDB::insert_or_assign(const vector<pair<Item, Label>> &data)
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot insert data to a stripped SenderDB");
                throw logic_error("failed to insert data");
            }
            if (!is_labeled()) {
                APSI_LOG_ERROR(
                    "Attempted to insert labeled data but this is an unlabeled SenderDB");
                throw logic_error("failed to insert data");
            }

            STOPWATCH(sender_stopwatch, "SenderDB::insert_or_assign (labeled)");
            APSI_LOG_INFO("Start inserting " << data.size() << " items in SenderDB");

            // First compute the hashes for the input data
            auto hashed_data =
                OPRFSender::ComputeHashes(data, oprf_key_, label_byte_count_, nonce_byte_count_);

            // Lock the database for writing
            auto lock = get_writer_lock();

            // We need to know which items are new and which are old, since we have to tell
            // dispatch_insert_or_assign when to have an overwrite-on-collision versus
            // add-binbundle-on-collision policy.
            auto new_data_end =
                remove_if(hashed_data.begin(), hashed_data.end(), [&](const auto &item_label_pair) {
                    bool found = hashed_items_.find(item_label_pair.first) != hashed_items_.end();
                    if (!found) {
                        // Add to hashed_items_ already at this point!
                        hashed_items_.insert(item_label_pair.first);
                        item_count_++;
                    }

                    // Remove those that were found
                    return found;
                });

            // Dispatch the insertion, first for the new data, then for the data we're gonna
            // overwrite
            uint32_t bins_per_bundle = params_.bins_per_bundle();
            uint32_t max_bin_size = params_.table_params().max_items_per_bin;
            uint32_t ps_low_degree = params_.query_params().ps_low_degree;

            // Compute the label size; this ceil(effective_label_bit_count / item_bit_count)
            size_t label_size = compute_label_size(nonce_byte_count_ + label_byte_count_, params_);

            auto new_item_count = distance(hashed_data.begin(), new_data_end);
            auto existing_item_count = distance(new_data_end, hashed_data.end());

            if (existing_item_count) {
                APSI_LOG_INFO(
                    "Found " << existing_item_count << " existing items to replace in SenderDB");

                // Break the data into field element representation. Also compute the items' cuckoo
                // indices.
                vector<pair<AlgItemLabel, size_t>> data_with_indices =
                    preprocess_labeled_data(new_data_end, hashed_data.end(), params_);

                dispatch_insert_or_assign(
                    data_with_indices,
                    bin_bundles_,
                    crypto_context_,
                    bins_per_bundle,
                    label_size,
                    max_bin_size,
                    ps_low_degree,
                    true, /* overwrite items */
                    compressed_);

                // Release memory that is no longer needed
                hashed_data.erase(new_data_end, hashed_data.end());
            }

            if (new_item_count) {
                APSI_LOG_INFO("Found " << new_item_count << " new items to insert in SenderDB");

                // Process and add the new data. Break the data into field element representation.
                // Also compute the items' cuckoo indices.
                vector<pair<AlgItemLabel, size_t>> data_with_indices =
                    preprocess_labeled_data(hashed_data.begin(), hashed_data.end(), params_);

                dispatch_insert_or_assign(
                    data_with_indices,
                    bin_bundles_,
                    crypto_context_,
                    bins_per_bundle,
                    label_size,
                    max_bin_size,
                    ps_low_degree,
                    false, /* don't overwrite items */
                    compressed_);
            }

            // Generate the BinBundle caches
            generate_caches();

            APSI_LOG_INFO("Finished inserting " << data.size() << " items in SenderDB");
        }

        void SenderDB::insert_or_assign(const vector<Item> &data)
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot insert data to a stripped SenderDB");
                throw logic_error("failed to insert data");
            }
            if (is_labeled()) {
                APSI_LOG_ERROR("Attempted to insert unlabeled data but this is a labeled SenderDB");
                throw logic_error("failed to insert data");
            }

            STOPWATCH(sender_stopwatch, "SenderDB::insert_or_assign (unlabeled)");
            APSI_LOG_INFO("Start inserting " << data.size() << " items in SenderDB");

            // First compute the hashes for the input data
            auto hashed_data = OPRFSender::ComputeHashes(data, oprf_key_);

            // Lock the database for writing
            auto lock = get_writer_lock();

            // We are not going to insert items that already appear in the database.
            auto new_data_end =
                remove_if(hashed_data.begin(), hashed_data.end(), [&](const auto &item) {
                    bool found = hashed_items_.find(item) != hashed_items_.end();
                    if (!found) {
                        // Add to hashed_items_ already at this point!
                        hashed_items_.insert(item);
                        item_count_++;
                    }

                    // Remove those that were found
                    return found;
                });

            // Erase the previously existing items from hashed_data; in unlabeled case there is
            // nothing to do
            hashed_data.erase(new_data_end, hashed_data.end());

            APSI_LOG_INFO("Found " << hashed_data.size() << " new items to insert in SenderDB");

            // Break the new data down into its field element representation. Also compute the
            // items' cuckoo indices.
            vector<pair<AlgItem, size_t>> data_with_indices =
                preprocess_unlabeled_data(hashed_data.begin(), hashed_data.end(), params_);

            // Dispatch the insertion
            uint32_t bins_per_bundle = params_.bins_per_bundle();
            uint32_t max_bin_size = params_.table_params().max_items_per_bin;
            uint32_t ps_low_degree = params_.query_params().ps_low_degree;

            dispatch_insert_or_assign(
                data_with_indices,
                bin_bundles_,
                crypto_context_,
                bins_per_bundle,
                0, /* label size */
                max_bin_size,
                ps_low_degree,
                false, /* don't overwrite items */
                compressed_);

            // Generate the BinBundle caches
            generate_caches();

            APSI_LOG_INFO("Finished inserting " << data.size() << " items in SenderDB");
        }

        void SenderDB::remove(const vector<Item> &data)
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot remove data from a stripped SenderDB");
                throw logic_error("failed to remove data");
            }

            STOPWATCH(sender_stopwatch, "SenderDB::remove");
            APSI_LOG_INFO("Start removing " << data.size() << " items from SenderDB");

            // First compute the hashes for the input data
            auto hashed_data = OPRFSender::ComputeHashes(data, oprf_key_);

            // Lock the database for writing
            auto lock = get_writer_lock();

            // Remove items that do not exist in the database.
            auto existing_data_end =
                remove_if(hashed_data.begin(), hashed_data.end(), [&](const auto &item) {
                    bool found = hashed_items_.find(item) != hashed_items_.end();
                    if (found) {
                        // Remove from hashed_items_ already at this point!
                        hashed_items_.erase(item);
                        item_count_--;
                    }

                    // Remove those that were not found
                    return !found;
                });

            // This distance is always non-negative
            size_t existing_item_count =
                static_cast<size_t>(distance(existing_data_end, hashed_data.end()));
            if (existing_item_count) {
                APSI_LOG_WARNING(
                    "Ignoring " << existing_item_count
                                << " items that are not present in the SenderDB");
            }

            // Break the data down into its field element representation. Also compute the items'
            // cuckoo indices.
            vector<pair<AlgItem, size_t>> data_with_indices =
                preprocess_unlabeled_data(hashed_data.begin(), hashed_data.end(), params_);

            // Dispatch the removal
            uint32_t bins_per_bundle = params_.bins_per_bundle();
            dispatch_remove(data_with_indices, bin_bundles_, bins_per_bundle);

            // Generate the BinBundle caches
            generate_caches();

            APSI_LOG_INFO("Finished removing " << data.size() << " items from SenderDB");
        }

        bool SenderDB::has_item(const Item &item) const
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot retrieve the presence of an item from a stripped SenderDB");
                throw logic_error("failed to retrieve the presence of item");
            }

            // First compute the hash for the input item
            auto hashed_item = OPRFSender::ComputeHashes({ &item, 1 }, oprf_key_)[0];

            // Lock the database for reading
            auto lock = get_reader_lock();

            return hashed_items_.find(hashed_item) != hashed_items_.end();
        }

        Label SenderDB::get_label(const Item &item) const
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot retrieve a label from a stripped SenderDB");
                throw logic_error("failed to retrieve label");
            }
            if (!is_labeled()) {
                APSI_LOG_ERROR("Attempted to retrieve a label but this is an unlabeled SenderDB");
                throw logic_error("failed to retrieve label");
            }

            // First compute the hash for the input item
            HashedItem hashed_item;
            LabelKey key;
            tie(hashed_item, key) = OPRFSender::GetItemHash(item, oprf_key_);

            // Lock the database for reading
            auto lock = get_reader_lock();

            // Check if this item is in the DB. If not, throw an exception
            if (hashed_items_.find(hashed_item) == hashed_items_.end()) {
                APSI_LOG_ERROR("Cannot retrieve label for an item that is not in the SenderDB");
                throw invalid_argument("failed to retrieve label");
            }

            uint32_t bins_per_bundle = params_.bins_per_bundle();

            // Preprocess a single element. This algebraizes the item and gives back its field
            // element representation as well as its cuckoo hash. We only read one of the locations
            // because the labels are the same in each location.
            AlgItem alg_item;
            size_t cuckoo_idx;
            tie(alg_item, cuckoo_idx) = preprocess_unlabeled_data(hashed_item, params_)[0];

            // Now figure out where to look to get the label
            size_t bin_idx, bundle_idx;
            tie(bin_idx, bundle_idx) = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);

            // Retrieve the algebraic labels from one of the BinBundles at this index
            const vector<BinBundle> &bundle_set = bin_bundles_[bundle_idx];
            vector<felt_t> alg_label;
            bool got_labels = false;
            for (const BinBundle &bundle : bundle_set) {
                // Try to retrieve the contiguous labels from this BinBundle
                if (bundle.try_get_multi_label(alg_item, bin_idx, alg_label)) {
                    got_labels = true;
                    break;
                }
            }

            // It shouldn't be possible to have items in your set but be unable to retrieve the
            // associated label. Throw an exception because something is terribly wrong.
            if (!got_labels) {
                APSI_LOG_ERROR(
                    "Failed to retrieve label for an item that was supposed to be in the SenderDB");
                throw logic_error("failed to retrieve label");
            }

            // All good. Now just reconstruct the big label from its split-up parts
            EncryptedLabel encrypted_label = dealgebraize_label(
                alg_label,
                alg_label.size() * static_cast<size_t>(params_.item_bit_count_per_felt()),
                params_.seal_params().plain_modulus());

            // Resize down to the effective byte count
            encrypted_label.resize(nonce_byte_count_ + label_byte_count_);

            // Decrypt the label
            return decrypt_label(encrypted_label, key, nonce_byte_count_);
        }

        size_t SenderDB::save(ostream &out) const
        {
            // Lock the database for reading
            auto lock = get_reader_lock();

            STOPWATCH(sender_stopwatch, "SenderDB::save");
            APSI_LOG_DEBUG("Start saving SenderDB");

            // First save the PSIParam
            stringstream ss;
            params_.save(ss);
            string params_str = ss.str();

            flatbuffers::FlatBufferBuilder fbs_builder(1024);

            auto params = fbs_builder.CreateVector(
                reinterpret_cast<const uint8_t *>(&params_str[0]), params_str.size());
            fbs::SenderDBInfo info(
                safe_cast<uint32_t>(label_byte_count_),
                safe_cast<uint32_t>(nonce_byte_count_),
                safe_cast<uint32_t>(item_count_),
                compressed_,
                stripped_);
            auto oprf_key_span = oprf_key_.key_span();
            auto oprf_key = fbs_builder.CreateVector(oprf_key_span.data(), oprf_key_span.size());
            auto hashed_items = fbs_builder.CreateVectorOfStructs([&]() {
                // The HashedItems vector is populated with an immediately-invoked lambda
                vector<fbs::HashedItem> ret;
                ret.reserve(get_hashed_items().size());
                for (const auto &it : get_hashed_items()) {
                    // Then create the vector of bytes for this hashed item
                    auto item_data = it.get_as<uint64_t>();
                    ret.emplace_back(item_data[0], item_data[1]);
                }
                return ret;
            }());

            auto bin_bundle_count = get_bin_bundle_count();

            fbs::SenderDBBuilder sender_db_builder(fbs_builder);
            sender_db_builder.add_params(params);
            sender_db_builder.add_info(&info);
            sender_db_builder.add_oprf_key(oprf_key);
            sender_db_builder.add_hashed_items(hashed_items);
            sender_db_builder.add_bin_bundle_count(safe_cast<uint32_t>(bin_bundle_count));
            auto sdb = sender_db_builder.Finish();
            fbs_builder.FinishSizePrefixed(sdb);

            out.write(
                reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));
            size_t total_size = fbs_builder.GetSize();

            // Finally write the BinBundles
            size_t bin_bundle_data_size = 0;
            for (size_t bundle_idx = 0; bundle_idx < bin_bundles_.size(); bundle_idx++) {
                for (auto &bb : bin_bundles_[bundle_idx]) {
                    auto size = bb.save(out, static_cast<uint32_t>(bundle_idx));
                    APSI_LOG_DEBUG(
                        "Saved BinBundle at bundle index " << bundle_idx << " (" << size
                                                           << " bytes)");
                    bin_bundle_data_size += size;
                }
            }

            total_size += bin_bundle_data_size;
            APSI_LOG_DEBUG(
                "Saved SenderDB with " << get_item_count() << " items (" << total_size
                                       << " bytes)");

            APSI_LOG_DEBUG("Finished saving SenderDB");

            return total_size;
        }

        pair<SenderDB, size_t> SenderDB::Load(istream &in)
        {
            STOPWATCH(sender_stopwatch, "SenderDB::Load");
            APSI_LOG_DEBUG("Start loading SenderDB");

            vector<unsigned char> in_data(apsi::util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(
                reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderDBBuffer(verifier);
            if (!safe) {
                APSI_LOG_ERROR("Failed to load SenderDB: the buffer is invalid");
                throw runtime_error("failed to load SenderDB");
            }

            auto sdb = fbs::GetSizePrefixedSenderDB(in_data.data());

            // Load the PSIParams; this will automatically check version compatibility
            unique_ptr<PSIParams> params;
            try {
                ArrayGetBuffer agbuf(
                    reinterpret_cast<const char *>(sdb->params()->data()),
                    static_cast<streamsize>(sdb->params()->size()));
                istream params_stream(&agbuf);
                params = make_unique<PSIParams>(PSIParams::Load(params_stream).first);
            } catch (const runtime_error &ex) {
                APSI_LOG_ERROR("APSI threw an exception creating PSIParams: " << ex.what());
                throw runtime_error("failed to load SenderDB");
            }

            // Load the info so we know what kind of SenderDB to create
            size_t item_count = static_cast<size_t>(sdb->info()->item_count());
            size_t label_byte_count = static_cast<size_t>(sdb->info()->label_byte_count());
            size_t nonce_byte_count = static_cast<size_t>(sdb->info()->nonce_byte_count());

            bool compressed = sdb->info()->compressed();
            bool stripped = sdb->info()->stripped();

            APSI_LOG_DEBUG(
                "Loaded SenderDB properties: "
                "item_count: "
                << item_count
                << "; "
                   "label_byte_count: "
                << label_byte_count
                << "; "
                   "nonce_byte_count: "
                << nonce_byte_count
                << "; "
                   "compressed: "
                << boolalpha << compressed
                << "; "
                   "stripped: "
                << boolalpha << stripped);

            // Create the correct kind of SenderDB
            unique_ptr<SenderDB> sender_db;
            try {
                sender_db =
                    make_unique<SenderDB>(*params, label_byte_count, nonce_byte_count, compressed);
                sender_db->stripped_ = stripped;
                sender_db->item_count_ = item_count;
            } catch (const invalid_argument &ex) {
                APSI_LOG_ERROR("APSI threw an exception creating SenderDB: " << ex.what());
                throw runtime_error("failed to load SenderDB");
            }

            // Check that the OPRF key size is correct
            size_t loaded_oprf_key_size = sdb->oprf_key()->size();
            if (loaded_oprf_key_size != oprf_key_size) {
                APSI_LOG_ERROR(
                    "The loaded OPRF key has invalid size ("
                    << loaded_oprf_key_size << " bytes; expected " << oprf_key_size << " bytes)");
                throw runtime_error("failed to load SenderDB");
            }

            // Copy over the OPRF key
            sender_db->oprf_key_.load(oprf_key_span_const_type(
                reinterpret_cast<const unsigned char *>(sdb->oprf_key()->data()), oprf_key_size));

            // Load the hashed items if this SenderDB is not stripped
            if (!stripped) {
                const auto &hashed_items = *sdb->hashed_items();
                sender_db->hashed_items_.reserve(hashed_items.size());
                for (const auto &it : hashed_items) {
                    sender_db->hashed_items_.insert({ it->low_word(), it->high_word() });
                }

                // Check that item_count matches the number of hashed items
                if (item_count != hashed_items.size()) {
                    APSI_LOG_ERROR(
                        "The item count indicated in the loaded SenderDB ("
                        << item_count << ") does not match the size of the loaded data ("
                        << hashed_items.size() << ")");
                    throw runtime_error("failed to load SenderDB");
                }
            }

            uint32_t bin_bundle_count = sdb->bin_bundle_count();
            size_t bin_bundle_data_size = 0;
            uint32_t max_bin_size = params->table_params().max_items_per_bin;
            uint32_t ps_low_degree = params->query_params().ps_low_degree;
            uint32_t bins_per_bundle = params->bins_per_bundle();
            size_t label_size = compute_label_size(nonce_byte_count + label_byte_count, *params);

            // Load all BinBundle data
            vector<vector<unsigned char>> bin_bundle_data;
            bin_bundle_data.reserve(bin_bundle_count);
            while (bin_bundle_count--) {
                bin_bundle_data.push_back(read_from_stream(in));
            }

            // Use multiple threads to recreate the BinBundles
            ThreadPoolMgr tpm;

            vector<mutex> bundle_idx_mtxs(sender_db->bin_bundles_.size());
            mutex bin_bundle_data_size_mtx;
            vector<future<void>> futures;
            for (size_t i = 0; i < bin_bundle_data.size(); i++) {
                futures.push_back(tpm.thread_pool().enqueue([&, i]() {
                    BinBundle bb(
                        sender_db->crypto_context_,
                        label_size,
                        max_bin_size,
                        ps_low_degree,
                        bins_per_bundle,
                        compressed,
                        stripped);
                    auto bb_data = bb.load(bin_bundle_data[i]);

                    // Clear the data buffer since we have now loaded the BinBundle
                    bin_bundle_data[i].clear();

                    // Check that the loaded bundle index is not out of range
                    if (bb_data.first >= sender_db->bin_bundles_.size()) {
                        APSI_LOG_ERROR(
                            "The bundle index of the loaded BinBundle ("
                            << bb_data.first << ") exceeds the maximum ("
                            << params->bundle_idx_count() - 1 << ")");
                        throw runtime_error("failed to load SenderDB");
                    }

                    // Add the loaded BinBundle to the correct location in bin_bundles_
                    bundle_idx_mtxs[bb_data.first].lock();
                    sender_db->bin_bundles_[bb_data.first].push_back(move(bb));
                    bundle_idx_mtxs[bb_data.first].unlock();

                    APSI_LOG_DEBUG(
                        "Loaded BinBundle at bundle index " << bb_data.first << " ("
                                                            << bb_data.second << " bytes)");

                    lock_guard<mutex> bin_bundle_data_size_lock(bin_bundle_data_size_mtx);
                    bin_bundle_data_size += bb_data.second;
                }));
            }

            // Wait for the tasks to finish
            for (auto &f : futures) {
                f.get();
            }

            size_t total_size = in_data.size() + bin_bundle_data_size;
            APSI_LOG_DEBUG(
                "Loaded SenderDB with " << sender_db->get_item_count() << " items (" << total_size
                                        << " bytes)");

            // Make sure the BinBundle caches are valid
            sender_db->generate_caches();

            APSI_LOG_DEBUG("Finished loading SenderDB");

            return { move(*sender_db), total_size };
        }
    } // namespace sender
} // namespace apsi
