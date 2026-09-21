// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_set>
#include <utility>
#include <vector>

// GSL
#include "gsl/span"

// APSI
#include "apsi/bin_bundle.h"
#include "apsi/crypto_context.h"
#include "apsi/item.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/psi_params.h"

// SEAL
#include "seal/plaintext.h"

namespace apsi::sender {
    /**
    A SenderDB maintains an in-memory representation of the sender's set of items and labels (in
    labeled mode). This data is not simply copied into the SenderDB data structures, but also
    preprocessed heavily to allow for faster online computation time. Since inserting a large
    number of new items into a SenderDB can take time, it is not recommended to recreate the
    SenderDB when the database changes a little bit. Instead, the class supports fast update and
    deletion operations that should be preferred: SenderDB::insert_or_assign and
    SenderDB::remove.

    The SenderDB constructor allows the label byte count to be specified; unlabeled mode is
    activated by setting the label byte count to zero. It is possible to optionally specify the
    size of the nonce used in encrypting the labels, but this is best left to its default value
    unless the user is absolutely sure of what they are doing.

    The SenderDB requires substantially more memory than the raw data would. Part of that memory
    can automatically be compressed when it is not in use; this feature is enabled by default,
    and can be disabled when constructing the SenderDB. The downside of in-memory compression is
    a performance reduction from decompressing parts of the data when they are used, and
    recompressing them if they are updated.

    An update and a query cannot overlap. SenderDB::insert_or_assign and SenderDB::remove hold a
    writer lock for the whole of their work, including the OPRF hashing they begin with, while
    answering a query holds a reader lock for as long as the answer takes. An embedder that
    updates a SenderDB while it serves queries therefore stalls every query for the duration of
    the update, which for a large batch is not brief. Where that matters, build the new state
    separately and direct later queries at it, or update while the sender is not serving.
    */
    class SenderDB {
    public:
        /**
        Creates a new SenderDB.
        */
        SenderDB(
            const PSIParams &params,
            std::size_t label_byte_count = 0,
            std::size_t nonce_byte_count = 16,
            bool compressed = true);

        /**
        Creates a new SenderDB.
        */
        SenderDB(
            const PSIParams &params,
            oprf::OPRFKey oprf_key,
            std::size_t label_byte_count = 0,
            std::size_t nonce_byte_count = 16,
            bool compressed = true);

        /**
        Creates a new SenderDB by moving from an existing one.

        Moving must not overlap any other use of either SenderDB, including a query in progress.
        A move replaces the PSI parameters and the CryptoContext, and those are read through
        accessors that take no lock, because query worker threads call them while the calling
        thread holds the reader lock. The lock taken here therefore orders a move against other
        moves and against the locked operations, but not against those accessors.
        */
        SenderDB(SenderDB &&source) noexcept;

        /**
        Moves an existing SenderDB to the current one. As with the move constructor, this must not
        overlap any other use of either SenderDB.
        */
        SenderDB &operator=(SenderDB &&source) noexcept;

        SenderDB(const SenderDB &copy) = delete;

        /**
        Clears the database. Every item and label will be removed. The OPRF key is unchanged.
        */
        void clear();

        /**
        Returns whether this is a labeled SenderDB.
        */
        bool is_labeled() const
        {
            return 0 != label_byte_count_;
        }

        /**
        Returns the label byte count. A zero value indicates an unlabeled SenderDB.
        */
        std::size_t get_label_byte_count() const
        {
            return label_byte_count_;
        }

        /**
        Returns the nonce byte count used for encrypting labels.
        */
        std::size_t get_nonce_byte_count() const
        {
            return nonce_byte_count_;
        }

        /**
        Indicates whether SEAL plaintexts are compressed in memory.
        */
        bool is_compressed() const
        {
            return compressed_;
        }

        /**
        Indicates whether the SenderDB has been stripped of all information not needed for
        serving a query.
        */
        bool is_stripped() const
        {
            return stripped_;
        }

        /**
        Strips the SenderDB of all information not needed for serving a query. Returns a copy of
        the OPRF key and clears it from the SenderDB.
        */
        oprf::OPRFKey strip();

        /**
        Returns a copy of the OPRF key.
        */
        oprf::OPRFKey get_oprf_key() const;

        /**
        Inserts the given data into the database. This function can be used only on a labeled
        SenderDB instance. If an item already exists in the database, its label is overwritten
        with the new label.
        */
        void insert_or_assign(const std::vector<std::pair<Item, Label>> &data);

        /**
        Inserts the given (hashed) item-label pair into the database. This function can be used
        only on a labeled SenderDB instance. If the item already exists in the database, its
        label is overwritten with the new label.
        */
        void insert_or_assign(const std::pair<Item, Label> &data)
        {
            std::vector<std::pair<Item, Label>> data_singleton{ data };
            insert_or_assign(data_singleton);
        }

        /**
        Inserts the given data into the database. This function can be used only on an unlabeled
        SenderDB instance.
        */
        void insert_or_assign(const std::vector<Item> &data);

        /**
        Inserts the given (hashed) item into the database. This function can be used only on an
        unlabeled SenderDB instance.
        */
        void insert_or_assign(const Item &data)
        {
            std::vector<Item> data_singleton{ data };
            insert_or_assign(data_singleton);
        }

        /**
        Clears the database and inserts the given data. This function can be used only on a
        labeled SenderDB instance.
        */
        void set_data(const std::vector<std::pair<Item, Label>> &data)
        {
            clear();
            insert_or_assign(data);
        }

        /**
        Clears the database and inserts the given data. This function can be used only on an
        unlabeled SenderDB instance.
        */
        void set_data(const std::vector<Item> &data)
        {
            clear();
            insert_or_assign(data);
        }

        /**
        Removes the given data from the database, using at most thread_count threads.
        */
        void remove(const std::vector<Item> &data);

        /**
        Removes the given (hashed) item from the database.
        */
        void remove(const Item &data)
        {
            std::vector<Item> data_singleton{ data };
            remove(data_singleton);
        }

        /**
        Returns whether the given item has been inserted in the SenderDB.
        */
        bool has_item(const Item &item) const;

        /**
        Returns the label associated to the given item in the database. Throws
        std::invalid_argument if the item does not appear in the database.
        */
        Label get_label(const Item &item) const;

        /**
        Returns a set of cache references corresponding to the bundles at the given bundle
        index. Even though this function returns a vector, the order has no significance. Throws
        std::out_of_range if bundle_idx is not a valid bundle index.

        This function is meant for internal use. It acquires no lock, and the references it
        returns point into the SenderDB's own storage: the caller must hold the reader lock
        before calling and keep holding it for as long as any of the returned references is
        used, including by any task it hands them to. An insert, removal, clear or strip
        reallocates or destroys the underlying bundles, and holding a shared_ptr to the SenderDB
        does not keep an individual bundle or its cache alive.
        */
        auto get_cache_at(std::uint32_t bundle_idx)
            -> std::vector<std::reference_wrapper<const BinBundleCache>>;

        /**
        Returns a reference to the PSI parameters for this SenderDB.
        */
        const PSIParams &get_params() const
        {
            return params_;
        }

        /**
        Returns a reference to the CryptoContext for this SenderDB.
        */
        const CryptoContext &get_crypto_context() const
        {
            return crypto_context_;
        }

        /**
        Returns a reference to the SEALContext for this SenderDB.
        */
        std::shared_ptr<seal::SEALContext> get_seal_context() const
        {
            return crypto_context_.seal_context();
        }

        /**
        Returns a reference to a set of item hashes already existing in the SenderDB.
        */
        const std::unordered_set<HashedItem> &get_hashed_items() const
        {
            return hashed_items_;
        }

        /**
        Returns the number of items in this SenderDB.
        */
        size_t get_item_count() const
        {
            return item_count_;
        }

        /**
        Returns the total number of bin bundles at a specific bundle index.
        */
        std::size_t get_bin_bundle_count(std::uint32_t bundle_idx) const;

        /**
        Returns the total number of bin bundles.
        */
        std::size_t get_bin_bundle_count() const;

        /**
        Returns an upper bound on the base-2 logarithm of the probability that a query of
        query_item_count items returns at least one false positive against this database.

        This is the figure a deployment wants. It counts what PSIParams::log2_fpp_per_bin_bundle
        cannot: the bin bundles a location spills into, which this database knows, and the items
        a query carries, which the caller supplies. Pass 1 for the probability per item.

        The result moves as items are inserted, since inserting can add bin bundles. It is an
        upper bound rather than an exact figure -- both terms it adds are union bounds -- and it
        assumes the OPRF leaves items pseudorandom.

        Throws std::invalid_argument if query_item_count is zero.
        */
        [[nodiscard]] double log2_fpp(std::size_t query_item_count) const;

        /**
        Returns the total number of bin bundles. The caller must already hold a lock on this
        SenderDB; this function acquires none. Acquiring the reader lock a second time on a
        thread that already holds it is undefined behavior and deadlocks against a waiting
        writer, so a caller holding the lock must use this function rather than
        get_bin_bundle_count. This function is meant for internal use.
        */
        std::size_t get_bin_bundle_count_unlocked() const;

        /**
        Returns how efficiently the SenderDB is packaged. A higher rate indicates better
        performance and a lower communication cost in a query execution.
        */
        double get_packing_rate() const;

        /**
        Obtains a scoped lock preventing the SenderDB from being changed.
        */
        std::shared_lock<std::shared_mutex> get_reader_lock() const
        {
            return std::shared_lock<std::shared_mutex>(db_lock_);
        }

        /**
        Writes the SenderDB to a stream.
        */
        std::size_t save(std::ostream &out) const;

        /**
        Reads the SenderDB from a stream.
        */
        static std::pair<SenderDB, std::size_t> Load(std::istream &in);

    private:
        std::unique_lock<std::shared_mutex> get_writer_lock()
        {
            return std::unique_lock<std::shared_mutex>(db_lock_);
        }

        /**
        Moves the contents of source into a newly constructed SenderDB. The move constructor
        delegates here, passing a writer lock on source: the arguments of a delegating
        mem-initializer are evaluated before the target constructor is entered, so source is
        locked before any of its state is read. The lock is taken by value so that it outlives
        this constructor; do not replace the parameter with a local, which would be constructed
        only after the member initializers have already run.
        */
        SenderDB(
            SenderDB &&source,
            std::unique_lock<std::shared_mutex> source_lock [[maybe_unused]]) noexcept;

        void clear_internal();

        void generate_caches();

        /**
        The set of all items that have been inserted into the database
        */
        std::unordered_set<HashedItem> hashed_items_;

        /**
        The PSI parameters define the SEAL parameters, base field, item size, table size, etc.
        */
        PSIParams params_;

        /**
        Necessary for evaluating polynomials of Plaintexts.
        */
        CryptoContext crypto_context_;

        /**
        A read-write lock to protect the database from modification while in use.
        */
        mutable std::shared_mutex db_lock_;

        /**
        Indicates the size of the label in bytes. A zero value indicates an unlabeled SenderDB.
        */
        std::size_t label_byte_count_;

        /**
        Indicates the number of bytes of the effective label reserved for a randomly sampled
        nonce. The effective label byte count is the sum of label_byte_count and
        nonce_byte_count. The value can range between 0 and 16. If label_byte_count is zero,
        nonce_byte_count has no effect.
        */
        std::size_t nonce_byte_count_;

        /**
        The number of items currently in the SenderDB.
        */
        std::size_t item_count_;

        /**
        Indicates whether SEAL plaintexts are compressed in memory.
        */
        bool compressed_;

        /**
        Indicates whether the SenderDB has been stripped of all information not needed for
        serving a query.
        */
        bool stripped_{};

        /**
        All the BinBundles in the database, indexed by bundle index. The set (represented by a
        vector internally) at bundle index i contains all the BinBundles with bundle index i.
        */
        std::vector<std::vector<BinBundle>> bin_bundles_;

        /**
        Holds the OPRF key for this SenderDB.
        */
        oprf::OPRFKey oprf_key_;
    }; // class SenderDB
} // namespace apsi::sender
