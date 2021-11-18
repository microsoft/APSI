// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
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
#include "seal/util/locks.h"

namespace apsi {
    namespace sender {
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
        */
        class SenderDB {
        public:
            /**
            Creates a new SenderDB.
            */
            SenderDB(
                PSIParams params,
                std::size_t label_byte_count = 0,
                std::size_t nonce_byte_count = 16,
                bool compressed = true);

            /**
            Creates a new SenderDB.
            */
            SenderDB(
                PSIParams params,
                oprf::OPRFKey oprf_key,
                std::size_t label_byte_count = 0,
                std::size_t nonce_byte_count = 16,
                bool compressed = true);

            /**
            Creates a new SenderDB by moving from an existing one.
            */
            SenderDB(SenderDB &&source);

            /**
            Moves an existing SenderDB to the current one.
            */
            SenderDB &operator=(SenderDB &&source);

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
            index. Even though this function returns a vector, the order has no significance. This
            function is meant for internal use.
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
            Returns how efficiently the SenderDB is packaged. A higher rate indicates better
            performance and a lower communication cost in a query execution.
            */
            double get_packing_rate() const;

            /**
            Obtains a scoped lock preventing the SenderDB from being changed.
            */
            seal::util::ReaderLock get_reader_lock() const
            {
                return db_lock_.acquire_read();
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
            SenderDB(const SenderDB &copy) = delete;

            seal::util::WriterLock get_writer_lock()
            {
                return db_lock_.acquire_write();
            }

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
            mutable seal::util::ReaderWriterLocker db_lock_;

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
            bool stripped_;

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
    }      // namespace sender
} // namespace apsi
