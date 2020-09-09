// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <unordered_set>
#include <unordered_map>
#include <utility>
#include <vector>

// GSL
#include "gsl/span"

// APSI
#include "apsi/binbundle.h"
#include "apsi/item.h"
#include "apsi/psiparams.h"
#include "apsi/cryptocontext.h"
#include "apsi/util/db_encoding.h"

// SEAL
#include "seal/plaintext.h"
#include "seal/util/locks.h"

namespace apsi
{
    namespace sender
    {
        class SenderDB
        {
        public:
            SenderDB(PSIParams params) : params_(params), crypto_context_(params_.seal_params())
            {
                // Make sure the evaluator is set. This will be used for BatchedPlaintextPolyn::eval.
                crypto_context_.set_evaluator();
            }

            /**
            Clears the database.
            */
            virtual void clear_db() = 0;

            /**
            Clears the database and inserts the given data, using at most thread_count threads. This function can be
            used only on a LabeledSenderDB instance.
            */
            virtual void set_data(
                const std::unordered_map<HashedItem, util::FullWidthLabel> &data,
                std::size_t thread_count
            ) = 0;

            /**
            Clears the database and inserts the given data, using at most thread_count threads. This function can be
            used only on an UnlabeledSenderDB instance.
            */
            virtual void set_data(
                const std::unordered_set<HashedItem> &data,
                std::size_t thread_count
            ) = 0;

            /**
            Inserts the given data into the database, using at most thread_count threads. This function can be used only
            on a LabeledSenderDB instance. If an item already exists, its label is overwritten with the new label.
            */
            virtual void insert_or_assign(
                const std::unordered_map<HashedItem, util::FullWidthLabel> &data,
                std::size_t thread_count
            ) = 0;

            /**
            Inserts the given data into the database, using at most thread_count threads. This function can be used only
            on a LabeledSenderDB instance. If an item already exists, its label is overwritten with the new label.
            */
            virtual void insert_or_assign(
                const std::pair<HashedItem, util::FullWidthLabel> &data
            ) = 0;

            /**
            Inserts the given data into the database, using at most thread_count threads. This function can be used only
            on an UnlabeledSenderDB instance.
            */
            virtual void insert_or_assign(
                const std::unordered_set<HashedItem> &data,
                std::size_t thread_count
            ) = 0;

            /**
            Inserts the given data into the database, using at most thread_count threads. This function can be used only
            on an UnlabeledSenderDB instance.
            */
            virtual void insert_or_assign(
                const HashedItem &data
            ) = 0;

            /**
            Removes the given data from the database, using at most thread_count threads.
            */
            virtual void remove(
                const std::unordered_set<HashedItem> &data,
                std::size_t thread_count
            ) = 0;

            /**
            Removes the given data from the database, using at most thread_count threads.
            */
            virtual void remove(
                const HashedItem &data
            ) = 0;

            /**
            Returns a set of cache references corresponding to the bundles at the given bundle index. Even though this
            function returns a vector, the order has no significance.
            */
            virtual auto get_cache_at(std::uint32_t bundle_idx)
                -> std::vector<std::reference_wrapper<const BinBundleCache> > = 0;

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
            const CryptoContext &get_context() const
            {
                return crypto_context_;
            }

            /**
            Returns a reference to a set of items already existing in the SenderDB.
            */
            const std::unordered_set<HashedItem> &get_items() {
                return items_;
            }

            /**
            Returns the total number of bin bundles.
            */
            virtual std::size_t get_bin_bundle_count() = 0;

            /**
            Obtains a scoped lock preventing the SenderDB from being changed.
            */
            seal::util::ReaderLock get_reader_lock()
            {
                return db_lock_.acquire_read();
            }

        protected:
            /**
            The set of all items that have been inserted into the database
            */
            std::unordered_set<HashedItem> items_;

            /**
            This defines our SEAL context, base field, item size, etc.
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
        }; // class SenderDB

        class LabeledSenderDB : public SenderDB
        {
        private:
            /**
            All the BinBundles in the DB, indexed by bin index. The set (represented by a vector internally) at bundle
            index i contains all the BinBundles with bundle index i.
            */
            std::vector<std::vector<BinBundle<felt_t> > > bin_bundles_;

        public:
            /**
            Creates a new LabeledSenderDB.
            */
            LabeledSenderDB(PSIParams params) : SenderDB(std::move(params))
            {
                clear_db();
            }

            /**
            Clears the database.
            */
            void clear_db() override;

            /**
            Returns the total number of bin bundles.
            */
            std::size_t get_bin_bundle_count() override;

            /**
            Returns a set of DB cache references corresponding to the bundles at the given
            bundle index. This returns a vector but order doesn't matter.
            */
            auto get_cache_at(std::uint32_t bundle_idx)
                -> std::vector<std::reference_wrapper<const BinBundleCache> > override;

            /**
            Clears the database and inserts the given data, using at most thread_count threads.
            */
            void set_data(
                const std::unordered_map<HashedItem, FullWidthLabel> &data,
                std::size_t thread_count = 0
            ) override;

            /**
            DO NOT USE. Unlabeled insertion on a labeled database does not and should not work.
            */
            void set_data(
                const std::unordered_set<HashedItem> &data,
                std::size_t thread_count = 0
            ) override;

            /**
            Inserts the given data into the database, using at most thread_count threads.
            */
            void insert_or_assign(
                const std::unordered_map<HashedItem, FullWidthLabel> &data,
                std::size_t thread_count = 0
            ) override;

            /**
            Inserts the given data into the database, using at most thread_count threads.
            */
            void insert_or_assign(
                const std::pair<HashedItem, FullWidthLabel> &data
            ) override
            {
                std::unordered_map<HashedItem, FullWidthLabel> data_map;
                data_map.emplace(data);
                insert_or_assign(data_map, 1);
            }

            /**
            DO NOT USE. Unlabeled insertion on a labeled database does not and should not work.
            */
            void insert_or_assign(
                const std::unordered_set<HashedItem> &data,
                std::size_t thread_count = 0
            ) override;

            /**
            DO NOT USE. Unlabeled insertion on a labeled database does not and should not work.
            */
            void insert_or_assign(
                const HashedItem &data
            ) override
            {
                std::unordered_set<HashedItem> data_set;
                data_set.emplace(data);
                insert_or_assign(data_set, 1);
            }

            /**
            Removes the given data from the database, using at most thread_count threads.
            */
            void remove(
                const std::unordered_set<HashedItem> &data,
                std::size_t thread_count
            ) override;

            /**
            Removes the given data from the database, using at most thread_count threads.
            */
            void remove(
                const HashedItem &data
            ) override
            {
                std::unordered_set<HashedItem> data_set;
                data_set.emplace(data);
                remove(data_set, 1);
            }

            /**
            Returns the label associated to the given item in the database. Throws std::invalid_argument if the item
            does not appear in the database.
            */
            FullWidthLabel get_label(const HashedItem &item) const;
        }; // class LabeledSenderDB

        class UnlabeledSenderDB : public SenderDB
        {
        private:
            /**
            All the BinBundles in the DB, indexed by bin index. The set (represented by a vector internally) at bundle
            index i contains all the BinBundles with bundle index i.
            */
            std::vector<std::vector<BinBundle<monostate> > > bin_bundles_;

        public:
            /**
            Creates a new UnlabeledSenderDB.
            */
            UnlabeledSenderDB(PSIParams params) : SenderDB(std::move(params))
            {
                clear_db();
            }

            /**
            Clears the database.
            */
            void clear_db() override;

            /**
            Returns the total number of bin bundles.
            */
            std::size_t get_bin_bundle_count() override;

            /**
            Returns a set of DB cache references corresponding to the bundles at the given
            bundle index. This returns a vector but order doesn't matter.
            */
            std::vector<std::reference_wrapper<const BinBundleCache> > get_cache_at(std::uint32_t bundle_idx)  override;

            /**
            DO NOT USE. Labeled insertion on an unlabeled database does not and should not work.
            */
            void set_data(
                const std::unordered_map<HashedItem, FullWidthLabel> &data,
                std::size_t thread_count = 0
            ) override;

            /**
            Clears the database and inserts the given data using at most thread_count threads.
            */
            void set_data(
                const std::unordered_set<HashedItem> &data,
                std::size_t thread_count = 0
            ) override;

            /**
            DO NOT USE. Labeled insertion on an unlabeled database does not and should not work.
            */
            void insert_or_assign(
                const std::unordered_map<HashedItem, FullWidthLabel> &data,
                std::size_t thread_count = 0
            ) override;

            /**
            DO NOT USE. Labeled insertion on an unlabeled database does not and should not work.
            */
            void insert_or_assign(
                const std::pair<HashedItem, FullWidthLabel> &data
            ) override
            {
                std::unordered_map<HashedItem, FullWidthLabel> data_map;
                data_map.emplace(data);
                insert_or_assign(data_map, 1);
            }

            /**
            Inserts the given data into the database, using at most thread_count threads.
            */
            void insert_or_assign(
                const std::unordered_set<HashedItem> &data,
                std::size_t thread_count = 0
            ) override;

            /**
            Inserts the given data into the database, using at most thread_count threads.
            */
            void insert_or_assign(
                const HashedItem &data
            ) override
            {
                std::unordered_set<HashedItem> data_set;
                data_set.emplace(data);
                insert_or_assign(data_set, 1);
            }

            /**
            Removes the given data from the database, using at most thread_count threads.
            */
            void remove(
                const std::unordered_set<HashedItem> &data,
                std::size_t thread_count = 0
            ) override;

            /**
            Removes the given data from the database, using at most thread_count threads.
            */
            void remove(
                const HashedItem &data
            ) override
            {
                std::unordered_set<HashedItem> data_set;
                data_set.emplace(data);
                remove(data_set, 1);
            }
        }; // class UnlabeledSenderDB
    }  // namespace sender
} // namespace apsi
