// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <unordered_set>
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

// Kuku
#include "kuku/kuku.h"

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
            Clears the database
            */
            virtual void clear_db() = 0;

            /**
            Clears the database and inserts the given data, using at most thread_count threads. Only one of these is
            defined for a given child of SenderDB, corresponding to whether it is labeled or unlabeled.
            */
            virtual void set_data(
                std::vector<std::pair<HashedItem, util::FullWidthLabel> > &data,
                std::size_t thread_count
            ) = 0;
            virtual void set_data(
                const std::vector<HashedItem> &data,
                std::size_t thread_count
            ) = 0;

            /**
            Inserts the given data into the database, using at most thread_count threads. Only one of these is defined
            for a given child of SenderDB, corresponding to whether it is labeled or unlabeled. In the labeled case, if
            an item exists, its label is overwritten with the new label value.
            */
            virtual void insert_data(
                std::vector<std::pair<HashedItem, util::FullWidthLabel> > &data,
                std::size_t thread_count
            ) = 0;
            virtual void insert_data(
                const std::vector<HashedItem> &data,
                std::size_t thread_count
            ) = 0;

            /**
            Returns a set of DB cache references corresponding to the bundles at the given
            bundle index. This returns a vector but order doesn't matter.
            */
            virtual auto get_cache_at(std::uint32_t bundle_idx)
                -> std::vector<std::reference_wrapper<const BinBundleCache> > = 0;

            const PSIParams &get_params() const
            {
                return params_;
            }

            CryptoContext get_context() const
            {
                return crypto_context_;
            }

            const std::unordered_set<HashedItem>& get_items() {
                return items_;
            }

            /**
            Returns the total number of bin bundles.
            */
            virtual std::size_t bin_bundle_count() = 0;

            seal::util::ReaderLock get_reader_lock()
            {
                return db_lock_.acquire_read();
            }

        protected:

            /**
            The set of all items that have been inserted into the database
            */
            mutable std::unordered_set<HashedItem> items_;

            /**
            This defines our SEAL context, base field, item size, etc.
            */
            PSIParams params_;

            /**
            Necessary for evaluating polynomials of Plaintexts
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
            index i contains all the BinBundles with bundle index i
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
            Clears the database
            */
            void clear_db() override;

            /**
            Returns the total number of bin bundles.
            */
            std::size_t bin_bundle_count() override;

            /**
            Returns a set of DB cache references corresponding to the bundles at the given
            bundle index. This returns a vector but order doesn't matter.
            */
            auto get_cache_at(std::uint32_t bundle_idx)
                -> std::vector<std::reference_wrapper<const BinBundleCache> > override;

            /**
            Clears the database and inserts the given data, using at most thread_count threads. This will mutate the
            input vector. Specifically, it will stable-sort the vector into (new entries || overwriting entries).
            */
            void set_data(
                std::vector<std::pair<HashedItem, FullWidthLabel> > &data,
                std::size_t thread_count = 0
            ) override;

            /**
            DO NOT USE. Unlabeled insertion on a labeled database does not and should not work.
            */
            void set_data(
                const std::vector<HashedItem> &data,
                std::size_t thread_count = 0
            ) override;

            /**
            Inserts the given data into the database, using at most thread_count threads. This will mutate the input
            vector. Specifically, it will stable-sort the vector into (new entries || overwriting entries).
            */
            void insert_data(
                std::vector<std::pair<HashedItem, FullWidthLabel> > &data,
                std::size_t thread_count = 0
            ) override;

            /**
            DO NOT USE. Unlabeled insertion on a labeled database does not and should not work.
            */
            void insert_data(
                const std::vector<HashedItem> &data,
                std::size_t thread_count = 0
            ) override;
        }; // class LabeledSenderDB

        class UnlabeledSenderDB : public SenderDB
        {
        private:
            /**
            All the BinBundles in the DB, indexed by bin index. The set (represented by a vector internally) at bundle
            index i contains all the BinBundles with bundle index i
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
            Clears the database
            */
            void clear_db() override;

            /**
            Returns the total number of bin bundles.
            */
            std::size_t bin_bundle_count() override;

            /**
            Returns a set of DB cache references corresponding to the bundles at the given
            bundle index. This returns a vector but order doesn't matter.
            */
            std::vector<std::reference_wrapper<const BinBundleCache> > get_cache_at(std::uint32_t bundle_idx)  override;

            /**
            DO NOT USE. Labeled insertion on an unlabeled database does not and should not work.
            */
            void set_data(
                std::vector<std::pair<HashedItem, FullWidthLabel> > &data,
                std::size_t thread_count = 0
            ) override;

            /**
            Clears the database and inserts the given data, using at most thread_count threads
            */
            void set_data(
                const std::vector<HashedItem> &data,
                std::size_t thread_count = 0
            ) override;

            /**
            DO NOT USE. Labeled insertion on an unlabeled database does not and should not work.
            */
            void insert_data(
                std::vector<std::pair<HashedItem, FullWidthLabel> > &data,
                std::size_t thread_count = 0
            ) override;

            /**
            Inserts the given data into the database, using at most thread_count threads
            */
            void insert_data(
                const std::vector<HashedItem> &data,
                std::size_t thread_count = 0
            ) override;
        }; // class UnlabeledSenderDB
    }  // namespace sender
} // namespace apsi
