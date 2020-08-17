// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>
#include <set>

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
            SenderDB(PSIParams params) :
                params_(params),
                crypto_context_(seal::SEALContext::Create(params.seal_params()))
            {}

            /**
            Clears the database
            */
            virtual void clear_db() = 0;

            /**
            Clears the database and inserts the given data, using at most thread_count threads. Only one of these is
            defined for a given child of SenderDB, corresponding to whether it is labeled or unlabeled.
            */
            virtual void set_data(const std::map<HashedItem, util::FullWidthLabel> &data, std::size_t thread_count) = 0;
            virtual void set_data(const std::map<HashedItem, monostate> &data, std::size_t thread_count) = 0;

            /**
            Inserts the given data into the database, using at most thread_count threads. Only one of these is defined
            for a given child of SenderDB, corresponding to whether it is labeled or unlabeled.
            */
            virtual void add_data(const std::map<HashedItem, util::FullWidthLabel> &data, std::size_t thread_count) = 0;
            virtual void add_data(const std::map<HashedItem, monostate> &data, std::size_t thread_count) = 0;

            /**
            Returns a set of DB cache references corresponding to the bundles at the given
            bundle index. This returns a vector but order doesn't matter.
            */
            virtual std::vector<std::reference_wrapper<const BinBundleCache> > get_cache_at(std::uint32_t bundle_idx) = 0;

            const PSIParams &get_params() const
            {
                return params_;
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
            Necessary for evaluating polynomials of Plaintexts
            */
            CryptoContext crypto_context_;

            /**
            This defines our SEAL context, base field, item size, etc.
            */
            PSIParams params_;

            /**
            A read-write lock to protect the database from modification while in use.
            */
            mutable seal::util::ReaderWriterLocker db_lock_;
        }; // class SenderDB

        class LabeledSenderDB : public SenderDB
        {
            // Inherit SenderDB constructor
            using SenderDB::SenderDB;

            /**
            All the BinBundles in the DB, indexed by bin index. The set (represented by a vector internally) at bundle
            index i contains all the BinBundles with bundle index i
            */
            std::vector<std::vector<BinBundle<felt_t> > > bin_bundles_;

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
            std::vector<std::reference_wrapper<const BinBundleCache> > get_cache_at(std::uint32_t bundle_idx) override;

            /**
            Clears the database and inserts the given data, using at most thread_count threads
            */
            void set_data(const std::map<HashedItem, FullWidthLabel> &data, std::size_t thread_count = 0) override;
            void set_data(const std::map<HashedItem, monostate> &data, std::size_t thread_count = 0) override;

            /**
            Inserts the given data into the database, using at most thread_count threads
            */
            void add_data(const std::map<HashedItem, FullWidthLabel> &data, std::size_t thread_count = 0) override;
            void add_data(const std::map<HashedItem, monostate> &data, std::size_t thread_count = 0) override;
        }; // class LabeledSenderDB

        class UnlabeledSenderDB : public SenderDB
        {
            // Inherit SenderDB constructor
            using SenderDB::SenderDB;

            /**
            All the BinBundles in the DB, indexed by bin index. The set (represented by a vector internally) at bundle
            index i contains all the BinBundles with bundle index i
            */
            std::vector<std::vector<BinBundle<monostate> > > bin_bundles_;

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
            std::vector<std::reference_wrapper<const BinBundleCache> > get_cache_at(std::uint32_t bundle_idx) override;

            /**
            Clears the database and inserts the given data, using at most thread_count threads
            */
            void set_data(const std::map<HashedItem, FullWidthLabel> &data, std::size_t thread_count = 0) override;
            void set_data(const std::map<HashedItem, monostate> &data, std::size_t thread_count = 0) override;

            /**
            Inserts the given data into the database, using at most thread_count threads
            */
            void add_data(const std::map<HashedItem, FullWidthLabel> &data, std::size_t thread_count = 0) override;
            void add_data(const std::map<HashedItem, monostate> &data, std::size_t thread_count = 0) override;
        }; // class UnlabeledSenderDB
    }  // namespace sender
} // namespace apsi
