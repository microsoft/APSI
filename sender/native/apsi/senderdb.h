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
            virtual void set_data(const std::map<Item, util::FullWidthLabel> &data, std::size_t thread_count) = 0;
            virtual void set_data(const std::map<Item, monostate> &data, std::size_t thread_count) = 0;

            /**
            Inserts the given data into the database, using at most thread_count threads. Only one of these is defined
            for a given child of SenderDB, corresponding to whether it is labeled or unlabeled.
            */
            virtual void add_data(const std::map<Item, util::FullWidthLabel> &data, std::size_t thread_count) = 0;
            virtual void add_data(const std::map<Item, monostate> &data, std::size_t thread_count) = 0;

            /**
            Returns a set of DB cache references corresponding to the bundles at the given
            bundle index.
            */
            virtual std::set<std::reference_wrapper<const BinBundleCache> > get_cache_at(std::uint32_t bundle_idx) = 0;

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

        private:
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
            All the BinBundles in the DB, indexed by bin index. The set at bundle index i contains all the BinBundles
            with bundle index i
            */
            std::vector<std::set<BinBundle<felt_t> > > bin_bundles_;

            /**
            Returns the total number of bin bundles.
            */
            std::size_t bin_bundle_count();

            /**
            Returns a set of DB cache references corresponding to the bundles at the given
            bundle index.
            */
            std::set<std::reference_wrapper<const BinBundleCache> > get_cache_at(std::uint32_t bundle_idx);

            /**
            Clears the database and inserts the given data, using at most thread_count threads
            */
            void set_data(const std::map<Item, FullWidthLabel> &data, std::size_t thread_count);
            void set_data(const std::map<Item, monostate> &data, std::size_t thread_count);

            /**
            Inserts the given data into the database, using at most thread_count threads
            */
            void add_data(const std::map<Item, FullWidthLabel> &data, std::size_t thread_count);
            void add_data(const std::map<Item, monostate> &data, std::size_t thread_count);
        }; // class LabeledSenderDB

        class UnabeledSenderDB : public SenderDB
        {
            // Inherit SenderDB constructor
            using SenderDB::SenderDB;

            /**
            All the BinBundles in the DB, indexed by bin index. The set at bundle index i contains all the BinBundles
            with bundle index i
            */
            std::vector<std::set<BinBundle<monostate> > > bin_bundles_;

            /**
            Returns the total number of bin bundles.
            */
            std::size_t bin_bundle_count();

            /**
            Returns a set of DB cache references corresponding to the bundles at the given
            bundle index.
            */
            std::set<std::reference_wrapper<const BinBundleCache> > get_cache_at(std::uint32_t bundle_idx);

            /**
            Clears the database and inserts the given data, using at most thread_count threads
            */
            void set_data(const std::map<Item, FullWidthLabel> &data, std::size_t thread_count);
            void set_data(const std::map<Item, monostate> &data, std::size_t thread_count);

            /**
            Inserts the given data into the database, using at most thread_count threads
            */
            void add_data(const std::map<Item, FullWidthLabel> &data, std::size_t thread_count);
            void add_data(const std::map<Item, monostate> &data, std::size_t thread_count);
        }; // class UnlabeledSenderDB
    }  // namespace sender
} // namespace apsi
