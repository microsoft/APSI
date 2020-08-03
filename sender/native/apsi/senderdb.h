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
            SenderDB(PSIParams params);

            /**
            Clears the database
            */
            void clear_db();

            /**
            Clears the database and inserts the given data, using at most thread_count threads. Only one of these is
            defined for a given child of SenderDB, corresponding to whether it is labeled or unlabeled.
            */
            virtual void set_data(std::map<Item, FullWidthLabel> &data, std::size_t thread_count) = 0;
            virtual void set_data(std::map<Item, monostate> &data, std::size_t thread_count) = 0;

            /**
            Inserts the given data into the database, using at most thread_count threads. Only one of these is defined
            for a given child of SenderDB, corresponding to whether it is labeled or unlabeled.
            */
            virtual void add_data(std::map<Item, FullWidthLabel> &data, std::size_t thread_count) = 0;
            virtual void add_data(std::map<Item, monostate> &data, std::size_t thread_count) = 0;

            /**
            Returns a set of DB cache references corresponding to the bundles at the given
            bundle index.
            */
            std::set<BinBundleCache&> get_cache(std::uint32_t bundle_idx);

            const PSIParams &get_params() const
            {
                return params_;
            }

            /**
            Returns the total number of bin bundles.
            */
            std::size_t bin_bundle_count() const;

            seal::util::ReaderLock get_reader_lock() const
            {
                return db_lock_.acquire_read();
            }

        protected:

            /**
            This defines our SEAL context, base field, item size, etc.
            */
            PSIParams params_;

            /**
            All the BinBundles in the DB, indexed by bin index. The set at bundle index i contains all the BinBundles
            with bundle index i
            */
            std::vector<std::set<BinBundle<L> > > bin_bundles_;

        private:
            /**
            A read-write lock to protect the database from modification while in use.
            */
            mutable seal::util::ReaderWriterLocker db_lock_;
        }; // class SenderDB

        class LabeledSenderDB : public SenderDB
        {
            /**
            Clears the database and inserts the given data, using at most thread_count threads
            */
            void set_data(std::map<Item, FullWidthLabel> &data, std::size_t thread_count);
            void set_data(std::map<Item, monostate> &data, std::size_t thread_count);

            /**
            Inserts the given data into the database, using at most thread_count threads
            */
            void add_data(std::map<Item, FullWidthLabel> &data, std::size_t thread_count);
            void add_data(std::map<Item, monostate> &data, std::size_t thread_count);
        }; // class LabeledSenderDB

        class UnabeledSenderDB : public SenderDB
        {
            /**
            Clears the database and inserts the given data, using at most thread_count threads
            */
            void set_data(std::map<Item, FullWidthLabel> &data, std::size_t thread_count);
            void set_data(std::map<Item, monostate> &data, std::size_t thread_count);

            /**
            Inserts the given data into the database, using at most thread_count threads
            */
            void add_data(std::map<Item, FullWidthLabel> &data, std::size_t thread_count);
            void add_data(std::map<Item, monostate> &data, std::size_t thread_count);
        }; // class UnlabeledSenderDB
    }  // namespace sender
} // namespace apsi
