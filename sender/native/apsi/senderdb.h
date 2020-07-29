// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <atomic>
#include <cstddef>
#include <memory>
#include <utility>
#include <vector>
#include <set>

// GSL
#include <gsl/span>

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
        // Labels are always the size of items, i.e., ITEM_BIT_LEN bits long
        using FullWidthLabel = Item;

        // A representation of item-label as a sequence of felt_t pairs, or item-unit as a sequence of pairs where the
        // first element is felt_t and the second is monostate
        template<typename L>
        using AlgItemLabel = std::vector<std::pair<felt_t, L> >;

        template<typename L>
        class SenderDB
        {
        public:
            SenderDB(PSIParams params);

            /**
            Clears the database
            */
            void clear_db();

            /**
            Clears the database and inserts the given data, using at most thread_count threads
            */
            virtual void set_data(std::map<Item, FullWidthLabel> &data, size_t thread_count) = 0;
            virtual void set_data(std::map<Item, monostate> &data, size_t thread_count) = 0;

            /**
            Inserts the given data into the database, using at most thread_count threads
            */
            virtual void add_data(std::map<Item, FullWidthLabel> &data, size_t thread_count) = 0;
            virtual void add_data(std::map<Item, monostate> &data, size_t thread_count) = 0;

            /**
            Returns a set of DB cache references corresponding to the bundles at the given
            bundle index.
            */
            std::set<BinBundleCache&> get_cache(std::size_t bundle_idx);

            const PSIParams &get_params() const
            {
                return params_;
            }

            seal::util::ReaderLock get_reader_lock() const
            {
                return db_lock_.acquire_read();
            }

        private:
            /**
            Inserts the given items and corresponding labels into the database at the given cuckoo indices. Concretely,
            for every ((item, label), cuckoo_idx) element, the item is inserted into the database at cuckoo_idx and its
            label is set to label.
            */
            void add_data_worker(
                const gsl::span<pair<&pair<felt_t, L>, size_t> > data_with_indices
            );

            /**
            This defines our SEAL context, base field, item size, etc.
            */
            PSIParams params_;

            /**
            All the BinBundles in the DB, indexed by bin index. The set at bundle index i contains all the BinBundles
            with bundle index i
            */
            std::vector<std::set<BinBundle<L> > > bin_bundles_;

            /**
            A read-write lock to protect the database from modification while in use.
            */
            seal::util::ReaderWriterLocker db_lock_;
        }; // class SenderDB

        class LabeledSenderDB: SenderDB<felt_t> {
            /**
            Clears the database and inserts the given data, using at most thread_count threads
            */
            void set_data(std::map<Item, FullWidthLabel> &data, size_t thread_count);
            void set_data(std::map<Item, monostate> &data, size_t thread_count);

            /**
            Inserts the given data into the database, using at most thread_count threads
            */
            void add_data(std::map<Item, FullWidthLabel> &data, size_t thread_count);
            void add_data(std::map<Item, monostate> &data, size_t thread_count);
        }; // class LabeledSenderDB

        class UnabeledSenderDB: SenderDB<monostate> {
            /**
            Clears the database and inserts the given data, using at most thread_count threads
            */
            void set_data(std::map<Item, FullWidthLabel> &data, size_t thread_count);
            void set_data(std::map<Item, monostate> &data, size_t thread_count);

            /**
            Inserts the given data into the database, using at most thread_count threads
            */
            void add_data(std::map<Item, FullWidthLabel> &data, size_t thread_count);
            void add_data(std::map<Item, monostate> &data, size_t thread_count);
        }; // class UnlabeledSenderDB
    }  // namespace sender
} // namespace apsi
