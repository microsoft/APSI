// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <atomic>
#include <cstddef>
#include <memory>
#include <utility>
#include <vector>

// GSL
#include <gsl/span>

// APSI
#include "apsi/dbblock.h"
#include "apsi/item.h"
#include "apsi/psiparams.h"
#include "apsi/sendersessioncontext.h"
#include "apsi/senderthreadcontext.h"

// Kuku
#include "kuku/kuku.h"

// SEAL
#include "seal/plaintext.h"

namespace apsi
{
    namespace sender
    {
        // Labels are always the size of items, i.e., ITEM_BIT_LEN bits long
        using FullWidthLabel = Item;

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
            Returns the whole DB cache. The value at index i is the set of caches of BinBundles at bundle index i.
            */
            std::vector<std::vector<BinBundleCache> > &get_cache();

            const PSIParams &get_params() const
            {
                return params_;
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
            All the BinBundles in the DB, indexed by bin index. The vector at bundle index i contains all the BinBundles
            with bundle index i. The order of the BinBundle within a given bundle index doesn't matter (we could've just
            as easily used a vector<set<BinBundle>>), but the canonical ordering makes references to specific BinBundles
            easier.
            */
            std::vector<std::vector<BinBundle<L> > > bin_bundles_;
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
