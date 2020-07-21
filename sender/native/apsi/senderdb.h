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
        template<typename L>
        class LabeledSenderDB
        {
        public:
            LabeledSenderDB(PSIParams params);

            /**
            Clears the database
            */
            void clear_db();

            /**
            Clears the database and inserts the given data, using at most thread_count threads
            */
            void set_data(std::map<Item, L> &data, size_t thread_count)

            /**
            Inserts the given data into the database, using at most thread_count threads
            */
            void add_data(std::map<Item, L> &data, size_t thread_count)

            /**
            Inserts the given items and corresponding labels into the database at the given cuckoo indices. Concretely,
            for every ((item, label), cuckoo_idx) element, the item is inserted into the database at cuckoo_idx and its
            label is set to label.
            */
            void add_data_worker(
                const gsl::span<pair<&pair<Item, vector<uint8_t> >, size_t> > data_with_indices
            );

            const PSIParams &get_params() const
            {
                return params_;
            }

        private:
            PSIParams params_;

            /**
            All the BinBundles in the DB, indexed by bin index. The vector at bundle index i contains all the BinBundles
            with bundle index i. The order of the BinBundle within a given bundle index doesn't matter (we could've just
            as easily used a vector<set<BinBundle>>), but the canonical ordering makes references to specific BinBundles
            easier.
            */
            std::vector<std::vector<LabeledBinBundle> > bin_bundles_;

        }; // class LabeledSenderDB
    }  // namespace sender
} // namespace apsi
