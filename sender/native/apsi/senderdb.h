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
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_array.h"
#include "apsi/ffield/ffield_elt.h"
#include "apsi/item.h"
#include "apsi/psiparams.h"
#include "apsi/sendersessioncontext.h"
#include "apsi/senderthreadcontext.h"
#include "apsi/util/matrix.h"
#include "apsi/util/matrixview.h"

// Kuku
#include "kuku/kuku.h"

// SEAL
#include "seal/plaintext.h"

namespace apsi
{
    namespace sender
    {
        class SenderDB
        {
        public:
            SenderDB(PSIParams params);

            /**
            Clears sender's database and set all entries to sender's null item.
            */
            void clear_db();

            /**
            Loads the input data into sender's database, and precomputes all necessary components for the PSI protocol,
            including symmetric polynomials, batching, etc.
            */
            void load_db(int thread_count, const std::vector<Item> &data, MatrixView<unsigned char> vals = {});

            /**
            Sets the sender's database by hashing the data items with all hash functions.
            */
            void set_data(gsl::span<const Item> keys, int thread_count);
            void set_data(gsl::span<const Item> keys, MatrixView<unsigned char> values, int thread_count);

            /**
            Adds the data items to sender's database.
            */
            void add_data(gsl::span<const Item> keys, int thread_count);
            void add_data(gsl::span<const Item> keys, MatrixView<unsigned char> values, int thread_count);

            /**
             No hash version of add data, specific for one query
            */
            void add_data_no_hash(gsl::span<const Item> data, MatrixView<unsigned char> values);

            /**
            Handles the work of one thread for adding items to sender's database
            */
            void add_data_worker(
                int thread_idx, int thread_count, gsl::span<const Item> data, MatrixView<unsigned char> values,
                std::vector<int> &loads);

            /**
            Adds one item to sender's database.
            */
            void add_data(const Item &item, int thread_count);

            /**
            Batches the randomized symmetric polynomials for the specified split and the specified batch in sender's
            database.

            @see randomized_symmetric_polys for computing randomized symmetric polynomials.
            */
            void batched_randomized_symmetric_polys(SenderThreadContext &th_context, int start_block, int end_block);

            void batched_interpolate_polys(SenderThreadContext &th_context, int start_block, int end_block);

            DBBlock &get_block(std::size_t batch, std::size_t split)
            {
                return *db_blocks_(batch, split);
            }

            std::uint64_t get_block_count() const
            {
                return db_blocks_.size();
            }

            const PSIParams &get_params() const
            {
                return params_;
            }

        private:
            PSIParams params_;
            FField field_;
            FFieldElt null_element_;
            FFieldElt neg_null_element_;
            int encoding_bit_length_;

            /*
            Size m vector, where m is the table size. Each value is an incremental counter for the
            corresponding bin in shuffle_index_. It points to the next value to be taken from shuffle_index_
            in the corresponding bin. */
            std::vector<int> next_locs_;

            /*
            Batched randomized symmetric polynomial terms.
            #splits x #batches x (split_size + 1). In fact, B = #splits x split_size. The table is
            essentially split into '#splits x #batches' blocks. Each block is related with a split
            and a batch.
            */
            std::vector<seal::Plaintext> batch_random_symm_poly_storage_;

            /*
            Null value for sender: 00..0011..11. The number of 1 is itemL.
            (Note: Null value for receiver is: 00..0010..00, with 1 on the itemL-th position.)
            */
            Item sender_null_item_;

            /* The FField encoding of the sender null value. */

            /*
            B x m, where B is sender's bin size, m is table size.
            This is actually a rotated view of the DB. We store it in this
            view so that multi-threading is more efficient for accessing data,
            i.e., one thread will take care of several continuous complete rows.
            */
            Matrix<DBBlock> db_blocks_;

            std::pair<DBBlock *, DBBlock::Position> acquire_db_position_after_oprf(std::size_t cuckoo_loc);

            SenderSessionContext session_context_;

            /**
            Precomputes all necessary components for the PSI protocol, including symmetric polynomials, batching, etc.
            This function is expensive and can be called after sender finishes adding items to the database.
            */
            void offline_compute(int thread_count);

            /**
            Handles work for offline_compute for a single thread.
            */
            void offline_compute_work(SenderThreadContext &th_context, int total_thread_count);

            /**
            Report progress of the offline_compute operation.
            Progress is reported to the Log.
            */
            void report_offline_compute_progress(
                std::vector<SenderThreadContext> &thread_contexts, std::atomic<bool> &work_finished);
        }; // class SenderDB
    }      // namespace sender
} // namespace apsi
