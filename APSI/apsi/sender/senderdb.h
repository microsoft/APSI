#pragma once

// STD
#include <memory>
#include <vector>
#include <iostream>
#include <atomic>
#include <unordered_set>

// APSI
#include "apsi/item.h"
#include "apsi/apsidefines.h"
#include "apsi/psiparams.h"
#include "apsi/sender/senderthreadcontext.h"
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_elt.h"
#include "apsi/ffield/ffield_array.h"
#include "apsi/ffield/ffield_fast_batch_encoder.h"
#include "apsi/tools/matrixview.h"
#include "apsi/tools/matrix.h"

// Cuckoo
#include "cuckoo/cuckoo.h"

// SEAL
#include "seal/plaintext.h"
#include "seal/evaluator.h"
#include "seal/batchencoder.h"

// CryptoTools
#include "cryptoTools/Crypto/PRNG.h"

namespace apsi
{
    namespace sender
    {
        struct DBInterpolationCache
        {
            DBInterpolationCache(
                std::shared_ptr<FFieldFastBatchEncoder> ex_batch_encoder,
                int batch_size,
                int items_per_split,
                int value_byte_length
                );


            std::vector<std::vector<FFieldArray>> div_diff_temp;
            std::vector<FFieldArray> coeff_temp, x_temp, y_temp;
            std::unordered_set<u64> key_set;
            std::vector<u64> temp_vec;
        }; 

        // represents a specific batch/split and stores the associated data.
        struct DBBlock
        {
            struct Position
            {
                int batch_offset;
                int split_offset = -1;

                explicit operator bool() const
                {
                    return split_offset != -1;
                }
            };

            void init(
                int batch_idx,
                int split_idx,
                int value_byte_length,
                int batch_size,
                int items_per_split)
            {
                label_data_.resize(batch_size * items_per_split * value_byte_length);
                key_data_.resize(batch_size * items_per_split);

                batch_idx_ = batch_idx;
                split_idx_ = split_idx;
                value_byte_length_ = value_byte_length;
                items_per_batch_ = batch_size;
                items_per_split_ = items_per_split;
            }

            std::vector<u8> label_data_;
            std::vector<Item> key_data_;

            std::unique_ptr<std::atomic_bool[]> has_item_;
            // the index of this region
            int batch_idx_, split_idx_;

            // the number of bytes that each label is
            int value_byte_length_;

            // the number of cuckoo slots that this regions spans.
            int items_per_batch_;

            // the number of items that are in a split. 
            int items_per_split_;

            oc::span<seal::Plaintext> batch_random_symm_poly_;

            std::vector<seal::Plaintext> batched_label_coeffs_;

            std::vector<FFieldArray> debug_label_coeffs_;
            std::vector<FFieldArray> debug_sym_block_;

            /**
            Computes the symmetric polynomials for the specified split and the specified batch in sender's database.
            One symmetric polynomial is computed for one sub-bin (because a bin is separated into splits).
            Input sub-bin: (a_1, a_2, ..., a_n)
            Output polynomial terms: (1, \sum_i a_i, \sum_{i,j} a_i*a_j, ...).
            */
            void symmetric_polys(
                SenderThreadContext &th_context,
                MatrixView<_ffield_array_elt_t> symm_block,
                int encoding_bit_length,
                const FFieldArray &neg_null_element);

            /**
            Computes the randomized symmetric polynomials for the specified split and the specified batch in sender's database. Basically, it
            multiplies each term in a symmetric polynomial with the same random number. Different symmetric polynomials are multiplied with
            different random numbers.

            @see symmetric_polys for computing symmetric polynomials.
            */
            void randomized_symmetric_polys(
                SenderThreadContext &th_context,
                MatrixView<_ffield_array_elt_t> symm_block,
                int encoding_bit_length,
                FFieldArray &neg_null_element);

            Position try_aquire_position(int cuckoo_loc, oc::PRNG& prng);

            void batch_interpolate(
                SenderThreadContext &th_context,
                std::shared_ptr<seal::SEALContext> seal_context,
                std::shared_ptr<seal::Evaluator> evaluator,
                std::shared_ptr<seal::BatchEncoder> batch_encoder,
                std::shared_ptr<FFieldFastBatchEncoder> ex_batch_encoder,
                DBInterpolationCache &cache,
                const PSIParams &params);

            void check(const Position& pos);

            bool has_item(const Position& pos)
            {
#ifndef NDEBUG
                check(pos);
#endif
                return has_item_.get()[pos.batch_offset * items_per_split_ + pos.split_offset];
            }

            Item& get_key(const Position& pos)
            {
#ifndef NDEBUG
                check(pos);
#endif
                return key_data_[pos.batch_offset * items_per_split_ + pos.split_offset];
            }

            u8* get_label(const Position& pos)
            {
#ifndef NDEBUG
                check(pos);
#endif

                return &label_data_[(pos.batch_offset * items_per_split_ + pos.split_offset) * value_byte_length_];
            }

            u64 get_key_u64(const Position& pos)
            {
                auto& i = get_key(pos);
                return *(u64*)&i;
            }

            u64 get_label_u64(const Position& pos)
            {
                auto l = get_label(pos);
                u64 r = 0;
                memcpy(&r, l, value_byte_length_);
                return r;
            }

            void clear();
        };

        class SenderDB
        {
        public:
            SenderDB(const PSIParams &params, 
                std::shared_ptr<seal::SEALContext> &seal_context,
                std::vector<std::shared_ptr<FField> > &ex_field);

            /**
            Clears sender's database and set all entries to sender's null item.
            */
            void clear_db();

            /**
            Sets the sender's database by hashing the data items with all hash functions.
            */
            void set_data(oc::span<const Item> keys, int thread_count);
            void set_data(oc::span<const Item> keys, MatrixView<u8> values, int thread_count);


            /**
            Adds the data items to sender's database.
            */
            void add_data(oc::span<const Item> keys, int thread_count);
            void add_data(oc::span<const Item> keys, MatrixView<u8> values, int thread_count);

            /**
            Adds one item to sender's database.
            */
            void add_data(const Item &item, int thread_count);

            /**
            Deletes the data items in the sender's database. Items are ignored if they don't exist in the database.
            */
            //void delete_data(oc::span<const Item> data);

            /**
            Deletes one item in sender's database. The item is ignored if it doesn't exist in the database.
            */
            //void delete_data(const Item &item);

            //void save(std::ostream &stream) const;

            //void load(std::istream &stream);

            /**
            Batches the randomized symmetric polynonmials for the specified split and the specified batch in sender's database.

            @see randomized_symmetric_polys for computing randomized symmetric polynomials.
            */
            void batched_randomized_symmetric_polys(
                SenderThreadContext &th_context,
                std::shared_ptr<seal::Evaluator> evaluator, 
                std::shared_ptr<seal::BatchEncoder> batch_encoder,
                std::shared_ptr<FFieldFastBatchEncoder> ex_batch_encoder,
                int thread_count);

            void batched_interpolate_polys(
                SenderThreadContext& th_context,
                int thread_count,
                std::shared_ptr<seal::Evaluator> evaluator,
                std::shared_ptr<seal::BatchEncoder> batch_encoder,
                std::shared_ptr<FFieldFastBatchEncoder> ex_batch_encoder
                );

            //Item& get_key(u64 cuckoo_index, u64 position_idx) {
            //    return keys_(position_idx, cuckoo_index);
            //}

            //DBBlock& get_associated_block(u64 cuckoo_idx, u64 position)
            //{
            //    return db_blocks_(cuckoo_idx / params_.batch_size(), position / params_.split_size());
            //}
            //u8* get_value(u64 cuckoo_index, u64 position_idx) 
            //{
            //    auto idx = params_.sender_bin_size() * cuckoo_index + position_idx;
            //    return values_ptr_.get()  + idx * params_.get_label_bit_count;
            //}

            //const Item& get_key(u64 cuckoo_index, u64 position_idx) const {
            //    return keys_(position_idx, cuckoo_index);
            //}
            //const u8* get_value(u64 cuckoo_index, u64 position_idx) const {
            //    auto idx = params_.sender_bin_size() * cuckoo_index + position_idx;
            //    return values_ptr_.get() + idx * params_.get_label_bit_count;
            //}

            DBBlock& get_block(int batch, int split)
            {
                return db_blocks_(batch, split);
            }

        private:
            PSIParams params_;
            std::shared_ptr<seal::SEALContext> seal_context_;
            std::vector<std::shared_ptr<FField> > ex_field_;
            FFieldArray null_element_;
            FFieldArray neg_null_element_;
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

            /* The ExField encoding of the sender null value. */

            /* 
            B x m, where B is sender's bin size, m is table size.
            This is actually a rotated view of the DB. We store it in this
            view so that multi-threading is more efficient for accessing data, 
            i.e., one thread will take care of several continuous complete rows. 
            */
            Matrix<DBBlock> db_blocks_;
            //std::vector<DBRegion> regions_;
            //std::shared_ptr<u8[]> values_ptr_;

            

            /* 
            Thread safe function to insert an item into the bin 
            index by cockooIndex. The PRNG and be any PRNG.  
            */
            std::pair<DBBlock*, DBBlock::Position> aquire_db_position(int cockooIndex, oc::PRNG& prng);
            
            /* 
            Returns true if the position'th slot within the bin at cockooIndex 
            currently has an item. */
            //bool has_item(int cockooIndex, int position);

            oc::PRNG prng_;
        };
    }
}
