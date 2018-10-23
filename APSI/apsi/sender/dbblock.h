#pragma once

// STD
#include <vector>
#include <memory>
#include <unordered_set>

// APSI
#include "apsi/apsidefines.h"
#include "apsi/item.h"
#include "apsi/sender/senderthreadcontext.h"

// SEAL
#include "seal/plaintext.h"
#include "seal/context.h"
#include "seal/evaluator.h"


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

        /**
        Represents a specific batch/split and stores the associated data.
        */
        struct DBBlock
        {
            struct Position
            {
                int batch_offset;
                int split_offset = -1;

                bool is_initialized() const
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

            gsl::span<seal::Plaintext> batch_random_symm_poly_;

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

            Position try_aquire_position(int cuckoo_loc, apsi::tools::PRNG& prng);

            void batch_interpolate(
                SenderThreadContext &th_context,
                std::shared_ptr<seal::SEALContext> seal_context,
                std::shared_ptr<seal::Evaluator> evaluator,
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
    }
}
