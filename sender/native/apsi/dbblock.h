// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <unordered_set>
#include <vector>

// APSI
#include "apsi/ffield/ffield_batch_encoder.h"
#include "apsi/item.h"
#include "apsi/senderthreadcontext.h"

// SEAL
#include "seal/context.h"
#include "seal/evaluator.h"
#include "seal/plaintext.h"

namespace apsi
{
    namespace sender
    {
        struct DBInterpolationCache
        {
            DBInterpolationCache(FField field, int batch_size, int items_per_split, int value_byte_count);

            std::vector<std::vector<FFieldArray>> div_diff_temp;
            std::vector<FFieldArray> coeff_temp, x_temp, y_temp;
            std::unordered_set<std::uint64_t> key_set;
            std::vector<std::uint64_t> temp_vec;
        }; // struct DBInterpolationCache

        /**
        Represents a specific batch/split and stores the associated data.
        */
        struct DBBlock
        {
            struct Position
            {
                std::int64_t batch_offset;
                std::int64_t split_offset = -1;

                bool is_initialized() const
                {
                    return split_offset != -1;
                }
            }; // struct Position

            void init(std::int64_t batch_idx, std::int64_t split_idx, std::int64_t value_byte_length, std::int64_t batch_size, std::int64_t items_per_split)
            {
                label_data_.resize(static_cast<size_t>(batch_size * items_per_split * value_byte_length));
                key_data_.resize(static_cast<size_t>(batch_size * items_per_split));

                batch_idx_ = batch_idx;
                split_idx_ = split_idx;
                value_byte_length_ = value_byte_length;
                items_per_batch_ = batch_size;
                items_per_split_ = items_per_split;
            }

            std::vector<unsigned char> label_data_;
            std::vector<Item> key_data_;

            std::unique_ptr<std::atomic_bool[]> has_item_;
            // the index of this region
            std::int64_t batch_idx_, split_idx_;

            // the number of bytes that each label is
            std::int64_t value_byte_length_;

            // the number of cuckoo slots that this regions spans.
            std::int64_t items_per_batch_;

            // the number of items that are in a split.
            std::int64_t items_per_split_;

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
                SenderThreadContext &th_context, int encoding_bit_length, const FFieldElt &neg_null_element);

            Position try_acquire_position_after_oprf(int bin_idx);

            void batch_interpolate(
                SenderThreadContext &th_context, std::shared_ptr<seal::SEALContext> seal_context,
                const std::unique_ptr<seal::Evaluator> &evaluator,
                const std::unique_ptr<FFieldBatchEncoder> &batch_encoder, DBInterpolationCache &cache,
                const PSIParams &params);

            void check(const Position &pos);

            bool has_item(const Position &pos)
            {
#ifndef NDEBUG
                check(pos);
#endif
                return has_item_.get()[pos.batch_offset * items_per_split_ + pos.split_offset];
            }

            Item &get_key(const Position &pos)
            {
#ifndef NDEBUG
                check(pos);
#endif
                return key_data_[static_cast<size_t>(pos.batch_offset * items_per_split_ + pos.split_offset)];
            }

            unsigned char *get_label(const Position &pos)
            {
#ifndef NDEBUG
                check(pos);
#endif

                return &label_data_[static_cast<size_t>(
                    (pos.batch_offset * items_per_split_ + pos.split_offset) * value_byte_length_)];
            }

            std::uint64_t get_key_uint64(const Position &pos)
            {
                auto &i = get_key(pos);
                return *(std::uint64_t *)&i;
            }

            std::uint64_t get_label_uint64(const Position &pos)
            {
                auto l = get_label(pos);
                std::uint64_t r = 0;
                memcpy(&r, l, static_cast<size_t>(value_byte_length_));
                return r;
            }

            void clear();
        }; // struct DBBlock
    }      // namespace sender
} // namespace apsi
