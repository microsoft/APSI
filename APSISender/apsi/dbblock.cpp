// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <memory>

// APSI
#include "apsi/dbblock.h"
#include "apsi/tools/prng.h"
#include "apsi/tools/interpolate.h"
#include "apsi/logging/log.h"

// SEAL
#include <seal/util/uintarithsmallmod.h>

using namespace std;
using namespace apsi;
using namespace apsi::sender;
using namespace apsi::tools;
using namespace apsi::logging;
using namespace seal;
using namespace seal::util;

void DBBlock::clear()
{
    auto ss = key_data_.size();
    has_item_ = make_unique<atomic_bool[]>(ss);

    // Make sure all entries are false
    for (int i = 0; i < ss; i++)
    {
        has_item_[i] = false;
    }
}

DBBlock::Position DBBlock::try_aquire_position(int bin_idx, PRNG& prng)
{
    if (bin_idx >= items_per_batch_)
    {
        throw runtime_error("bin_idx should be smaller than items_per_batch");
    }

    int idx = 0;
    auto start = bin_idx * items_per_split_;
    auto end = (bin_idx + 1) * items_per_split_;

    // For 100 tries, guess a bin location can try to insert item there
    for (int i = 0; i < 100; i++)
    {
        idx = prng.get<apsi::u32>() % items_per_split_;

        bool exp = false;
        if (has_item_[start + idx].compare_exchange_strong(exp, true))
        {
            return { bin_idx, idx };
        }
    }

    // If still failed, try to do linear scan
    for (int i = 0; i < items_per_split_; ++i)
    {
        bool exp = false;
        if (has_item_[start + idx].compare_exchange_strong(exp, true))
        {
            // Great, found an empty location and have marked it as mine
            return { bin_idx, idx };
        }

        idx = (idx + 1) % items_per_split_;
    }

    return {};
}

DBBlock::Position DBBlock::try_aquire_position_after_oprf(int bin_idx)
{
    if (bin_idx >= items_per_batch_)
    {
        throw runtime_error("bin_idx should be smaller than items_per_batch");
    }

    int idx = 0;
    auto start = bin_idx * items_per_split_;
    auto end = (bin_idx + 1) * items_per_split_;

    // If still failed, try to do linear scan
    for (int i = 0; i < items_per_split_; ++i)
    {
        bool exp = false;
        if (has_item_[start + idx].compare_exchange_strong(exp, true))
        {
            // Great, found an empty location and have marked it as mine
            return { bin_idx, idx };
        }

        idx = (idx + 1) % items_per_split_;
    }

    return {};
}

void DBBlock::check(const Position & pos)
{
    if (!pos.is_initialized() ||
        pos.batch_offset >= items_per_batch_ ||
        pos.split_offset >= items_per_split_)
    {
        stringstream ss;
        ss
            << !pos.is_initialized() << "\n"
            << pos.batch_offset << " >= " << items_per_batch_ << "\n"
            << pos.split_offset << " >= " << items_per_split_;
        Log::error(ss.str().c_str());
        throw std::runtime_error("bad index");
    }
}

void DBBlock::symmetric_polys(
    SenderThreadContext &th_context,
    MatrixView<_ffield_elt_coeff_t> symm_block,
    int encoding_bit_length,
    const FFieldElt &neg_null_element)
{
    i64 split_size = items_per_split_;
    i64 batch_size = items_per_batch_;
    auto num_rows = batch_size;
    auto field = th_context.field();

    auto ch = field.ch();
    auto d = field.d();

    Position pos;
    for (pos.batch_offset = 0; pos.batch_offset < num_rows; pos.batch_offset++)
    {
        FFieldElt temp11(field);
        FFieldElt temp2(field);
        FFieldElt *temp1;

        // Set symm_block[pos.batch_offset, split_size] to 1
        fill_n(symm_block(pos.batch_offset, split_size), d, 1);

        for (pos.split_offset = split_size - 1; pos.split_offset >= 0; pos.split_offset--)
        {
            if (!has_item(pos))
            {
                temp1 = const_cast<FFieldElt*>(&neg_null_element);
            }
            else
            {
                get_key(pos).to_exfield_element(temp11, encoding_bit_length);

                temp1 = &temp11;
                temp1->neg();
            }

            auto symm_block_ptr = symm_block(pos.batch_offset, pos.split_offset + 1);

            transform(symm_block_ptr, symm_block_ptr + d,
                temp1->data(),
                symm_block_ptr - d,
                [&ch](auto a, auto b) { return multiply_uint_uint_mod(a, b, ch); });

            for (i64 k = pos.split_offset + 1; k < split_size; k++, symm_block_ptr += d)
            {
                transform(temp1->data(), temp1->data() + d,
                    symm_block_ptr + d,
                    temp2.data(),
                    [&ch](auto a, auto b) { return multiply_uint_uint_mod(a, b, ch); });

                transform(symm_block_ptr, symm_block_ptr + d,
                    temp2.data(),
                    symm_block_ptr,
                    [&ch](auto a, auto b) { return add_uint_uint_mod(a, b, ch); });
            }
        }
    }
}

void DBBlock::randomized_symmetric_polys(
    SenderThreadContext &th_context,
    MatrixView<_ffield_elt_coeff_t> symm_block,
    int encoding_bit_length,
    const FFieldElt &neg_null_element)
{
    i64 split_size_plus_one = items_per_split_ + 1;
    symmetric_polys(th_context, symm_block, encoding_bit_length, neg_null_element);

    auto num_rows = items_per_batch_;
    PRNG &prng = th_context.prng();

    FFieldArray r(symm_block.rows(), th_context.field());
    r.set_random_nonzero(prng);

    auto ch = th_context.field().ch();
    auto d = th_context.field().d();
    auto symm_block_ptr = symm_block.data();
    for (i64 i = 0; i < num_rows; i++)
    {
        for (i64 j = 0; j < split_size_plus_one; j++, symm_block_ptr += d)
        {
            transform(symm_block_ptr, symm_block_ptr + d,
                r.data(static_cast<size_t>(i)),
                symm_block_ptr,
                [&ch](auto a, auto b) { return multiply_uint_uint_mod(a, b, ch); });
        }
    }
}

void DBBlock::batch_interpolate(
    SenderThreadContext &th_context,
    shared_ptr<SEALContext> seal_context,
    shared_ptr<Evaluator> evaluator,
    shared_ptr<FFieldFastBatchEncoder> ex_batch_encoder,
    DBInterpolationCache& cache,
    const PSIParams& params)
{
    auto mod = params.get_seal_params().encryption_params.plain_modulus().value();
    MemoryPoolHandle local_pool = th_context.pool();
    Position pos;

    for (pos.batch_offset = 0; pos.batch_offset < items_per_batch_; ++pos.batch_offset)
    {
        FFieldElt temp(ex_batch_encoder->field());
        FFieldArray& x = cache.x_temp[pos.batch_offset];
        FFieldArray& y = cache.y_temp[pos.batch_offset];

        int size = 0;
        for (pos.split_offset = 0; pos.split_offset < items_per_split_; ++pos.split_offset)
        {
            if (has_item(pos))
            {


                auto& key_item = get_key(pos);

                temp.encode(gsl::span<u64>{key_item.get_value()}, params.get_label_bit_count());
                x.set(size, temp);


                auto src = get_label(pos);
                temp.encode(gsl::span<u8>{src, value_byte_length_}, params.get_label_bit_count());
                y.set(size, temp);

                ++size;
            }
        }


        bool empty_row = (size == 0); 

 
        // pad the points to have max degree (split_size)
        // with (x,x) points where x is unique.
        cache.key_set.clear();

        for (int i = 0; i < size; ++i)
        {
            auto r = cache.key_set.emplace(x.get_coeff_of(i, 0));
        }

        cache.temp_vec[0] = 0;
        while (size != items_per_split_)
        {
            if (cache.temp_vec[0] >= mod)
            {
                std::cout << cache.temp_vec[0] << " >= " << mod;
                throw std::runtime_error("");
            }

            if (cache.key_set.find(cache.temp_vec[0]) == cache.key_set.end())
            {
                temp.encode(gsl::span<u64>{cache.temp_vec}, params.get_label_bit_count());

                x.set(size, temp);
                y.set(size, temp);
                ++size;
            }

            ++cache.temp_vec[0];
        }


        ffield_newton_interpolate_poly(
            x, y,
            // We don't use the cache for divided differences.
            // cache.div_diff_temp[pos.batch_offset],
            cache.coeff_temp[pos.batch_offset]);
    }

    batched_label_coeffs_.resize(items_per_split_);

    // We assume there are all the same
    auto degree = th_context.field().d();
    FFieldArray temp_array(ex_batch_encoder->create_array());
    for (int s = 0; s < items_per_split_; s++)
    {
        Plaintext &batched_coeff = batched_label_coeffs_[s];

        // transpose the coeffs into temp_array
        for (int b = 0; b < items_per_batch_; b++)
        {
            for (unsigned c = 0; c < degree; ++c)
                temp_array.set_coeff_of(b, c, cache.coeff_temp[b].get_coeff_of(s, c));
        }

        auto capacity = static_cast<size_t>(params.encryption_params().coeff_modulus().size() *
            params.encryption_params().poly_modulus_degree());
        batched_coeff.reserve(capacity);

        ex_batch_encoder->compose(temp_array, batched_coeff);

        // Log::debug("s = %i, is_zero = %i", s, batched_coeff.is_zero()); 


        Position temppos;
        temppos.split_offset = s;

        // Debug
        for (int j = 0; j < items_per_batch_; j++) {
            temppos.batch_offset = j; 
            if (has_item(temppos) && split_idx_ == 1) {
                Log::debug("real item at batch offset %i and split offset %i", j, s); 
                Log::debug("label for this item is 0x%llx", get_label_u64(temppos));
            }
        }
        cout << endl;



        evaluator->transform_to_ntt_inplace(batched_coeff, seal_context->first_parms_id());
    }
}

DBInterpolationCache::DBInterpolationCache(
    std::shared_ptr<FFieldFastBatchEncoder> ex_batch_encoder,
    int items_per_batch_,
    int items_per_split_,
    int value_byte_length_)
{
    coeff_temp.reserve(items_per_batch_);
    x_temp.reserve(items_per_batch_);
    y_temp.reserve(items_per_batch_);

    for (u64 i = 0; i < items_per_batch_; ++i)
    {
        coeff_temp.emplace_back(items_per_split_, ex_batch_encoder->field());
        x_temp.emplace_back(items_per_split_, ex_batch_encoder->field());
        y_temp.emplace_back(items_per_split_, ex_batch_encoder->field());
    }

    temp_vec.resize((value_byte_length_ + sizeof(u64)) / sizeof(u64), 0);
    key_set.reserve(items_per_split_);
}
