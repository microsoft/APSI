// APSI
#include "apsi/sender/dbblock.h"
#include "apsi/tools/prng.h"
#include "apsi/tools/interpolate.h"
#include "apsi/logging/log.h"
#include "apsi/ffield/ffield_fast_batch_encoder.h"


using namespace std;
using namespace apsi;
using namespace apsi::sender;
using namespace apsi::tools;
using namespace apsi::logging;
using namespace seal;


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
    MatrixView<_ffield_array_elt_t> symm_block,
    int encoding_bit_length,
    const FFieldArray &neg_null_element)
{
    int split_size = items_per_split_;
    int batch_size = items_per_batch_;
    auto num_rows = batch_size;
    auto &field_vec = th_context.exfield();

    Position pos;
    for (pos.batch_offset = 0; pos.batch_offset < num_rows; pos.batch_offset++)
    {
        FFieldElt temp11(field_vec[pos.batch_offset]);
        FFieldElt temp2(field_vec[pos.batch_offset]);
        FFieldElt *temp1;
        FFieldElt curr_neg_null_element(neg_null_element.get(pos.batch_offset));
        auto &ctx = field_vec[pos.batch_offset]->ctx();
        fq_nmod_one(&symm_block(pos.batch_offset, split_size), field_vec[pos.batch_offset]->ctx());

        for (pos.split_offset = split_size - 1; pos.split_offset >= 0; pos.split_offset--)
        {
            if (!has_item(pos))
            {
                temp1 = &curr_neg_null_element;
            }
            else
            {
                get_key(pos).to_exfield_element(temp11, encoding_bit_length);

                temp1 = &temp11;
                temp1->neg();
            }

            auto symm_block_ptr = &symm_block(pos.batch_offset, pos.split_offset + 1);

            fq_nmod_mul(
                symm_block_ptr - 1,
                symm_block_ptr,
                temp1->data(), ctx);

            for (int k = pos.split_offset + 1; k < split_size; k++, symm_block_ptr++)
            {
                fq_nmod_mul(temp2.data(), temp1->data(), symm_block_ptr + 1, ctx);
                fq_nmod_add(
                    symm_block_ptr,
                    symm_block_ptr,
                    temp2.data(), ctx);
            }
        }
    }
}

void DBBlock::randomized_symmetric_polys(
    SenderThreadContext &th_context,
    MatrixView<_ffield_array_elt_t> symm_block,
    int encoding_bit_length,
    FFieldArray &neg_null_element)
{
    int split_size_plus_one = items_per_split_ + 1;
    symmetric_polys(th_context, symm_block, encoding_bit_length, neg_null_element);

    auto num_rows = items_per_batch_;
    PRNG &prng = th_context.prng();

    FFieldArray r(th_context.exfield());
    r.set_random_nonzero(prng);

    auto symm_block_ptr = symm_block.data();
    for (int i = 0; i < num_rows; i++)
    {
        auto &field_ctx = th_context.exfield()[i]->ctx();
        for (int j = 0; j < split_size_plus_one; j++, symm_block_ptr++)
        {
            fq_nmod_mul(symm_block_ptr, symm_block_ptr, r.data() + i, field_ctx);
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
    auto mod = seal_context->context_data()->parms().plain_modulus().value();
    MemoryPoolHandle local_pool = th_context.pool();
    Position pos;

    for (pos.batch_offset = 0; pos.batch_offset < items_per_batch_; ++pos.batch_offset)
    {
        FFieldElt temp(ex_batch_encoder->field(pos.batch_offset));
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
    unsigned degree = th_context.exfield()[0]->d();
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


        auto capacity = static_cast<Plaintext::size_type>(params.encryption_params().coeff_modulus().size() *
            params.encryption_params().poly_modulus_degree());
        batched_coeff.reserve(capacity);

        ex_batch_encoder->compose(temp_array, batched_coeff);
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
        coeff_temp.emplace_back(ex_batch_encoder->field(i), items_per_split_);
        x_temp.emplace_back(ex_batch_encoder->field(i), items_per_split_);
        y_temp.emplace_back(ex_batch_encoder->field(i), items_per_split_);
    }

    temp_vec.resize((value_byte_length_ + sizeof(u64)) / sizeof(u64), 0);
    key_set.reserve(items_per_split_);
}

