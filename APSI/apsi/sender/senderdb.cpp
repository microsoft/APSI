// STD
#include <fstream>
#include <algorithm>
#include <memory>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <iomanip>

// APSI
#include "apsi/sender/senderdb.h"
#include "apsi/apsidefines.h"
#include "apsi/tools/interpolate.h"
#include "apsi/ffield/ffield_array.h"
#include "apsi/tools/ec_utils.h"
#include "apsi/tools/prng.h"
#include "apsi/tools/utils.h"

// SEAL
#include "seal/evaluator.h"
#include "seal/batchencoder.h"
#include "seal/util/uintcore.h"

// FourQ
#include "FourQ_api.h"

// crypto++
#include "cryptopp/sha3.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace apsi;
using namespace apsi::tools;
using namespace apsi::sender;


SenderDB::SenderDB(const PSIParams &params, 
    shared_ptr<SEALContext> &seal_context, 
    vector<shared_ptr<FField> > &ex_field) :
    params_(params),
    seal_context_(seal_context),
    ex_field_(ex_field),
    null_element_(ex_field_),
    neg_null_element_(ex_field_),
    next_locs_(params.table_size(), 0),
    batch_random_symm_poly_storage_(params.split_count() * params.batch_count() * (params.split_size() + 1))
{
    for (auto &plain : batch_random_symm_poly_storage_)
    {
        // Reserve memory for ciphertext size plaintexts (NTT transformed mod q)
        plain.reserve(static_cast<int>(params_.encryption_params().coeff_modulus().size() *
            params_.encryption_params().poly_modulus_degree()));
    }

#ifdef USE_SECURE_SEED
    prng_.set_seed(sys_random_seed());
#else
    TODO("***************** INSECURE *****************, define USE_SECURE_SEED to fix");
    prng_.set_seed(one_block, /* buffer_size */ 256);
#endif

    // Set null value for sender: 1111...1110 (128 bits)
    // Receiver's null value comes from the Cuckoo class: 1111...1111
    sender_null_item_[0] = ~1;
    sender_null_item_[1] = ~0;

    // What is the actual length of strings stored in the hash table
    encoding_bit_length_ = params.item_bit_count();

    // Create the null ExFieldElement (note: encoding truncation affects high bits)
    for(auto i = 0; i < ex_field_.size(); i++)
    {
        null_element_.set(i, sender_null_item_.to_exfield_element(ex_field_[i], encoding_bit_length_));
    }
    neg_null_element_ = -null_element_;

    int batch_size = params_.batch_size();
    int split_size = params_.split_size();
    int byte_length = static_cast<int>(round_up_to(params_.get_label_bit_count(), 8) / 8);
    int nb = params_.batch_count();
    int ns = params_.split_count();
    db_blocks_.resize(nb, ns);

    for (int b_idx = 0; b_idx < nb; b_idx++)
    {
        for (int s_idx = 0; s_idx < ns; s_idx++)
        {
            db_blocks_(b_idx, s_idx).init(
                b_idx, s_idx,
                byte_length,
                batch_size,
                split_size);
        }
    }
}

void SenderDB::clear_db()
{
    for (auto& block : db_blocks_)
        block.clear();
}

void SenderDB::set_data(gsl::span<const Item> data, int thread_count)
{
    set_data(data, {}, thread_count);
}

void SenderDB::set_data(gsl::span<const Item> data, MatrixView<u8> vals, int thread_count)
{
    StopwatchScope set_scope(sender_stop_watch, "SenderDB::set_data");
    clear_db();
    add_data(data, vals, thread_count);
}

std::string hexStr(u8* data, u64 size)
{
    std::stringstream ss;

    ss << '{';
    for (u64 i = 0; i < size; ++i)
    {
        ss << ' ' << std::setw(2) << std::hex << std::setfill('0') << int(data[i]);
    }
    ss << '}';
    return ss.str();
}

void SenderDB::add_data(gsl::span<const Item> data, MatrixView<u8> values, int thread_count)
{
    if (values.stride() != params_.get_label_byte_count())
        throw std::invalid_argument("unexpacted label length");

    vector<thread> thrds(thread_count);
    for (int t = 0; t < thrds.size(); t++)
    {
        auto seed = prng_.get<block>();
        thrds[t] = thread([&, t, seed]()
        {
            PRNG prng(seed, /* buffer_size */ 256);
            auto start = t * data.size() / thrds.size();
            auto end = (t + 1) * data.size() / thrds.size();

            vector<u8> buff((sizeof(digit_t) * NWORDS_ORDER) - 1);
            PRNG pp(cc_block);
            digit_t key[NWORDS_ORDER];
            random_fourq(key, pp);

            vector<cuckoo::LocFunc> normal_loc_func(params_.hash_func_count());

            for (int i = 0; i < normal_loc_func.size(); i++)
            {
                normal_loc_func[i] = cuckoo::LocFunc(params_.log_table_size(), params_.hash_func_seed() + i);
            }

            for (size_t i = start; i < end; i++)
            {
                // Do we do OPRF for Sender's security?
                if (params_.use_oprf())
                {
                    // Compute EC PRF first for data
                    PRNG p(data[i], /* buffer_size */ 8);
                    digit_t a[NWORDS_ORDER];
                    random_fourq(a, p);
                    Montgomery_multiply_mod_order(a, key, a);
                    eccoord_to_buffer(a, buff.data());

                    // Then compress with SHA3
                    CryptoPP::SHA3_256 sha;
                    sha.Update(buff.data(), buff.size());
                    sha.TruncatedFinal(reinterpret_cast<CryptoPP::byte*>(const_cast<Item*>(&data[i])), sizeof(block));
                }

                std::array<u64, 3> locs;
                std::array<Item, 3> keys;
                std::array<bool, 3> skip{ false, false, false };

                // Compute bin locations
                locs[0] = normal_loc_func[0].location(data[i]);
                locs[1] = normal_loc_func[1].location(data[i]);
                locs[2] = normal_loc_func[2].location(data[i]);
                keys[0] = keys[1] = keys[2] = data[i];
                skip[1] = locs[0] == locs[1];
                skip[2] = locs[0] == locs[2] || locs[1] == locs[2];

                // Claim an empty location in each matching bin
                for (int j = 0; j < params_.hash_func_count(); j++)
                {
                    if (skip[j] == false)
                    {

                        // Lock-free thread-safe bin position search
                        auto block_pos = aquire_db_position(static_cast<int>(locs[j]), prng);
                        auto& db_block = *block_pos.first;
                        auto pos = block_pos.second;


                        db_block.get_key(pos) = keys[j];

                        if (params_.get_label_bit_count())
                        {
                            auto dest = db_block.get_label(pos);
                            memcpy(dest, values[i].data(), params_.get_label_byte_count());
                        }
                    }
                }
            };
        });
    }

    for (auto &t : thrds)
    {
        t.join();
    }

    bool validate = false;
    if (validate)
    {

        vector<cuckoo::LocFunc> normal_loc_func(params_.hash_func_count());

        for (int i = 0; i < normal_loc_func.size(); i++)
        {
            normal_loc_func[i] = cuckoo::LocFunc(params_.log_table_size(), params_.hash_func_seed() + i);
        }


        for (i64 i = 0; i < data.size(); ++i)
        {

            // Claim an emply location in each matching bin
            for (int j = 0; j < params_.hash_func_count(); j++)
            {
                Item key;
                u64 cuckoo_loc;

                // Compute bin locations
                cuckoo_loc = normal_loc_func[j].location(data[i]);
                key = data[i];

                // Lock-free thread-safe bin position search
                DBBlock::Position pos;
                auto batch_idx = cuckoo_loc / params_.batch_size();
                pos.batch_offset = cuckoo_loc % params_.batch_size();

                auto count = 0;
                for (u64 j = 0; j < db_blocks_.columns(); ++j)
                {
                    auto& blk = db_blocks_(batch_idx, j);
                    ;
                    for (pos.split_offset = 0;
                        pos.split_offset < blk.items_per_split_;
                        ++pos.split_offset)
                    {
                        if (blk.has_item(pos) &&
                            blk.get_key(pos) == key)
                        {
                            ++count;
                        }
                    }
                }

                if (count != 1)
                    throw std::runtime_error("");
            }
        }

    }
}

void SenderDB::add_data(gsl::span<const Item> data, int thread_count)
{
    add_data(data, {}, thread_count);
}

std::pair<DBBlock*, DBBlock::Position>
    SenderDB::aquire_db_position(int cuckoo_loc, PRNG &prng)
{
    auto batch_idx = cuckoo_loc / params_.batch_size();
    auto batch_offset = cuckoo_loc % params_.batch_size();

    auto s_idx = prng.get<u32>() % db_blocks_.stride();
    for (int i = 0; i < db_blocks_.stride(); ++i)
    {
        auto pos = db_blocks_(batch_idx, s_idx).try_aquire_position(batch_offset, prng);
        if (pos)
        {
            return { &db_blocks_(batch_idx, s_idx) , pos };
        }

        s_idx = (s_idx + 1) % db_blocks_.stride();
    }

    // Throw an error because bin overflowed
    throw runtime_error("simple hashing failed due to bin overflow");
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
    if (!pos ||
        pos.batch_offset >= items_per_batch_ ||
        pos.split_offset >= items_per_split_)
    {
        std::cout
            << !pos << "\n"
            << pos.batch_offset << " >= " << items_per_batch_ << "\n"
            << pos.split_offset << " >= " << items_per_split_ << std::endl;
        throw std::runtime_error("bad index");
    }
}

void SenderDB::add_data(const Item &item, int thread_count)
{
    add_data(vector<Item>(1, item), thread_count);
}

void DBBlock::symmetric_polys(
    SenderThreadContext &th_context,
    MatrixView<_ffield_array_elt_t> symm_block,
    int encoding_bit_length,
    const FFieldArray &neg_null_element)
{
    int split_size = items_per_split_;
    int split_size_plus_one = split_size + 1;
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
    int batch_size = items_per_batch_;
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

void SenderDB::batched_randomized_symmetric_polys(
    SenderThreadContext &context,
    int start_block,
    int end_block,
    shared_ptr<Evaluator> evaluator,
    shared_ptr<FFieldFastBatchEncoder> ex_batch_encoder)
{
    // Get the symmetric block
    auto symm_block = context.symm_block();

    int table_size = params_.table_size(),
        split_size = params_.split_size(),
        batch_size = params_.batch_size(),
        split_size_plus_one = split_size + 1;

    FFieldArray batch_vector(context.exfield());
    vector<uint64_t> integer_batch_vector(batch_size);

    // Data in batch-split table is stored in "batch-major order"
    auto indexer = [splitStep = params_.batch_count() * split_size_plus_one,
        batchStep = split_size_plus_one](int splitIdx, int batchIdx, int i)
    {
        return splitIdx * splitStep + batchIdx * batchStep + i;
    };

    MemoryPoolHandle local_pool = context.pool();

    for (int next_block = start_block; next_block < end_block; next_block++)
    {
        int split = next_block / params_.batch_count();
        int batch = next_block % params_.batch_count();

        int split_start = split * split_size,
            batch_start = batch * batch_size,
            batch_end = (batch_start + batch_size < table_size ? (batch_start + batch_size) : table_size);

        auto &block = db_blocks_.data()[next_block];
        block.randomized_symmetric_polys(context, symm_block, encoding_bit_length_, neg_null_element_);
        block.batch_random_symm_poly_ = { &batch_random_symm_poly_storage_[indexer(split, batch, 0)] , split_size_plus_one };

        if (params_.debug())
        {
            block.debug_sym_block_.clear();
            block.debug_sym_block_.reserve(split_size_plus_one);
        }

        for (int i = 0; i < split_size_plus_one; i++)
        {
            Plaintext &poly = block.batch_random_symm_poly_[i];

            // This branch works even if ex_field_ is an integer field, but it is slower than normal batching.
            for (int k = 0; batch_start + k < batch_end; k++)
            {
                fq_nmod_set(batch_vector.data() + k, &symm_block(k, i), batch_vector.field(k)->ctx());
            }
            ex_batch_encoder->compose(batch_vector, poly);
            evaluator->transform_to_ntt(poly, seal_context_->first_parms_id(), local_pool);

            if (params_.debug())
            {
                block.debug_sym_block_.push_back(batch_vector);
            }
        }

        context.inc_randomized_polys();
    }
}

void SenderDB::batched_interpolate_polys(
    SenderThreadContext &th_context,
    int start_block,
    int end_block,
    shared_ptr<Evaluator> evaluator,
    shared_ptr<FFieldFastBatchEncoder> ex_batch_encoder)
{
    auto &mod = params_.encryption_params().plain_modulus();

    DBInterpolationCache cache(ex_batch_encoder, params_.batch_size(), params_.split_size(), params_.get_label_byte_count());
    // minus 1 to be safe.
    auto coeffBitCount = seal::util::get_significant_bit_count(mod.value()) - 1;
    u64 degree = 1;
    if (ex_batch_encoder)
    {
        degree = ex_batch_encoder->d();
    }

    if (params_.get_label_bit_count() >= coeffBitCount * degree)
    {
        throw std::runtime_error("labels are too large for exfield.");
    }

    if (params_.get_label_bit_count() >= 64)
    {
        throw std::runtime_error("labels are too large u64 interpolation.");
    }

    for (int bIdx = start_block; bIdx < end_block; bIdx++)
    {
        auto& block = db_blocks_(bIdx);
        block.batch_interpolate(th_context, seal_context_, evaluator, ex_batch_encoder, cache, params_);
        th_context.inc_interpolate_polys();
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


void test_interp_poly(FFieldArray& x, FFieldArray& y,
    FFieldArray& poly,
    int size,
    int bit_count)
{
    for (u64 i = 0; i < x.size(); ++i)
    {
        auto sum = poly.get(0);
        auto xx = x.get(i);
        for (u64 j = 1; j < poly.size(); ++j)
        {
            sum += xx * poly.get(j);
            xx = xx * x.get(i);
        }

        if (sum != y.get(i))
        {
            throw std::runtime_error("bad interpolation");
        }

        if (i < size)
        {
            std::vector<u8> buff((bit_count + 7) / 8);
            x.get(i).decode(gsl::span<u8>{buff}, bit_count);
            std::cout << "x=" << hexStr(buff.data(), buff.size()) << " -> ";

            sum.decode(gsl::span<u8>{buff}, bit_count);
            std::cout << hexStr(buff.data(), buff.size()) << std::endl;
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

    if (params.use_low_degree_poly())
        throw std::runtime_error("not impl");

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
                temp.encode(gsl::span<u64>{key_item.value_}, params.get_label_bit_count());
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
        batched_coeff.reserve(capacity, local_pool);

        ex_batch_encoder->compose(temp_array, batched_coeff);
        evaluator->transform_to_ntt(batched_coeff, seal_context->first_parms_id());
    }
}

std::vector<u64> add_(gsl::span<u64> x, gsl::span<u64> y, const seal::SmallModulus& mod)
{
    std::vector<u64> r(x.size());
    for (int i = 0; i < r.size(); ++i)
    {
        r[i] = x[i] + y[i] % mod.value();
    }

    return r;
}

u64 pow_(u64 x, u64 p, const seal::SmallModulus& mod)
{
    u64 r = 1;
    while (p--)
    {
        r = (r * x) % mod.value();
    }
    return x;
}

std::vector<apsi::u64> debug_eval_term(
    int term,
    MatrixView<u64> coeffs,
    gsl::span<u64> x,
    const seal::SmallModulus& mod)
{
    if (x.size() != coeffs.rows())
        throw std::runtime_error("Size of x should be the same as coeffs.rows");

    std::vector<u64> r(x.size());

    for (int i = 0; i < x.size(); ++i)
    {
        auto xx = pow_(x[i], term, mod);

        r[i] = (xx * coeffs(term, i)) % mod.value();
    }


    return r;
}

void print_poly(int b, MatrixView<u64> polys)
{
    std::cout << "P" << b << "(x) = ";
    for (u64 i = polys.stride(); i != -1; --i)
    {
        std::cout << polys(b, i) << " * x^" << i << " " << (i ? " + " : "");
    }
    std::cout << std::endl;
}
