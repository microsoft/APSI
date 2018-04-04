#include <fstream>
#include <algorithm>
#include <memory>
#include <thread>
#include <unordered_map>
#include <unordered_set>


#include "apsi/sender/senderdb.h"
#include "apsi/apsidefines.h"
#include "apsi/tools/interpolate.h"

#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/MatrixView.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Crypto/sha1.h"

#include "seal/evaluator.h"
#include "seal/polycrt.h"
#include "seal/util/uintcore.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace oc;

namespace apsi
{
    namespace sender
    {
        namespace
        {
            void randomize_element(ExFieldElement &element, PRNG &prng)
            {
                const uint64_t characteristic = element.ex_field()->characteristic().value();
                prng.get<uint64_t>(element.pointer(), element.ex_field()->coeff_count() - 1);
                for (int i = 0; i < element.ex_field()->coeff_count() - 1; i++)
                {
                    element[i] %= characteristic;
                }
            }
        }

        SenderDB::SenderDB(const PSIParams &params, shared_ptr<ExField> &ex_field) :
            params_(params),
            encoder_(params.log_table_size(), params.hash_func_count(), params.item_bit_count()),
            global_ex_field_(ex_field),
            //keys_(params.sender_bin_size(), params.table_size()),
            //values_(params.sender_bin_size(), params.table_size()),
            next_locs_(params.table_size(), 0),
            batch_random_symm_polys_(params.split_count() * params.batch_count() * (params.split_size() + 1))
        {
            for (auto &plain : batch_random_symm_polys_)
            {
                // Reserve memory for ciphertext size plaintexts (NTT transformed mod q)
                plain.reserve(params_.encryption_params().coeff_modulus().size() *
                    (params_.encryption_params().poly_modulus().coeff_count()));
            }

#ifdef USE_SECURE_SEED
            prng_.SetSeed(oc::sysRandomSeed());
#else
            TODO("***************** INSECURE *****************, define USE_SECURE_SEED to fix");
            prng_.SetSeed(oc::OneBlock, 256);
#endif

            // Set null value for sender: 1111...1110 (128 bits)
            // Receiver's null value comes from the Cuckoo class: 1111...1111
            sender_null_item_[0] = ~1;
            sender_null_item_[1] = ~0;


            // What is the actual length of strings stored in the hash table
            encoding_bit_length_ = (params.get_cuckoo_mode() == cuckoo::CuckooMode::Normal)
                ? params.item_bit_count() : encoder_.encoding_bit_length_;

            // Create the null ExFieldElement (note: encoding truncation affects high bits)
            null_element_ = sender_null_item_.to_exfield_element(global_ex_field_, encoding_bit_length_);
            neg_null_element_ = ExFieldElement(global_ex_field_);
            global_ex_field_->negate(null_element_, neg_null_element_);


            {
                int batch_size = params_.batch_size();
                int split_size = params_.split_size();
                int byte_length = oc::roundUpTo(params_.get_label_bit_count(), 8) / 8;
                int nb = params_.batch_count();
                int ns = params_.split_count();
                db_blocks_.resize(nb, ns);

                for (u64 b_idx = 0; b_idx < nb; ++b_idx)
                {
                    for (u64 s_idx = 0; s_idx < ns; ++s_idx)
                    {
                        db_blocks_(b_idx, s_idx).init(
                            b_idx, s_idx,
                            byte_length,
                            batch_size,
                            split_size);
                    }
                }
            }
        }

        void SenderDB::clear_db()
        {
            for (auto& block : db_blocks_)
                block.clear();
            //auto ss = params_.sender_bin_size() * params_.table_size();
            //simple_hashing_db_has_item_.reset(new atomic_bool[ss]);

            //// Make sure all entries are false
            //for (int i = 0; i < ss; i++)
            //{
            //    simple_hashing_db_has_item_[i] = false;
            //}
        }

        void SenderDB::set_data(oc::span<const Item> data, int thread_count)
        {
            set_data(data, {}, thread_count);
        }

        void SenderDB::set_data(oc::span<const Item> data, oc::MatrixView<const u8> vals, int thread_count)
        {
            clear_db();
            add_data(data, vals, thread_count);
            stop_watch.set_time_point("Sender add-data");
        }

        void SenderDB::add_data(oc::span<const Item> data, int thread_count)
        {
            add_data(data, {}, thread_count);
        }

        void SenderDB::add_data(oc::span<const Item> data, oc::MatrixView<const u8> values, int thread_count)
        {
            if (values.stride() != 0 && values.stride() != params_.get_value_byte_count())
                throw std::invalid_argument("values.stride()");

            vector<thread> thrds(thread_count);
            for (int t = 0; t < thrds.size(); t++)
            {
                auto seed = prng_.get<oc::block>();
                thrds[t] = thread([&, t, seed]()
                {
                    oc::PRNG prng(seed, 256);
                    auto start = t * data.size() / thrds.size();
                    auto end = (t + 1) * data.size() / thrds.size();

                    EllipticCurve curve(p256k1, prng.get<oc::block>());
                    vector<u8> buff(curve.getGenerator().sizeBytes());
                    PRNG pp(oc::CCBlock);
                    oc::EccNumber key_(curve, pp);

                    vector<cuckoo::LocFunc> normal_loc_func(params_.hash_func_count());
                    vector<cuckoo::PermutationBasedLocFunc> perm_loc_func(params_.hash_func_count());

                    for (int i = 0; i < normal_loc_func.size(); i++)
                    {
                        normal_loc_func[i] = cuckoo::LocFunc(params_.log_table_size(), params_.hash_func_seed() + i);
                        perm_loc_func[i] = cuckoo::PermutationBasedLocFunc(params_.log_table_size(), params_.hash_func_seed() + i);
                    }

                    for (int i = start; i < end; i++)
                    {
                        // Do we do OPRF for Sender's security?
                        if (params_.use_pk_oprf())
                        {
                            static_assert(sizeof(oc::block) == sizeof(Item), LOCATION);

                            // Compute EC PRF first for data
                            oc::PRNG p(static_cast<oc::block&>(data[i]), 8);
                            oc::EccPoint a(curve, p);

                            a *= key_;
                            a.toBytes(buff.data());

                            // Then compress with SHA1
                            oc::SHA1 sha(sizeof(block));
                            sha.Update(buff.data(), buff.size());
                            sha.Final(static_cast<oc::block&>(data[i]));
                        }

                        // Claim an emply location in each matching bin
                        for (int j = 0; j < params_.hash_func_count(); j++)
                        {
                            Item key;
                            u64 cuckoo_loc;
                            if (params_.get_cuckoo_mode() == cuckoo::CuckooMode::Normal)
                            {
                                // Compute bin locations
                                cuckoo_loc = normal_loc_func[j].location(data[i]);
                                key = data[i];
                            }
                            else
                            {
                                // Get the permutation-based Cuckoo location and find position
                                cuckoo_loc = perm_loc_func[j].location(data[i]);
                                key = encoder_.encode(data[i], j, true);
                            }

                            // Lock-free thread-safe bin position search
                            auto block_pos = aquire_db_position(cuckoo_loc, prng);
                            auto& db_block = *block_pos.first;
                            auto pos = block_pos.second;

                            db_block.get_key(pos) = key;
                            //std::cout << "key " << key << " -> block ("
                            //    << db_block.batch_idx_ << ", " << db_block.split_idx_ << ") "
                            //    << " @ " << pos.batch_offset << " " << pos.split_offset << std::endl;

                            if (values.size())
                            {
                                auto dest = db_block.get_label(pos);
                                memcpy(dest, values[i].data(), params_.get_value_byte_count());
                            }
                        }
                    };
                });
            }

            for (auto &t : thrds)
            {
                t.join();
            }
        }

        std::pair<DBBlock*, DBBlock::Position>
            SenderDB::aquire_db_position(int cuckoo_loc, oc::PRNG &prng)
        {
            auto batch_idx = cuckoo_loc / params_.batch_size();


            auto batch_offset = cuckoo_loc % params_.batch_size();

            auto s_idx = prng.get<u32>() % db_blocks_.stride();
            for (int i = 0; i < db_blocks_.stride(); ++i)
            {
                auto pos = db_blocks_(batch_idx, s_idx).try_aquire_position(batch_offset, prng);

                if (pos)
                    return { &db_blocks_(batch_idx, s_idx) , pos };

                s_idx = (s_idx + 1) % db_blocks_.stride();
            }

            // Throw an error because bin overflowed
            throw runtime_error("simple hashing failed due to bin overflow");
        }

        DBBlock::Position DBBlock::try_aquire_position(int bin_idx, oc::PRNG& prng)
        {
            if (bin_idx >= items_per_batch_)
            {
                throw runtime_error(LOCATION);
            }

            int idx = 0;
            auto start = bin_idx * items_per_split_;
            auto end = (bin_idx + 1) * items_per_split_;

            // For 100 tries, guess a bin location can try to insert item there
            for (int i = 0; i < 100; i++)
            {
                idx = prng.get<oc::u32>() % items_per_split_;

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

        //bool SenderDB::has_item(int cuckoo_loc, int position)
        //{
        //    auto s = params_.sender_bin_size();
        //    auto start = cuckoo_loc * s;
        //    return simple_hashing_db_has_item_[start + position];
        //}

        void SenderDB::add_data(const Item &item, int thread_count)
        {
            add_data(vector<Item>(1, item), thread_count);
        }

        //void SenderDB::delete_data(const vector<Item> &data)
        //{
        //    throw runtime_error("not implemented");
        //}
        //void SenderDB::delete_data(const Item &item)
        //{
        //    delete_data(vector<Item>(1, item));
        //}

        void DBBlock::symmetric_polys(
            SenderThreadContext &context,
            MatrixView<ExFieldElement> symm_block,
            int encoding_bit_length,
            seal::util::ExFieldElement& neg_null_element)
        {
            int split_size = items_per_split_;
            int batch_size = items_per_batch_;
            shared_ptr<ExField> &exfield = context.exfield();

            auto num_rows = symm_block.bounds()[0];

            ExFieldElement one(exfield, "1");
            ExFieldElement temp11(exfield), temp2(exfield), *temp1;

            Position pos;

            for (pos.batch_offset = 0; pos.batch_offset < num_rows; ++pos.batch_offset)
            {
                symm_block(pos.batch_offset, split_size) = one;

                for (pos.split_offset = split_size - 1; pos.split_offset >= 0; pos.split_offset--)
                {
                    //auto cuckoo_loc = i;

                    if (!has_item(pos))
                    {
                        temp1 = &neg_null_element;
                    }
                    else
                    {
                        get_key(pos).to_exfield_element(temp11, encoding_bit_length);
                        //ostreamLock(std::cout) << "sender(" << pos.batch_offset << ", " << pos.split_offset<< ") " << get_key(pos) << std::endl;
                        temp1 = &temp11;
                        exfield->negate(*temp1, *temp1);
                    }

                    exfield->multiply(
                        symm_block(pos.batch_offset, pos.split_offset + 1),
                        *temp1,
                        symm_block(pos.batch_offset, pos.split_offset));

                    for (int k = pos.split_offset + 1; k < split_size; k++)
                    {
                        exfield->multiply(
                            symm_block(pos.batch_offset, k + 1),
                            *temp1,
                            temp2);
                        symm_block(pos.batch_offset, k) += temp2;
                    }
                }
            }
        }

        void DBBlock::randomized_symmetric_polys(
            SenderThreadContext &context,
            MatrixView<ExFieldElement> symm_block,
            int encoding_bit_length,
            seal::util::ExFieldElement& neg_null_element)
        {
            int split_size = items_per_split_;
            symmetric_polys(context, symm_block, encoding_bit_length, neg_null_element);

            auto num_rows = symm_block.bounds()[0];
            oc::PRNG &prng = context.prng();

            ExFieldElement r(context.exfield());

            for (int i = 0; i < num_rows; i++)
            {
                // Sample non-zero randomness
                do
                {
                    randomize_element(r, prng);
                } while (r.is_zero());

                for (int j = 0; j < split_size + 1; j++)
                {
                    context.exfield()->multiply(symm_block(i, j), r, symm_block(i, j));
                }
            }
        }

        void DBBlock::clear()
        {
            auto ss = key_data_.size();
            has_item_.reset(new atomic_bool[ss]);

            // Make sure all entries are false
            for (int i = 0; i < ss; i++)
            {
                has_item_[i] = false;
            }
        }

        void SenderDB::batched_randomized_symmetric_polys(SenderThreadContext &context,
            shared_ptr<Evaluator> evaluator, shared_ptr<PolyCRTBuilder> builder, int thread_count)
        {
            // Get the symmetric block
            auto symm_block = context.symm_block();

            // The data is allocated in SenderThreadContext
            vector<ExFieldElement> &batch_vector = context.batch_vector();
            vector<uint64_t> &integer_batch_vector = context.integer_batch_vector();

            int table_size = params_.table_size(),
                split_size = params_.split_size(),
                batch_size = params_.batch_size(),
                split_size_plus_one = params_.split_size() + 1;

            // Data in batch-split table is stored in "batch-major order"
            auto indexer = [splitStep = params_.batch_count() * split_size_plus_one,
                batchStep = split_size_plus_one](int splitIdx, int batchIdx, int i)
            {
                return splitIdx * splitStep + batchIdx * batchStep + i;
            };

            MemoryPoolHandle local_pool = context.pool();
            int start_block = context.id() * db_blocks_.size() / thread_count;
            int end_block = (context.id() + 1) * db_blocks_.size() / thread_count;

            for (int next_block = start_block; next_block < end_block; next_block++)
            {

                int split = next_block / params_.batch_count();
                int batch = next_block % params_.batch_count();

                //if (!symm_polys_stale_[split][batch])
                //	continue;

                int split_start = split * split_size,
                    batch_start = batch * batch_size,
                    batch_end = (batch_start + batch_size < table_size ? (batch_start + batch_size) : table_size);

                auto& block = db_blocks_.data()[next_block];
                block.randomized_symmetric_polys(context, symm_block, encoding_bit_length_, neg_null_element_);
                //randomized_symmetric_polys(split, batch, context, symm_block);

                auto idx = indexer(split, batch, 0);
                if (builder)
                {
                    for (int i = 0; i < split_size + 1; i++, idx++)
                    {
                        Plaintext &poly = batch_random_symm_polys_[idx];
                        for (int k = 0; batch_start + k < batch_end; k++)
                        {
                            integer_batch_vector[k] = *symm_block(k, i).pointer(0);
                        }
                        builder->compose(integer_batch_vector, poly);
                        evaluator->transform_to_ntt(poly, local_pool);
                    }
                }
                else if (context.exbuilder())
                {
                    for (int i = 0; i < split_size + 1; i++, idx++)
                    {
                        Plaintext &poly = batch_random_symm_polys_[idx];

                        // This branch works even if ex_field_ is an integer field, but it is slower than normal batching.
                        for (int k = 0; batch_start + k < batch_end; k++)
                        {
                            batch_vector[k] = symm_block(k, i);
                        }
                        context.exbuilder()->compose(batch_vector, poly);
                        evaluator->transform_to_ntt(poly, local_pool);
                    }
                }
            }
        }

        void SenderDB::batched_interpolate_polys(
            SenderThreadContext & context,
            int thread_count,
            shared_ptr<Evaluator> evaluator,
            shared_ptr<PolyCRTBuilder>& builder)
        {
            auto& mod = params_.encryption_params().plain_modulus();
            if (params_.get_label_bit_count() >= seal::util::get_significant_bit_count(mod.value()))
            {
                throw std::runtime_error("labels are too large for exfield.");
            }

            if (params_.get_label_bit_count() >= 64)
            {
                throw std::runtime_error("labels are too large u64 interpolation.");
            }

            int start = context.id() * db_blocks_.size() / thread_count;
            int end = (context.id() + 1) * db_blocks_.size() / thread_count;

            for (int bIdx = start; bIdx < end; bIdx++)
            {
                auto& block = db_blocks_(bIdx);
                block.batch_interpolate(context, mod, evaluator, builder, params_);
            }

        }

        void DBBlock::batch_interpolate(
            SenderThreadContext & context,
            const seal::SmallModulus& mod,
            shared_ptr<Evaluator> evaluator,
            shared_ptr<PolyCRTBuilder>& builder,
            const PSIParams& params)
        {
            int max_size = 0;
            std::vector<int> poly_size(items_per_batch_);
            std::vector<std::pair<u64, u64>> inputs; inputs.resize(items_per_split_);
            label_coeffs.resize(items_per_batch_, items_per_split_);
            MemoryPoolHandle local_pool = context.pool();
            Position pos;

            if (value_byte_length_ > sizeof(u64))
            {
                throw std::runtime_error("labels too large");
            }

            for (pos.batch_offset = 0; pos.batch_offset < items_per_batch_; ++pos.batch_offset)
            {
                //memset(inputs.data(), 0, inputs.size() * sizeof(std::pair<u64, u64>));
                inputs.clear();

                for (pos.split_offset = 0; pos.split_offset < items_per_split_; ++pos.split_offset)
                {
                    //auto& key = inputs[pos.split_offset].first;
                    //auto& label = inputs[pos.split_offset].second;
                    //key = pos.split_offset;
                    //label = 0;


                    if (has_item(pos))
                    {
                        inputs.emplace_back();
                        auto& key = inputs.back().first;
                        auto& label = inputs.back().second;

                        auto key_item = *(std::array<u64, 2>*)&get_key(pos);

                        if (key_item[1] || key_item[0] >= mod.value())
                        {
                            std::cout << get_key(pos) << std::endl;
                            std::cout << key_item[0] << " " << key_item[1] << std::endl;

                            throw std::runtime_error("key too large");
                        }

                        key = key_item[0];

                        auto src = get_label(pos);
                        memcpy(&label, src, value_byte_length_);


                        if (label >= mod.value())
                        {
                            throw std::runtime_error("label too large");
                        }

                        //if (test)
                        //{
                        //    test_points.push_back({key, label});
                        //}
                    }
                }

                if (params.use_low_degree_poly() == false)
                {
                    // pad the points to have max degree (split_size)
                    // with (x,x) points where x is unique.

                    std::unordered_set<u64> key_set;
                    for (auto& xy : inputs)
                        key_set.emplace(xy.first);

                    u64 x = 0;
                    while (inputs.size() != items_per_split_)
                    {
                        if (key_set.find(x) == key_set.end())
                            inputs.push_back({ x,x });

                        ++x;
                    }

                    max_size = inputs.size();
                }


                if (inputs.size())
                {
                    max_size = std::max<int>(max_size, inputs.size());
                    poly_size[pos.batch_offset] = inputs.size();
                    auto px = label_coeffs[pos.batch_offset].subspan(0, inputs.size());

                    if (px.size() != inputs.size())
                        throw std::runtime_error("");
                    u64_newton_interpolate_poly(inputs, px, mod);
                }
            }

            batched_label_coeffs.resize(max_size);
            std::vector<u64> temp(items_per_batch_);

            for (int s = 0; s < max_size; ++s)
            {
                Plaintext& batched_coeff = batched_label_coeffs[s];

                for (int b = 0; b < items_per_batch_; ++b)
                {
                    if (poly_size[b] > s)
                        temp[b] = label_coeffs(b, s);
                    else
                        temp[b] = 0;
                }

                batched_coeff.reserve(
                    params.encryption_params().coeff_modulus().size() *
                    params.encryption_params().poly_modulus().coeff_count());

                builder->compose(temp, batched_coeff);
                evaluator->transform_to_ntt(batched_coeff);
            }
        }

        //void SenderDB::save(ostream &stream) const
        //{
        //    /** Save the following data.
        //    B x m
        //    vector<vector<Item>> simple_hashing_db_;

        //    m x B
        //    vector<vector<int>> shuffle_index_;

        //    size m vector
        //    vector<int> next_shuffle_locs_;

        //    #splits x #batches x (split_size + 1).
        //    vector<vector<vector<seal::Plaintext>>> batch_random_symm_polys_;

        //    #splits x #batches.
        //    vector<vector<bool>> symm_polys_stale_;
        //    **/

        //    int32_t bin_size = params_.sender_bin_size(), table_size = params_.table_size(),
        //        num_splits = params_.split_count(), num_batches = params_.batch_count(),
        //        split_size_plus_one = params_.split_size() + 1;

        //    stream.write(reinterpret_cast<const char*>(&bin_size), sizeof(int32_t));
        //    stream.write(reinterpret_cast<const char*>(&table_size), sizeof(int32_t));
        //    stream.write(reinterpret_cast<const char*>(&num_splits), sizeof(int32_t));
        //    stream.write(reinterpret_cast<const char*>(&num_batches), sizeof(int32_t));
        //    stream.write(reinterpret_cast<const char*>(&split_size_plus_one), sizeof(int32_t));

        //    for (int i = 0; i < bin_size; i++)
        //        for (int j = 0; j < table_size; j++)
        //            simple_hashing_db2_(i, j).save(stream);

        //    //for (int i = 0; i < table_size; i++)
        //    //	for (int j = 0; j < bin_size; j++)
        //    //		stream.write(reinterpret_cast<const char*>(&(shuffle_index_[i][j])), sizeof(int));

        //    //for (int i = 0; i < table_size; i++)
        //    //	stream.write(reinterpret_cast<const char*>(&(next_shuffle_locs_[i])), sizeof(int));

        //    //for (int i = 0; i < num_splits; i++)
        //    //    for (int j = 0; j < num_batches; j++)
        //    //        for (int k = 0; k < split_size_plus_one; k++)
        //    //            batch_random_symm_polys_[i][j][k].save(stream);
        //    for (auto& p : batch_random_symm_polys_)
        //        p.save(stream);

        //    //for (int i = 0; i < num_splits; i++)
        //    //	for (int j = 0; j < num_batches; j++)
        //    //	{
        //    //		uint8_t c = (uint8_t)symm_polys_stale_[i][j];
        //    //		stream.write(reinterpret_cast<const char*>(&c), 1);
        //    //	}
        //}

        //void SenderDB::load(istream &stream)
        //{
        //    int32_t bin_size = 0, table_size = 0,
        //        num_splits = 0, num_batches = 0,
        //        split_size_plus_one = 0;

        //    stream.read(reinterpret_cast<char*>(&bin_size), sizeof(int32_t));
        //    stream.read(reinterpret_cast<char*>(&table_size), sizeof(int32_t));
        //    stream.read(reinterpret_cast<char*>(&num_splits), sizeof(int32_t));
        //    stream.read(reinterpret_cast<char*>(&num_batches), sizeof(int32_t));
        //    stream.read(reinterpret_cast<char*>(&split_size_plus_one), sizeof(int32_t));

        //    if (bin_size != params_.sender_bin_size() || table_size != params_.table_size() ||
        //        num_splits != params_.split_count() || num_batches != params_.batch_count()
        //        || split_size_plus_one != params_.split_size() + 1)
        //        throw runtime_error("Unexpected params.");

        //    for (int i = 0; i < bin_size; i++)
        //        for (int j = 0; j < table_size; j++)
        //            simple_hashing_db2_(i, j).load(stream);

        //    //for (int i = 0; i < table_size; i++)
        //    //	for (int j = 0; j < bin_size; j++)
        //    //		stream.read(reinterpret_cast<char*>(&(shuffle_index_[i][j])), sizeof(int));

        //    //for (int i = 0; i < table_size; i++)
        //    //	stream.read(reinterpret_cast<char*>(&(next_shuffle_locs_[i])), sizeof(int));

        //    //for (int i = 0; i < num_splits; i++)
        //    //    for (int j = 0; j < num_batches; j++)
        //    //        for (int k = 0; k < split_size_plus_one; k++)
        //    //            batch_random_symm_polys_[i][j][k].load(stream);
        //    for (auto& p : batch_random_symm_polys_)
        //        p.load(stream);

        //    //for (int i = 0; i < num_splits; i++)
        //    //	for (int j = 0; j < num_batches; j++)
        //    //		stream.read(reinterpret_cast<char*>(&symm_polys_stale_[i][j]), sizeof(bool));
        //}

    }
}
