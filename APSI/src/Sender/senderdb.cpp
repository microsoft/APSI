
#include "Sender/senderdb.h"
#include "apsidefines.h"
#include "seal/util/uintcore.h"
#include <fstream>
#include <algorithm>
#include <memory>
#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/MatrixView.h"
#include "cryptoTools/Common/Log.h"
#include <thread>
#include <cryptoTools/Crypto/sha1.h>
#include <unordered_map>
#include "seal/evaluator.h"
#include "seal/polycrt.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace oc;

namespace apsi
{
    namespace sender
    {
        SenderDB::SenderDB(const PSIParams &params, shared_ptr<ExField> &ex_field) :
            params_(params),
            encoder_(params.log_table_size(), params.hash_func_count(), params.item_bit_length()),
            global_ex_field_(ex_field),
            simple_hashing_db2_(params.sender_bin_size(), params.table_size()),
            next_locs_(params.table_size(), 0),
            batch_random_symm_polys_(params.number_of_splits() * params.number_of_batches() * (params.split_size() + 1))
        {
            for (auto& plain : batch_random_symm_polys_)
            {
                // Reserve memory for ciphertext size plaintexts (NTT transformed mod q)
                plain.reserve(params_.coeff_modulus().size() * (params_.poly_degree() + 1));
            }

            oc::block seed;
            random_device rd;
            *reinterpret_cast<array<unsigned int, 4>*>(&seed) = { rd(), rd(), rd(), rd() };
            prng_.SetSeed(seed, 256);

            // Set null value for sender: 1111...1110 (128 bits)
            // Receiver's null value comes from the Cuckoo class: 1111...1111
            sender_null_item_[0] = ~1;
            sender_null_item_[1] = ~0;


            // What is the actual length of strings stored in the hash table
            encoding_bit_length_ = params.get_cuckoo_mode() == cuckoo::CuckooMode::Normal
                ? params.item_bit_length() : encoder_.encoding_bit_length_;

            // Create the null ExFieldElement (note: encoding truncation affects high bits)
            null_element_ = sender_null_item_.to_exfield_element(global_ex_field_, encoding_bit_length_);
            neg_null_element_ = ExFieldElement(global_ex_field_);
            global_ex_field_->negate(null_element_, neg_null_element_);


            //std::cout << "neg_null_element_: " << neg_null_element_ << std::endl;
        }

        void SenderDB::clear_db()
        {
            auto ss = params_.sender_bin_size() * params_.table_size();
            simple_hashing_db_has_item_.reset(new atomic_bool[ss]);

            // Make sure all entries are false
            for (int i = 0; i < ss; i++)
            {
                if (simple_hashing_db_has_item_[i])
                {
                    throw runtime_error(LOCATION);
                }
            }
        }

        void SenderDB::set_data(const vector<Item> &data)
        {
            clear_db();
            add_data(data);
            stop_watch.set_time_point("Sender add-data");
        }

        void SenderDB::add_data(const vector<Item> &data)
        {
            vector<thread> thrds(params_.sender_total_thread_count());
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
                        normal_loc_func[i] = cuckoo ::LocFunc(params_.log_table_size(), params_.hash_func_seed() + i);
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
                            if (params_.get_cuckoo_mode() == cuckoo::CuckooMode::Normal)
                            {
                                // Compute bin locations
                                auto cuckoo_loc = normal_loc_func[j].location(data[i]);

                                // Lock-free thread-safe bin position search
                                auto position = aquire_bin_location(cuckoo_loc, prng);

                                // Now actually insert the item into the database
                                simple_hashing_db2_(position, cuckoo_loc) = data[i];

                                //ostreamLock(cout) << "Sitem[" << i << "] = " << data[i] << " -> " << j << " " << simple_hashing_db2_(position, cuckoo_loc) << " @ " << cuckoo_loc << endl;
                            }
                            else
                            {
                                // Get the permutation-based Cuckoo location and find position
                                auto cuckoo_loc = perm_loc_func[j].location(data[i]);
                                auto position = aquire_bin_location(cuckoo_loc, prng);

                                // Insert as usual
                                simple_hashing_db2_(position, cuckoo_loc) = encoder_.encode(data[i], j, true);

                                //ostreamLock(cout) << "Sitem[" << i << "] = " << data[i] << " -> "<<j<<" " << simple_hashing_db2_(position, cuckoo_loc) << " @ " << cuckoo_loc << endl;
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

        int SenderDB::aquire_bin_location(int cuckoo_loc, oc::PRNG &prng)
        {
            auto s = params_.sender_bin_size();
            auto start = cuckoo_loc * s;
            auto end = (cuckoo_loc + 1) * s;
            if (cuckoo_loc >= params_.table_size())
            {
                throw runtime_error(LOCATION);
            }

            // For 100 tries, guess a bin location can try to insert item there
            for (int i = 0; i < 100; i++)
            {
                auto idx = prng.get<oc::u32>() % s;

                bool exp = false;
                if (simple_hashing_db_has_item_[start + idx].compare_exchange_strong(exp, true))
                {
                    // Great, found an empty location and have marked it as mine
                    return idx;
                }
            }

            // If still failed, try to do linear scan
            for (int idx = 0; idx < s; idx++)
            {
                bool exp = false;
                if (simple_hashing_db_has_item_[start + idx].compare_exchange_strong(exp, true))
                {
                    // Great, found an empty location and have marked it as mine
                    return idx;
                }
            }

            // Throw an error because bin overflowed
            throw runtime_error("simple hashing failed due to bin overflow");
        }

        bool SenderDB::has_item(int cuckoo_loc, int position)
        {
            auto s = params_.sender_bin_size();
            auto start = cuckoo_loc * s;
            return simple_hashing_db_has_item_[start + position];
        }

        void SenderDB::add_data(const Item &item)
        {
            add_data(vector<Item>(1, item));
        }

        void SenderDB::delete_data(const vector<Item> &data)
        {
            throw runtime_error("not implemented");
        }

        void SenderDB::delete_data(const Item &item)
        {
            delete_data(vector<Item>(1, item));
        }

        void SenderDB::symmetric_polys(int split, int batch, SenderThreadContext &context,
            MatrixView<ExFieldElement> symm_block)
        {
            int split_size = params_.split_size();
            int batch_size = params_.batch_size();
            int split_start = split * split_size;
            int batch_start = batch * batch_size;
            shared_ptr<ExField> &exfield = context.exfield();

            auto num_rows = symm_block.bounds()[0];

            ExFieldElement one(exfield, "1");
            ExFieldElement temp11(exfield), temp2(exfield), *temp1;

            for (int i = 0; i < num_rows; i++)
            {
                symm_block(i, split_size) = one;
                for (int j = split_size - 1; j >= 0; j--)
                {
                    auto position = split_start + j;
                    auto cuckoo_loc = batch_start + i;

                    if (!has_item(cuckoo_loc, position))
                    {
                        temp1 = &neg_null_element_;
                    }
                    else
                    {
                        simple_hashing_db2_(position, cuckoo_loc).to_exfield_element(temp11, encoding_bit_length_);
                        //ostreamLock(std::cout) << "sender(" << cuckoo_loc << ", " << position << ") " << simple_hashing_db2_(position, cuckoo_loc) << std::endl;
                        temp1 = &temp11;
                        exfield->negate(*temp1, *temp1);
                    }

                    exfield->multiply(
                        symm_block(i, j + 1),
                        *temp1,
                        symm_block(i, j));

                    for (int k = j + 1; k < split_size; k++)
                    {
                        exfield->multiply(
                            symm_block(i, k + 1),
                            *temp1,
                            temp2);
                        symm_block(i, k) += temp2;
                    }
                }
            }
        }

        void SenderDB::randomized_symmetric_polys(int split, int batch, SenderThreadContext &context, MatrixView<ExFieldElement> symm_block)
        {
            int split_size = params_.split_size();
            symmetric_polys(split, batch, context, symm_block);
            auto num_rows = symm_block.bounds()[0];

            for (int i = 0; i < num_rows; i++)
            {
                // Sample non-zero randomness
                ExFieldElement r;
                do
                {
                    r = context.exfield()->random_element();
                } while (r.is_zero());

                for (int j = 0; j < split_size + 1; j++)
                {
                    context.exfield()->multiply(symm_block(i, j), r, symm_block(i, j));
                }
            }
        }

        void SenderDB::batched_randomized_symmetric_polys(SenderThreadContext &context, 
            shared_ptr<Evaluator> evaluator, shared_ptr<PolyCRTBuilder> builder)
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
            auto indexer = [splitStep = params_.number_of_batches() * split_size_plus_one,
                batchStep = split_size_plus_one](int splitIdx, int batchIdx, int i)
            {
                return splitIdx * splitStep + batchIdx * batchStep + i;
            };

            MemoryPoolHandle local_pool = context.pool();

            int total_blocks = params_.number_of_splits() * params_.number_of_batches();
            int start_block = context.id() * total_blocks / params_.sender_total_thread_count();
            int end_block = (context.id() + 1) * total_blocks / params_.sender_total_thread_count();

            for (int next_block = start_block; next_block < end_block; next_block++)
            {
                int split = next_block / params_.number_of_batches();
                int batch = next_block % params_.number_of_batches();

                //if (!symm_polys_stale_[split][batch])
                //	continue;

                int split_start = split * split_size,
                    batch_start = batch * batch_size,
                    batch_end = (batch_start + batch_size < table_size ? (batch_start + batch_size) : table_size);

                randomized_symmetric_polys(split, batch, context, symm_block);

                auto idx = indexer(split, batch, 0);
                if (builder)
                {
                    for (int i = 0; i < split_size + 1; i++, idx++)
                    {
                        Plaintext &temp_plain = batch_random_symm_polys_[idx];
                        for (int k = 0; batch_start + k < batch_end; k++)
                        {
                            integer_batch_vector[k] = *symm_block(k, i).pointer(0);
                        }
                        builder->compose(integer_batch_vector, temp_plain);
                        evaluator->transform_to_ntt(temp_plain, local_pool);
                    }
                }
                else if (context.exbuilder())
                {
                    for (int i = 0; i < split_size + 1; i++, idx++)
                    {
                        Plaintext &temp_plain = batch_random_symm_polys_[idx];

                        // This branch works even if ex_field_ is an integer field, but it is slower than normal batching.
                        for (int k = 0; batch_start + k < batch_end; k++)
                        {
                            batch_vector[k] = symm_block(k, i);
                        }
                        context.exbuilder()->compose(batch_vector, temp_plain);
                        evaluator->transform_to_ntt(temp_plain, local_pool);
                    }
                }
            }
        }

        void SenderDB::save(ostream &stream) const
        {
            /** Save the following data.
            B x m
            vector<vector<Item>> simple_hashing_db_;

            m x B
            vector<vector<int>> shuffle_index_;

            size m vector
            vector<int> next_shuffle_locs_;

            #splits x #batches x (split_size + 1).
            vector<vector<vector<seal::Plaintext>>> batch_random_symm_polys_;

            #splits x #batches.
            vector<vector<bool>> symm_polys_stale_;
            **/

            int32_t bin_size = params_.sender_bin_size(), table_size = params_.table_size(),
                num_splits = params_.number_of_splits(), num_batches = params_.number_of_batches(),
                split_size_plus_one = params_.split_size() + 1;

            stream.write(reinterpret_cast<const char*>(&bin_size), sizeof(int32_t));
            stream.write(reinterpret_cast<const char*>(&table_size), sizeof(int32_t));
            stream.write(reinterpret_cast<const char*>(&num_splits), sizeof(int32_t));
            stream.write(reinterpret_cast<const char*>(&num_batches), sizeof(int32_t));
            stream.write(reinterpret_cast<const char*>(&split_size_plus_one), sizeof(int32_t));

            for (int i = 0; i < bin_size; i++)
                for (int j = 0; j < table_size; j++)
                    simple_hashing_db2_(i, j).save(stream);

            //for (int i = 0; i < table_size; i++)
            //	for (int j = 0; j < bin_size; j++)
            //		stream.write(reinterpret_cast<const char*>(&(shuffle_index_[i][j])), sizeof(int));

            //for (int i = 0; i < table_size; i++)
            //	stream.write(reinterpret_cast<const char*>(&(next_shuffle_locs_[i])), sizeof(int));

            //for (int i = 0; i < num_splits; i++)
            //    for (int j = 0; j < num_batches; j++)
            //        for (int k = 0; k < split_size_plus_one; k++)
            //            batch_random_symm_polys_[i][j][k].save(stream);
            for (auto& p : batch_random_symm_polys_)
                p.save(stream);

            //for (int i = 0; i < num_splits; i++)
            //	for (int j = 0; j < num_batches; j++)
            //	{
            //		uint8_t c = (uint8_t)symm_polys_stale_[i][j];
            //		stream.write(reinterpret_cast<const char*>(&c), 1);
            //	}
        }

        void SenderDB::load(istream &stream)
        {
            int32_t bin_size = 0, table_size = 0,
                num_splits = 0, num_batches = 0,
                split_size_plus_one = 0;

            stream.read(reinterpret_cast<char*>(&bin_size), sizeof(int32_t));
            stream.read(reinterpret_cast<char*>(&table_size), sizeof(int32_t));
            stream.read(reinterpret_cast<char*>(&num_splits), sizeof(int32_t));
            stream.read(reinterpret_cast<char*>(&num_batches), sizeof(int32_t));
            stream.read(reinterpret_cast<char*>(&split_size_plus_one), sizeof(int32_t));

            if (bin_size != params_.sender_bin_size() || table_size != params_.table_size() ||
                num_splits != params_.number_of_splits() || num_batches != params_.number_of_batches()
                || split_size_plus_one != params_.split_size() + 1)
                throw runtime_error("Unexpected params.");

            for (int i = 0; i < bin_size; i++)
                for (int j = 0; j < table_size; j++)
                    simple_hashing_db2_(i, j).load(stream);

            //for (int i = 0; i < table_size; i++)
            //	for (int j = 0; j < bin_size; j++)
            //		stream.read(reinterpret_cast<char*>(&(shuffle_index_[i][j])), sizeof(int));

            //for (int i = 0; i < table_size; i++)
            //	stream.read(reinterpret_cast<char*>(&(next_shuffle_locs_[i])), sizeof(int));

            //for (int i = 0; i < num_splits; i++)
            //    for (int j = 0; j < num_batches; j++)
            //        for (int k = 0; k < split_size_plus_one; k++)
            //            batch_random_symm_polys_[i][j][k].load(stream);
            for (auto& p : batch_random_symm_polys_)
                p.load(stream);

            //for (int i = 0; i < num_splits; i++)
            //	for (int j = 0; j < num_batches; j++)
            //		stream.read(reinterpret_cast<char*>(&symm_polys_stale_[i][j]), sizeof(bool));
        }

    }
}
