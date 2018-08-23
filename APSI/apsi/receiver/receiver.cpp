// STD
#include <sstream>
#include <map>

// APSI
#include "apsi/sender/sender.h"
#include "apsi/receiver/receiver.h"
#include "apsi/apsidefines.h"
#include "apsi/network/network_utils.h"
#include "apsi/tools/utils.h"
#include "apsi/tools/prng.h"

// SEAL
#include "seal/util/common.h"
#include "seal/util/uintcore.h"
#include "seal/encryptionparams.h"
#include "seal/keygenerator.h"

// CryptoPP
#include "cryptopp/sha3.h"

// FourQ
#include "FourQ_api.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace cuckoo;
using namespace apsi::tools;
using namespace oc;

namespace apsi
{
    namespace receiver
    {
        Receiver::Receiver(const PSIParams &params, int thread_count, const MemoryPoolHandle &pool) :
            params_(params),
            thread_count_(thread_count),
            pool_(pool),
            ex_field_(FField::Acquire(params.exfield_characteristic(), params.exfield_degree())),
            slot_count_((params_.encryption_params().poly_modulus_degree() / params_.exfield_degree()))
        {
            if (thread_count_ <= 0)
            {
                throw invalid_argument("thread_count must be positive");
            }
            initialize();
        }

        void Receiver::initialize()
        {
            //EncryptionParameters enc_params;

            //enc_params.set_poly_modulus("1x^" + to_string(params_.poly_degree()) + " + 1");
            //enc_params.set_coeff_modulus(params_.coeff_modulus());
            //enc_params.set_plain_modulus(ex_field_->coeff_modulus());

            seal_context_ = SEALContext::Create(params_.encryption_params());
            KeyGenerator generator(seal_context_);

            public_key_ = generator.public_key();
            secret_key_ = generator.secret_key();

            encryptor_.reset(new Encryptor(seal_context_, public_key_));
            decryptor_.reset(new Decryptor(seal_context_, secret_key_));

            // Initializing tools for dealing with compressed ciphertexts
            // We don't actually need the evaluator
            shared_ptr<Evaluator> dummy_evaluator = nullptr;
            compressor_.reset(new CiphertextCompressor(seal_context_, 
                dummy_evaluator, pool_));

            generator.generate_evaluation_keys(params_.decomposition_bit_count(), evaluation_keys_);

            if (seal_context_->context_data()->qualifiers().enable_batching)
            {
                batch_encoder_.reset(new BatchEncoder(seal_context_));
            }

            if (!batch_encoder_)
            {
                ex_batch_encoder_.reset(new FFieldFastBatchEncoder(ex_field_->ch(), ex_field_->d(),
                    get_power_of_two(params_.encryption_params().poly_modulus_degree())));
            }
        }

        std::pair<std::vector<bool>, Matrix<u8>> Receiver::query(vector<Item>& items, oc::Channel& chl)
        {

            auto qq = preprocess(items, chl);
            auto& ciphertexts = qq.first;
            auto& cuckoo = *qq.second;


            send(ciphertexts, chl);

            auto table_to_input_map = cuckoo_indices(items, cuckoo);
            recv_stop_watch.set_time_point("receiver pre-process/sent");

            /* Receive results in a streaming fashion. */
            //std::vector<int> cuckoo_position;
            //vector<ExFieldElement> result, labels;
            //Pointer backing, label_bacing;
            auto intersection = stream_decrypt(chl, table_to_input_map, items);
            //recv_stop_watch.set_time_point("receiver decrypt");

            //ExFieldElement zero(ex_field_);
            ;//(items.size());


             //for (int i = 0; i < params_.table_size(); i++)
             //{
             //    //if (table_to_input_map[i] == -1)
             //    {
             //        for (int j = 0; j < params_.split_count(); j++)
             //        {
             //            if (result[j][i] == zero)
             //            {
             //                auto idx = table_to_input_map[i];
             //                intersection.emplace_back();
             //                intersection.back().first = idx;

             //                if (params_.get_label_bit_count())
             //                {
             //                    //std::cout << "idx: " << idx << " " << labels[j][i].to_string() << std::endl;
             //                    intersection.back().second = labels[j][i];
             //                }
             //            }
             //        }
             //    }
             //}

             //chl.asyncSendCopy(array<int, 2>{-1,-1});


             /* Now we need to shorten and convert this tmp vector to match the length and indice of the query "items". */
            recv_stop_watch.set_time_point("receiver intersect");
            return intersection;
        }

        pair<
            map<uint64_t, vector<Ciphertext> >,
            unique_ptr<CuckooInterface> >
            Receiver::preprocess(vector<Item> &items, Channel &channel)
        {
            if (params_.use_pk_oprf())
            {
                PRNG prng(ZeroBlock);
                vector<vector<digit_t>> b;
                b.reserve(items.size());
                digit_t x[NWORDS_ORDER];

                auto step = (sizeof(digit_t) * NWORDS_ORDER) - 1;
                vector<u8> buff(items.size() * step);
                auto iter = buff.data();
                for (u64 i = 0; i < items.size(); i++)
                {
                    random_fourq(x, prng);
                    b.emplace_back(x, x + NWORDS_ORDER);

                    PRNG pp(items[i], /* buffer_size */ 8);

                    random_fourq(x, pp);
                    Montgomery_multiply_mod_order(x, b[i].data(), x);
                    eccoord_to_buffer(x, iter);
                    iter += step;
                }

                // send the data over the network and prep for the response.
                channel.asyncSend(move(buff));
                auto f = channel.asyncRecv(buff);

                // compute 1/b so that we can compute (x^ba)^(1/b) = x^a
                for (u64 i = 0; i < items.size(); ++i)
                {
                    digit_t inv[NWORDS_ORDER];
                    Montgomery_inversion_mod_order(b[i].data(), inv);
                    b[i] = vector<digit_t>(inv, inv + NWORDS_ORDER);
                }
                f.get();

                iter = buff.data();
                for (u64 i = 0; i < items.size(); i++)
                {
                    buffer_to_eccoord(iter, x);
                    Montgomery_multiply_mod_order(x, b[i].data(), x);
                    eccoord_to_buffer(x, iter);

                    // Compress with SHA3
                    CryptoPP::SHA3_256 sha;
                    sha.Update(iter, step);
                    sha.TruncatedFinal(reinterpret_cast<CryptoPP::byte*>(&items[i]), sizeof(block));

                    iter += step;
                }
            }

            unique_ptr<CuckooInterface> cuckoo = cuckoo_hashing(items);

            //vector<int> indices = cuckoo_indices(items, *cuckoo);

            unique_ptr<FFieldArray> exfield_items;
            unsigned padded_cuckoo_capacity = ((cuckoo->table_size() + slot_count_ - 1) / slot_count_) * slot_count_;
            if (batch_encoder_)
            {
                exfield_items.reset(new FFieldArray(ex_field_, padded_cuckoo_capacity));
            }
            else
            {
                vector<shared_ptr<FField> > field_vec;
                field_vec.reserve(padded_cuckoo_capacity);
                for (unsigned i = 0; i < padded_cuckoo_capacity; i++)
                {
                    field_vec.emplace_back(ex_batch_encoder_->field(i % slot_count_));
                }
                exfield_items.reset(new FFieldArray(field_vec));
            }
            exfield_encoding(*cuckoo, *exfield_items);

            map<uint64_t, FFieldArray> powers;
            generate_powers(*exfield_items, powers);

            // if (params_.debug())
            // {
            //     //for (u64 j = 0; j < exfield_items.size(); ++j)
            //     //{
            //     //    std::cout << "Exp[" << j << "]: " << exfield_items.get(j) << std::endl;
            //     //}
            //
            //     send_ffield_array(*exfield_items, channel);
            // }

            map<uint64_t, vector<Ciphertext> > ciphers;
            encrypt(powers, ciphers);

            return { move(ciphers), move(cuckoo) };
        }

        void Receiver::send(const map<uint64_t, vector<Ciphertext> > &query, Channel &channel)
        {
            /* Send keys. */
            send_pubkey(public_key_, channel);
            send_evalkeys(evaluation_keys_, channel);

            if (params_.debug())
            {
                send_prvkey(secret_key_, channel);
                send_prvkey(secret_key_, channel);
            }

            /* Send query data. */
            channel.asyncSendCopy(int(query.size()));
            for (map<uint64_t, vector<Ciphertext> >::const_iterator it = query.begin(); it != query.end(); it++)
            {
                channel.asyncSendCopy(it->first);

                for(auto& c : it->second)
                    send_ciphertext(c, channel);
            }
        }

        unique_ptr<CuckooInterface> Receiver::cuckoo_hashing(const vector<Item> &items)
        {
            auto receiver_null_item = oc::AllOneBlock;

            unique_ptr<CuckooInterface> cuckoo(
                static_cast<CuckooInterface*>(new Cuckoo(
                    params_.hash_func_count(),
                    params_.hash_func_seed(),
                    params_.log_table_size(),
                    params_.item_bit_count(),
                    params_.max_probe(),
                    receiver_null_item))
            );

            auto coeff_bit_count = seal::util::get_significant_bit_count(ex_field_->ch()) - 1;
            auto degree = ex_field_ ? ex_field_->d() : 1;

            if (cuckoo->encoding_bit_length() > coeff_bit_count * degree)
            {
                cout << "Reduced items too long. Only have " <<
                    coeff_bit_count * degree << " bits." << endl;
                throw runtime_error(LOCATION);
            }
            else
            {
                cout << "Using " << cuckoo->encoding_bit_length()
                    << " out of " << seal::util::get_significant_bit_count(params_.exfield_characteristic()) - 1
                    << "x" << degree
                    << " bits of exfield element." << endl;
            }
            bool insertionSuccess;
            for (int i = 0; i < items.size(); i++)
            {
                insertionSuccess = cuckoo->insert(items[i]);
                if (!insertionSuccess)
                    throw logic_error("cuck hashing failed.");
            }

            return cuckoo;
        }


        vector<int> Receiver::cuckoo_indices(const vector<Item> &items, cuckoo::CuckooInterface &cuckoo)
        {
            vector<int> indice(cuckoo.table_size(), -1);
            auto& encodings = cuckoo.get_encodings();

            // cuckoo::PermutationBasedCuckoo::Encoder encoder(cuckoo.log_table_size(), cuckoo.loc_func_count(), params_.item_bit_count());

            for (int i = 0; i < items.size(); i++)
            {
                auto q = cuckoo.query_item(items[i]);
                indice[q.table_index()] = i;

                if (neq(items[i], encodings[q.table_index()]))
                    throw runtime_error(LOCATION);

                //ostreamLock(cout) << "Ritem[" << i << "] = " << items[i] << " -> " << q.hash_func_index() << " " << encodings[q.table_index()] << " @ " << q.table_index() << endl;
            }
            return indice;
        }

        void Receiver::exfield_encoding(
            CuckooInterface &cuckoo,
            FFieldArray &ret)
        {
            int encoding_bit_length = cuckoo.encoding_bit_length();
            auto encoding_u64_len = roundUpTo(encoding_bit_length, 64) / 64;

            auto& encodings = cuckoo.get_encodings();

            for (int i = 0; i < cuckoo.table_size(); i++)
            {
                //if(cuckoo.has_item_at(i))
                ret.set(i, Item(encodings[i]).to_exfield_element(ret.field(i), encoding_bit_length));
            }
            for (int i = cuckoo.table_size(); i < ret.size(); i++)
            {
                ret.set(i, Item(cuckoo.null_value()).to_exfield_element(ret.field(i), encoding_bit_length));
            }
        }

        void Receiver::generate_powers(const FFieldArray &exfield_items,
            map<uint64_t, FFieldArray> &result)
        {
            int split_size = (params_.sender_bin_size() + params_.split_count() - 1) / params_.split_count();
            int window_size = params_.window_size();
            int radix = 1 << window_size;
            int bound = floor(log2(split_size) / window_size) + 1;

            FFieldArray current_power = exfield_items;
            for (uint64_t j = 0; j < bound; j++)
            {
                result.emplace(1ULL << (window_size * j), current_power);
                for (uint64_t i = 2; i < radix; i++)
                {
                    if (i * (1ULL << (window_size * j)) > split_size)
                    {
                        return;
                    }
                    result.emplace(i * (1ULL << (window_size * j)), result.at((i - 1) * (1ULL << (window_size * j))) * current_power);
                }
                for (int k = 0; k < window_size; k++)
                {
                    current_power.sq();
                }
            }

        }

        void Receiver::encrypt(map<uint64_t, FFieldArray> &input, map<uint64_t, vector<Ciphertext>> &destination)
        {
            destination.clear();
            for (auto it = input.begin(); it != input.end(); it++)
            {
                encrypt(it->second, destination[it->first]);
            }
        }

        void Receiver::encrypt(const FFieldArray &input, vector<Ciphertext> &destination)
        {
            int batch_size = slot_count_, num_of_batches = (input.size() + batch_size - 1) / batch_size;
            vector<uint64_t> integer_batch(batch_size, 0);
            destination.clear();
            destination.reserve(num_of_batches);
            Plaintext plain(pool_);
            if (batch_encoder_)
            {
                for (int i = 0; i < num_of_batches; i++)
                {
                    // This is a bit silly; BatchEncoder only takes vector inputs
                    // NO LONGER TRUE! Update to use span
                    for (int j = 0; j < batch_size; j++)
                    {
                        integer_batch[j] = input.get_coeff_of(i * batch_size + j, 0);
                    }
                    batch_encoder_->compose(integer_batch, plain);
                    destination.emplace_back(params_.encryption_params(), pool_);
                    encryptor_->encrypt(plain, destination.back(), pool_);
                }
            }
            else
            {
                FFieldArray batch(ex_batch_encoder_->create_array());
                for (int i = 0; i < num_of_batches; i++)
                {
                    for (int j = 0; j < batch_size; j++)
                    {
                        batch.set(j, i * batch_size + j, input);
                    }
                    ex_batch_encoder_->compose(batch, plain);
                    destination.emplace_back(params_.encryption_params(), pool_);
                    encryptor_->encrypt(plain, destination.back(), pool_);
                }
            }
        }

        //vector<vector<ExFieldElement>> Receiver::bulk_decrypt(const vector<vector<Ciphertext>> &result_ciphers)
        //{
        //    if (result_ciphers.size() != params_.split_count() || result_ciphers[0].size() != params_.batch_count())
        //        throw invalid_argument("Result ciphers have unexpexted sizes.");

        //    int slot_count = ex_batch_encoder_->slot_count();
        //    memory_backing_.emplace_back(Pointer());
        //    vector<vector<ExFieldElement>> result = ex_field_->allocate_elements(
        //        result_ciphers.size(), result_ciphers[0].size() * slot_count, memory_backing_.back());
        //    Pointer tmp_backing;
        //    vector<ExFieldElement> temp = ex_field_->allocate_elements(slot_count, tmp_backing);
        //    for (int i = 0; i < result_ciphers.size(); i++)
        //        for(int j = 0; j < result_ciphers[0].size(); j++)
        //        {
        //            decrypt(result_ciphers[i][j], temp);
        //            for (int k = 0; k < temp.size(); k++)
        //                result[i][j * slot_count + k] = temp[k];
        //        }
        //    cout << "Remaining Nosie Budget: " << decryptor_->invariant_noise_budget(result_ciphers[0][0]) << endl;

        //    return result;
        //}



        std::pair<std::vector<bool>, Matrix<u8>> Receiver::stream_decrypt(
            oc::Channel &channel,
            const std::vector<int> &table_to_input_map,
            std::vector<Item> &items)
        {

            std::pair<std::vector<bool>, Matrix<u8>> ret;
            auto& ret_bools = ret.first;
            auto& ret_labels = ret.second;


            ret_bools.resize(items.size(), false);

            if (params_.get_label_bit_count())
            {
                ret_labels.resize(items.size(), params_.get_label_byte_count());
            }


            int num_of_splits = params_.split_count(),
                num_of_batches = params_.batch_count(),
                block_count = num_of_splits * num_of_batches,
                batch_size = slot_count_;

            struct RecvPackage
            {
                int split_idx, batch_idx;
                std::string data, label_data;
                std::future<void> fut, label_fut;
            };

            std::vector<RecvPackage> recvPackages(block_count);
            for (auto& pkg : recvPackages)
            {
                channel.asyncRecv(pkg.split_idx);
                channel.asyncRecv(pkg.batch_idx);
                pkg.fut = channel.asyncRecv(pkg.data);

                if (params_.get_label_bit_count())
                {
                    pkg.label_fut = channel.asyncRecv(pkg.label_data);
                }
            }

            auto numThreads = thread_count_;
            cout << "Decrypting " << block_count << " blocks (" << num_of_batches << "b x " << num_of_splits << "s) with "<< numThreads<<" threads" << endl;

            auto routine = [&](int t)
            {
                MemoryPoolHandle local_pool(MemoryPoolHandle::New());
                Plaintext p(local_pool);
                Ciphertext tmp(seal_context_->context_data(
                    seal_context_->last_parms_id())->parms(), local_pool);
                const bool short_strings = !!batch_encoder_;
                unique_ptr<FFieldArray> batch;
                if (!short_strings)
                {
                    batch.reset(new FFieldArray(ex_batch_encoder_->create_array()));
                }
                vector<uint64_t> integer_batch(batch_size);

                bool has_result;
                std::vector<char> has_label(batch_size);

                bool first = true;

                for (u64 i = t; i < recvPackages.size(); i += numThreads)
                {
                    auto& pkg = recvPackages[i];

                    pkg.fut.get();
                    auto base_idx = pkg.batch_idx * batch_size;

                    // recover the sym poly values 
                    has_result = false;
                    stringstream ss(pkg.data);
                    compressor_->compressed_load(ss, tmp);
                    // tmp.load(ss);

                    if (first && t == 0)
                    {
                        first = false;
                        cout << "Noise budget: " << decryptor_->invariant_noise_budget(tmp, local_pool) << " bits" << endl;
                        recv_stop_watch.set_time_point("receiver recv-start");
                    }

                    decryptor_->decrypt(tmp, p, local_pool);

                    //vector<uint64_t> integer_batch(batch_size);
                    if (short_strings)
                        batch_encoder_->decompose(p, integer_batch, local_pool);
                    else
                        ex_batch_encoder_->decompose(p, *batch);

                    for (int k = 0; k < integer_batch.size(); k++)
                    {
                        auto &is_zero = has_label[k];
                        auto idx = table_to_input_map[base_idx + k];

                        if (short_strings)
                            is_zero = integer_batch[k] == 0;
                        else
                            is_zero = batch->is_zero(k);

                        if (is_zero)
                        {
                            has_result = true;

                            //std::cout << "hit   " << (block)items[idx] <<" @ (" << pkg.batch_idx << ", " << pkg.split_idx << ") @ " << base_idx + k << std::endl;
                            ret_bools[idx] = true;
                        }


                        //if (idx!= -1 && short_strings == false)
                        //{
                        //    std::cout << "item[" << idx << "]  " << (block)items[idx] << " @ (" << pkg.batch_idx << ", " << pkg.split_idx << ") @ " << base_idx + k << std::endl
                        //        << "     " << batch.get(k) << std::endl;;

                        //}
                        //if (k < 10) std::cout << (k ? ", " : "") << integer_batch[k];
                    }
                    //std::cout << "..." << endl;


                    if (has_result && params_.get_label_bit_count())
                    {
                        pkg.label_fut.get();
                        std::stringstream ss(pkg.label_data);
                        //std::cout << pkg.batch_idx << " " << pkg.split_idx << " " << std::endl;
                        // tmp.load(ss);
                        compressor_->compressed_load(ss, tmp);

                        decryptor_->decrypt(tmp, p, local_pool);



                        if (short_strings)
                            batch_encoder_->decompose(p, integer_batch, local_pool);
                        else
                        {
                            // make sure its the right size. decrypt will shorted when there are zero coeffs at the top.
                            p.resize(ex_batch_encoder_->n());

                            ex_batch_encoder_->decompose(p, *batch);
                        }

                        for (int k = 0; k < integer_batch.size(); k++)
                        {
                            if (has_label[k])
                            {
                                auto idx = table_to_input_map[base_idx + k];

                                //std::cout << "label["<< idx<<"] " << items[idx] << " @ (" << pkg.batch_idx << ", " << pkg.split_idx << ") @ " << base_idx + k << "  ~  " <<std::hex<< integer_batch[k] <<std::dec << std::endl;
                                u8* src;
                                if (short_strings)
                                {
                                    src = (u8*)&integer_batch[k];
                                    memcpy(&ret_labels(idx, 0), src, ret_labels.stride());
                                }
                                else
                                {
                                    batch->get(k).decode(ret_labels[idx], params_.get_label_bit_count());
                                    //throw runtime_error("not implemented");
                                    // src = (u8*)batch[k].pointer(0);
                                }

                            }
                        }
                    }
                }
            };

            std::vector<std::thread> thrds(numThreads - 1);
            for (u64 t = 0; t < thrds.size(); ++t)
            {
                thrds[t] = std::thread(routine, t);
            }

            routine(numThreads - 1);
            for (auto& thrd : thrds)
                thrd.join();

            return std::move(ret);
        }


        void Receiver::decrypt(
            seal::Ciphertext &tmp,
            std::vector<bool> &rr,
            seal::Plaintext &p,
            std::vector<uint64_t> &integer_batch,
            FFieldArray &batch)
        {
            throw std::runtime_error("outdated code");
            decrypt(tmp, p);

            if (batch_encoder_)
            {
                batch_encoder_->decompose(p, integer_batch, pool_);

                for (int k = 0; k < integer_batch.size(); k++)
                {
                    rr[k] = integer_batch[k] == 0;

                    if (k < 10)
                        std::cout << (k ? ", " : "") << integer_batch[k];
                }


                std::cout << "..." << endl;
            }
            else
            {
                ex_batch_encoder_->decompose(p, batch);
                for (int k = 0; k < batch.size(); k++)
                {
                    rr[k] = batch.is_zero(k);
                }
            }
        }


        //void Receiver::decompose(const vector<vector<Plaintext>> &plain_matrix,
        //	vector<vector<::ExFieldElement>> &result)
        //{
        //	int num_of_splits = params_.split_count(),
        //		num_of_batches = params_.batch_count(),
        //		slot_count = ex_batch_encoder_->slot_count();

        //	memory_backing_.emplace_back(Pointer());
        //	result = ex_field_->allocate_elements(
        //		num_of_splits, num_of_batches * slot_count, memory_backing_.back());
        //	Pointer batch_backing;
        //	vector<ExFieldElement> batch = ex_field_->allocate_elements(slot_count, batch_backing);

        //	for (int i = 0; i < num_of_splits; i++)
        //	{
        //		for (int j = 0; j < num_of_batches; j++)
        //		{
        //			decompose(plain_matrix[i][j], batch);
        //			for (int k = 0; k < batch.size(); k++)
        //			{
        //				result[i][j * slot_count + k] = batch[k];
        //			}
        //		}
        //	}
        //}


        //     void Receiver::decrypt(const vector<Ciphertext> &ciphers,
        //vector<::ExFieldElement>& result,
        //::Pointer& backing)
        //     {
        //         int slot_count = ex_batch_encoder_->slot_count();
        //         
        //         vector<ExFieldElement> result = ex_field_->allocate_elements(ciphers.size() * slot_count, backing);
        //         Pointer tmp_backing;
        //         vector<ExFieldElement> temp = ex_field_->allocate_elements(slot_count, tmp_backing);
        //         for (int i = 0; i < ciphers.size(); i++)
        //         {
        //             if (batch_encoder_)
        //             {
        //                 vector<uint64_t> integer_batch = batch_encoder_->decompose(decryptor_->decrypt(ciphers[i]));
        //                 for (int j = 0; j < integer_batch.size(); j++)
        //                     *temp[j].pointer(0) = integer_batch[j];
        //             }
        //             else
        //             {
        //                 ex_batch_encoder_->decompose(decryptor_->decrypt(ciphers[i]), temp);
        //             }
        //             for(int j = 0; j < temp.size(); j++)
        //                 result[i * slot_count + j] = temp[j];
        //         }
        //         //return result;
        //     }

        //void Receiver::decrypt(const Ciphertext &cipher, vector<ExFieldElement> &batch)
        //{
        //    Plaintext plain;
        //    decrypt(cipher, plain);
        //    decompose(plain, batch);
        //}

        void Receiver::decrypt(const Ciphertext &cipher, Plaintext &plain)
        {
            decryptor_->decrypt(cipher, plain);
            //cout << "Noise budget: " << decryptor_->invariant_noise_budget(cipher) << endl;
        }

        //void Receiver::decompose(const Plaintext &plain, vector<::ExFieldElement> &batch)
        //{

        //}

    }
}
