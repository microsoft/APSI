#include "Sender/sender.h"
#include "Receiver/receiver.h"

// SEAL includes
#include "seal/util/uintcore.h"
#include "seal/encryptionparams.h"
#include "seal/keygenerator.h"
#include "apsidefines.h"
#include <sstream>
#include "Network/network_utils.h"
#include "cryptoTools/Crypto/sha1.h"
#include "cryptoTools/Common/Log.h"

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
        Receiver::Receiver(const PSIParams &params, const MemoryPoolHandle &pool) :
            params_(params),
            pool_(pool),
            ex_field_(ExField::Acquire(params.exfield_characteristic(), params.exfield_polymod(), pool))
        {
            initialize();
        }

        void Receiver::initialize()
        {
            EncryptionParameters enc_params;

            enc_params.set_poly_modulus("1x^" + to_string(params_.poly_degree()) + " + 1");
            enc_params.set_coeff_modulus(params_.coeff_modulus());
            enc_params.set_plain_modulus(ex_field_->coeff_modulus());

            SEALContext seal_context(enc_params);
            KeyGenerator generator(seal_context);

            public_key_ = generator.public_key();
            secret_key_ = generator.secret_key();

            encryptor_.reset(new Encryptor(seal_context, public_key_));
            decryptor_.reset(new Decryptor(seal_context, secret_key_));

            generator.generate_evaluation_keys(params_.decomposition_bit_count(), evaluation_keys_);

            exfieldpolycrtbuilder_.reset(new ExFieldPolyCRTBuilder(ex_field_, params_.log_poly_degree()));

            if (seal_context.qualifiers().enable_batching)
                polycrtbuilder_.reset(new PolyCRTBuilder(seal_context));

            ex_field_->init_frob_table();
        }

        vector<bool> Receiver::query(vector<Item>& items, oc::Channel& chl)
        {

            auto qq = preprocess(items, chl);
            auto& ciphertexts = qq.first;
            auto& cuckoo = *qq.second;


            send(ciphertexts, chl);

            auto table_to_input_map = cuckoo_indices(items, cuckoo);
            stop_watch.set_time_point("receiver pre-process/sent");

            /* Receive results in a streaming fashion. */
            vector<vector<ExFieldElement>> result;
            Pointer backing;
            stream_decrypt(chl, result, backing);
            stop_watch.set_time_point("receiver decrypt");

            ExFieldElement zero(ex_field_);
            vector<bool> intersection(items.size(), false);


            for (int i = 0; i < params_.table_size(); i++)
            {
                //if (table_to_input_map[i] == -1)
                {
                    for (int j = 0; j < params_.number_of_splits(); j++)
                    {
                        if (result[j][i] == zero)
                        {
                            //if (table_to_input_map[i] == -1)
                            //{
                            //    ostreamLock o(std::cout);
                            //    o << " **** False positive match at empty cuckoo[" << i << "] and response ciphtertext #" << j << std::endl;
                            //}
                            //else
                            //{
                            //    intersection[table_to_input_map[i]] = true;
                            //}
                            //break;
                            intersection[table_to_input_map[i]] = true;
                        }
                    }
                }
            }

            //chl.asyncSendCopy(std::array<int, 2>{-1,-1});


            /* Now we need to shorten and convert this tmp vector to match the length and indice of the query "items". */
            stop_watch.set_time_point("receiver intersect");
            return intersection;
        }

        std::pair<
            std::map<uint64_t, std::vector<seal::Ciphertext>>,
            unique_ptr<CuckooInterface>
        > Receiver::preprocess(vector<Item> &items, Channel& channel)
        {
            if (params_.use_pk_oprf())
            {

                //std::cout << "start " << std::endl;
                PRNG prng(ZeroBlock);
                EllipticCurve curve(p256k1, prng.get<oc::block>());
                std::vector<EccNumber> b;
                b.reserve(items.size());
                EccPoint x(curve);
                //std::vector<EccPoint> xx; xx.reserve(items.size());

                auto step = curve.getGenerator().sizeBytes();
                std::vector<u8> buff(items.size() * step);
                auto iter = buff.data();
                for (u64 i = 0; i < items.size(); ++i)
                {
                    b.emplace_back(curve, prng);
                    PRNG pp((oc::block&)items[i], 8);

                    x.randomize(pp);
                    x *= b[i];

                    x.toBytes(iter);
                    iter += step;
                }


                // send the data over the network and prep for the response.
                channel.asyncSend(std::move(buff));
                auto f = channel.asyncRecv(buff);

                // compute 1/b so that we can compute (x^ba)^(1/b) = x^a
                for (u64 i = 0; i < items.size(); ++i)
                {
                    b[i] = std::move(b[i].inverse());
                }
                f.get();

                iter = buff.data();
                for (u64 i = 0; i < items.size(); ++i)
                {
                    x.fromBytes(iter);
                    x *= b[i];

                    x.toBytes(iter);
                    SHA1 sha(sizeof(block));
                    sha.Update(iter, step);
                    sha.Final((oc::block&)items[i]);

                    iter += step;
                }
            }

            unique_ptr<CuckooInterface> cuckoo = cuckoo_hashing(items);

            //vector<int> indices = cuckoo_indices(items, *cuckoo);

            vector<ExFieldElement> exfield_items;
            Pointer data;
            exfield_encoding(*cuckoo, exfield_items, data);


            std::map<uint64_t, std::vector<seal::util::ExFieldElement> > powers;
            std::list<Pointer> data2;
            generate_powers(exfield_items, powers, data2);
            exfield_items.clear();
            data.release();

            map<uint64_t, vector<Ciphertext>> ciphers;
            encrypt(powers, ciphers);

            return { std::move(ciphers), std::move(cuckoo) };
        }

        void Receiver::send(const map<uint64_t, vector<Ciphertext>> &query, Channel &channel)
        {
            /* Send keys. */
            send_pubkey(public_key_, channel);
            send_evalkeys(evaluation_keys_, channel);

            /* Send query data. */
            channel.asyncSendCopy(int(query.size()));
            for (map<uint64_t, vector<Ciphertext>>::const_iterator it = query.begin(); it != query.end(); it++)
            {
                channel.asyncSendCopy(it->first);
                send_ciphertext(it->second, channel);
            }
        }

        unique_ptr<CuckooInterface> Receiver::cuckoo_hashing(const vector<Item> &items)
        {
            auto receiver_null_item = oc::AllOneBlock;

            unique_ptr<CuckooInterface> cuckoo(
                params_.get_cuckoo_mode() == CuckooMode::Permutation ?
                static_cast<CuckooInterface*>(new PermutationBasedCuckoo(
                    params_.hash_func_count(),
                    params_.hash_func_seed(),
                    params_.log_table_size(),
                    params_.item_bit_length(),
                    params_.max_probe(),
                    receiver_null_item))
                :
                static_cast<CuckooInterface*>(new Cuckoo(
                    params_.hash_func_count(),
                    params_.hash_func_seed(),
                    params_.log_table_size(),
                    params_.item_bit_length(),
                    params_.max_probe(),
                    receiver_null_item))
            );

            if (cuckoo->encoding_bit_length() >= ex_field_->characteristic().bit_count() * (ex_field_->poly_modulus().coeff_count() - 1))
            {
                cout << "Reduced items too long. Only have " <<
                    seal::util::get_significant_bit_count(params_.exfield_characteristic()) - 1 << " bits." << endl;
                throw std::runtime_error(LOCATION);
            }
            else
            {
                cout << "Using " << cuckoo->encoding_bit_length()
                    << " out of " << seal::util::get_significant_bit_count(params_.exfield_characteristic()) - 1
                    << " bits of exfield element." << std::endl;
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


        std::vector<int> Receiver::cuckoo_indices(const std::vector<Item> &items, cuckoo::CuckooInterface &cuckoo)
        {
            vector<int> indice(cuckoo.capacity(), -1);
            auto& encodings = cuckoo.get_encodings();

            cuckoo::PermutationBasedCuckoo::Encoder encoder(cuckoo.log_capacity(), cuckoo.loc_func_count(), params_.item_bit_length());


            for (int i = 0; i < items.size(); i++)
            {
                auto q = cuckoo.query_item(items[i]);
                indice[q.table_index()] = i;

                if (params_.get_cuckoo_mode() == CuckooMode::Permutation)
                {
                    auto rr = encoder.encode(items[i], q.hash_func_index(), true);
                    if (neq(oc::block(rr), oc::block(encodings[q.table_index()])))
                        throw std::runtime_error(LOCATION);
                }
                else
                {
                    if (neq(items[i], encodings[q.table_index()]))
                        throw std::runtime_error(LOCATION);
                }

                //ostreamLock(std::cout) << "Ritem[" << i << "] = " << items[i] << " -> " << q.hash_func_index() << " " << encodings[q.table_index()] << " @ " << q.table_index() << std::endl;
            }
            return indice;
        }

        void Receiver::exfield_encoding(
            CuckooInterface &cuckoo,
            std::vector<seal::util::ExFieldElement>& ret,
            seal::util::Pointer& data)
        {

            ret = ex_field_->allocate_elements(cuckoo.capacity(), data);
            int encoding_bit_length = cuckoo.encoding_bit_length();
            auto encoding_u64_len = roundUpTo(encoding_bit_length, 64) / 64;

            auto& encodings = cuckoo.get_encodings();

            for (int i = 0; i < cuckoo.capacity(); i++)
            {
                //if(cuckoo.has_item_at(i))
                Item(encodings[i]).to_exfield_element(ret[i], encoding_bit_length);
            }
        }

        void Receiver::generate_powers(const vector<ExFieldElement> &exfield_items,
            std::map<uint64_t, std::vector<seal::util::ExFieldElement> >& result,
            std::list<Pointer>& data)
        {
            int split_size = (params_.sender_bin_size() + params_.number_of_splits() - 1) / params_.number_of_splits();
            int window_size = params_.window_size();
            int radix = 1 << window_size;
            int bound = floor(log2(split_size) / window_size) + 1;

            vector<ExFieldElement> current_power = exfield_items;
            for (int j = 0; j < bound; j++)
            {
                result[1 << (window_size * j)] = current_power;
                for (int i = 2; i < radix; i++)
                {
                    if (i * (static_cast<uint64_t>(1) << (window_size * j)) > split_size)
                    {
                        return;
                    }
                    data.emplace_back(Pointer());
                    result[i * (1 << (window_size * j))] = ex_field_->allocate_elements(current_power.size(), data.back());
                    ex_field_->dyadic_multiply(result[(i - 1)*(1 << (window_size*j))], current_power, result[i * (1 << (window_size * j))]);
                }
                for (int k = 0; k < window_size; k++)
                {
                    ex_field_->dyadic_square_inplace(current_power);
                }
            }

        }

        void Receiver::encrypt(std::map<uint64_t, std::vector<ExFieldElement>> &input, map<uint64_t, vector<Ciphertext>> &destination)
        {
            destination.clear();
            for (auto it = input.begin(); it != input.end(); it++)
            {
                encrypt(it->second, destination[it->first]);
            }
        }

        void Receiver::encrypt(const vector<ExFieldElement> &input, vector<Ciphertext> &destination)
        {
            int batch_size = exfieldpolycrtbuilder_->slot_count(), num_of_batches = (input.size() + batch_size - 1) / batch_size;
            Pointer tmp_backing;
            vector<ExFieldElement> batch = ex_field_->allocate_elements(batch_size, tmp_backing);
            vector<uint64_t> integer_batch(batch_size, 0);
            destination.clear();
            for (int i = 0; i < num_of_batches; i++)
            {

                Plaintext plain;
                if (polycrtbuilder_)
                {
                    for (int j = 0; (j < batch_size) && ((i * batch_size + j) < input.size()); j++)
                        integer_batch[j] = *input[i * batch_size + j].pointer(0);
                    polycrtbuilder_->compose(integer_batch, plain);
                }
                else // This branch works even if ex_field_ is an integer field, but it is slower than normal batching.
                {
                    for (int j = 0; (j < batch_size) && ((i * batch_size + j) < input.size()); j++)
                        batch[j] = input[i * batch_size + j];
                    exfieldpolycrtbuilder_->compose(batch, plain);
                }
                destination.emplace_back();
                encryptor_->encrypt(plain, destination.back(), pool_);
            }
        }

        //vector<vector<ExFieldElement>> Receiver::bulk_decrypt(const vector<vector<Ciphertext>> &result_ciphers)
        //{
        //    if (result_ciphers.size() != params_.number_of_splits() || result_ciphers[0].size() != params_.number_of_batches())
        //        throw invalid_argument("Result ciphers have unexpexted sizes.");

        //    int slot_count = exfieldpolycrtbuilder_->slot_count();
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



        void Receiver::stream_decrypt(
            oc::Channel &channel,
            std::vector<std::vector<ExFieldElement>> &result,
            seal::util::Pointer& backing)
        {
            vector<vector<Plaintext>> plaintext_matrix;

            int num_of_splits = params_.number_of_splits(),
                num_of_batches = params_.number_of_batches(),
                block_count = num_of_splits * num_of_batches,
                split_idx = 0,
                batch_idx = 0,
                slot_count = exfieldpolycrtbuilder_->slot_count();

            Plaintext p;
            Ciphertext tmp;

            result = ex_field_->allocate_elements(num_of_splits, num_of_batches * slot_count, backing);
            Pointer batch_backing;
            vector<ExFieldElement> batch;

            if (!polycrtbuilder_)
            {
                batch = ex_field_->allocate_elements(slot_count, batch_backing);
            }
            vector<uint64_t> integer_batch((!!polycrtbuilder_) * slot_count);

            bool first = true;

            cout << "Decrypting " << block_count << " blocks (splits = " << num_of_splits << ")" << endl;
            while (block_count-- > 0)
            {
                //unique_ptr<Ciphertext> tmp(new Ciphertext());

                channel.recv(split_idx);
                channel.recv(batch_idx);
                receive_ciphertext(tmp, channel);
                decrypt(tmp, p);
                auto& rr = result[split_idx];

                if (first)
                {
                    first = false;
                    stop_watch.set_time_point("receiver recv-start");
                }


                if (polycrtbuilder_)
                {
                    vector<uint64_t> integer_batch;
                    polycrtbuilder_->decompose(p, integer_batch, pool_);

                    for (int k = 0; k < integer_batch.size(); k++)
                        *rr[batch_idx * slot_count + k].pointer(0) = integer_batch[k];
                }
                else
                {
                    exfieldpolycrtbuilder_->decompose(p, batch);
                    for (int k = 0; k < batch.size(); k++)
                        rr[batch_idx * slot_count + k] = batch[k];
                }

            }
        }



        //void Receiver::decompose(const std::vector<std::vector<seal::Plaintext>> &plain_matrix,
        //	std::vector<std::vector<seal::util::ExFieldElement>> &result)
        //{
        //	int num_of_splits = params_.number_of_splits(),
        //		num_of_batches = params_.number_of_batches(),
        //		slot_count = exfieldpolycrtbuilder_->slot_count();

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
        //std::vector<seal::util::ExFieldElement>& result,
        //seal::util::Pointer& backing)
        //     {
        //         int slot_count = exfieldpolycrtbuilder_->slot_count();
        //         
        //         vector<ExFieldElement> result = ex_field_->allocate_elements(ciphers.size() * slot_count, backing);
        //         Pointer tmp_backing;
        //         vector<ExFieldElement> temp = ex_field_->allocate_elements(slot_count, tmp_backing);
        //         for (int i = 0; i < ciphers.size(); i++)
        //         {
        //             if (polycrtbuilder_)
        //             {
        //                 vector<uint64_t> integer_batch = polycrtbuilder_->decompose(decryptor_->decrypt(ciphers[i]));
        //                 for (int j = 0; j < integer_batch.size(); j++)
        //                     *temp[j].pointer(0) = integer_batch[j];
        //             }
        //             else
        //             {
        //                 exfieldpolycrtbuilder_->decompose(decryptor_->decrypt(ciphers[i]), temp);
        //             }
        //             for(int j = 0; j < temp.size(); j++)
        //                 result[i * slot_count + j] = temp[j];
        //         }
        //         //return result;
        //     }

        //void Receiver::decrypt(const seal::Ciphertext &cipher, vector<ExFieldElement> &batch)
        //{
        //    Plaintext plain;
        //    decrypt(cipher, plain);
        //    decompose(plain, batch);
        //}

        void Receiver::decrypt(const seal::Ciphertext &cipher, Plaintext &plain)
        {
            decryptor_->decrypt(cipher, plain);
            //cout << "Noise budget: " << decryptor_->invariant_noise_budget(cipher) << endl;
        }

        //void Receiver::decompose(const Plaintext &plain, std::vector<seal::util::ExFieldElement> &batch)
        //{

        //}

    }
}