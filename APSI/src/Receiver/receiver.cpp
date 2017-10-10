#include "Receiver/receiver.h"
#include "util/uintcore.h"
#include "encryptionparams.h"
#include "keygenerator.h"
#include "Sender/sender.h"
#include "apsidefines.h"
#include <sstream>
#include "Network/byte_stream.h"
#include "Network/network_utils.h"


using namespace std;
using namespace seal;
using namespace seal::util;
using namespace cuckoo;
using namespace apsi::tools;
using namespace apsi::network;

namespace apsi
{
    namespace receiver
    {
        Receiver::Receiver(const PSIParams &params, const MemoryPoolHandle &pool)
            :params_(params), 
            pool_(pool),
            ex_field_(ExField::Acquire(params.exfield_characteristic(), params.exfield_polymod(), pool)),
            ios_(new BoostIOService(0))
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
            generator.generate();

            public_key_ = generator.public_key();
            secret_key_ = generator.secret_key();

            encryptor_.reset(new Encryptor(seal_context, public_key_));
            decryptor_.reset(new Decryptor(seal_context, secret_key_));

            evaluation_keys_ = generator.generate_evaluation_keys(params_.decomposition_bit_count());

            exfieldpolycrtbuilder_.reset(new ExFieldPolyCRTBuilder(ex_field_, params_.log_poly_degree()));

            if(seal_context.get_qualifiers().enable_batching)
                polycrtbuilder_.reset(new PolyCRTBuilder(seal_context));
            
            ex_field_->init_frob_table();
        }

        vector<bool> Receiver::query(const vector<Item> &items, apsi::sender::Sender &sender)
        {
            clear_memory_backing();

            unique_ptr<PermutationBasedCuckoo> cuckoo = cuckoo_hashing(items);

            vector<int> indices = cuckoo_indices(items, *cuckoo);

            vector<ExFieldElement> exfield_items = exfield_encoding(*cuckoo);

            map<uint64_t, vector<ExFieldElement>> powers = generate_powers(exfield_items);

            map<uint64_t, vector<Ciphertext>> ciphers = encrypt(powers);
            stop_watch.set_time_point("Receiver encryption");

            /* Send to sender. */
            vector<vector<Ciphertext>> result_ciphers = sender.respond(ciphers);
            stop_watch.set_time_point("Sender online");
            vector<vector<ExFieldElement>> result = bulk_decrypt(result_ciphers);
            stop_watch.set_time_point("Receiver decryption");

            vector<bool> tmp(params_.table_size(), false);
            ExFieldElement zero(ex_field_);
            for (int i = 0; i < params_.table_size(); i++)
            {
                bool match_found = false;
                for(int j = 0; j < params_.number_of_splits(); j++)
                {
                    if (result[j][i] == zero)
                    {
                        match_found = true;
                        break;
                    }
                }
                if (match_found)
                    tmp[i] = true;
            }

            /* Now we need to shorten and convert this tmp vector to match the length and indice of the query "items". */
            vector<bool> intersection(items.size(), false);
            for (int i = 0; i < indices.size(); i++)
                intersection[i] = tmp[indices[i]];

            return intersection;
        }

        vector<bool> Receiver::query(const vector<Item> &items, string ip, uint64_t port)
        {
            clear_memory_backing();

            auto query_data = preprocess(items);

            /* Create communication channel. */
            BoostEndpoint client(*ios_, ip, port, false, "APSI");
            Channel& client_channel = client.addChannel("-", "-");

            send(query_data.first, client_channel);

            /* Receive results in a streaming fashion. */
            vector<vector<ExFieldElement>> result = stream_decrypt(client_channel);            

            vector<bool> tmp(params_.table_size(), false);
            ExFieldElement zero(ex_field_);
            for (int i = 0; i < params_.table_size(); i++)
            {
                bool match_found = false;
                for (int j = 0; j < params_.number_of_splits(); j++)
                {
                    if (result[j][i] == zero)
                    {
                        match_found = true;
                        break;
                    }
                }
                if (match_found)
                    tmp[i] = true;
            }

            /* Now we need to shorten and convert this tmp vector to match the length and indice of the query "items". */
            vector<bool> intersection(items.size(), false);
            for (int i = 0; i < query_data.second.size(); i++)
                intersection[i] = tmp[query_data.second[i]];

            client_channel.close();
            client.stop();

            return intersection;
        }

        void Receiver::query(const std::vector<Item> &items, std::string ip, uint64_t port,
            std::vector<std::vector<seal::Plaintext>> &intermediate_result, vector<int> &indices)
        {
            clear_memory_backing();

            auto query_data = preprocess(items);
            indices = move(query_data.second);

            /* Create communication channel. */
            BoostEndpoint client(*ios_, ip, port, false, "APSI");
            Channel& client_channel = client.addChannel("-", "-");

            send(query_data.first, client_channel);

            /* Receive results in a streaming fashion. */
            stream_decrypt(client_channel, intermediate_result);

            client_channel.close();
            client.stop();
        }

        void Receiver::query(const std::vector<Item> &items, apsi::network::Channel &channel,
            std::vector<std::vector<seal::Plaintext>> &intermediate_result, vector<int> &indices)
        {
            clear_memory_backing();

            auto query_data = preprocess(items);
            indices = move(query_data.second);

            send(query_data.first, channel);

            /* Receive results in a streaming fashion. */
            stream_decrypt(channel, intermediate_result);
        }

        void Receiver::query(const std::map<uint64_t, std::vector<seal::Ciphertext>> &ciphers, apsi::network::Channel &channel,
            std::vector<std::vector<seal::Plaintext>> &intermediate_result)
        {
            clear_memory_backing();

            send(ciphers, channel);

            /* Receive results in a streaming fashion. */
            stream_decrypt(channel, intermediate_result);
        }

        std::vector<bool> Receiver::reveal_result(const std::vector<std::vector<seal::Plaintext>> &intermediate_result, const std::vector<int> &indices)
        {
            /* Receive results in a streaming fashion. */
            vector<vector<ExFieldElement>> result;
            decompose(intermediate_result, result);

            vector<bool> tmp(params_.table_size(), false);
            ExFieldElement zero(ex_field_);
            for (int i = 0; i < params_.table_size(); i++)
            {
                bool match_found = false;
                for (int j = 0; j < params_.number_of_splits(); j++)
                {
                    if (result[j][i] == zero)
                    {
                        match_found = true;
                        break;
                    }
                }
                if (match_found)
                    tmp[i] = true;
            }

            /* Now we need to shorten and convert this tmp vector to match the length and indice of the query "items". */
            vector<bool> intersection(indices.size(), false);
            for (int i = 0; i < indices.size(); i++)
                intersection[i] = tmp[indices[i]];

            return intersection;
        }

        std::pair<
            std::map<uint64_t, std::vector<seal::Ciphertext>>,
            std::vector<int>
        > Receiver::preprocess(const vector<Item> &items)
        {
            unique_ptr<PermutationBasedCuckoo> cuckoo = cuckoo_hashing(items);

            vector<int> indices = cuckoo_indices(items, *cuckoo);

            vector<ExFieldElement> exfield_items = exfield_encoding(*cuckoo);

            map<uint64_t, vector<ExFieldElement>> powers = generate_powers(exfield_items);

            map<uint64_t, vector<Ciphertext>> ciphers = encrypt(powers);

            return make_pair(ciphers, indices);
        }

        void Receiver::send(const map<uint64_t, vector<Ciphertext>> &query, Channel &channel)
        {
            /* Send keys. */
            send_pubkey(public_key_, channel);
            send_evalkeys(evaluation_keys_, channel);

            /* Send query data. */
            send_int(query.size(), channel);
            for (map<uint64_t, vector<Ciphertext>>::const_iterator it = query.begin(); it != query.end(); it++)
            {
                send_uint64(it->first, channel);
                send_ciphertext(it->second, channel);
            }
        }

        unique_ptr<PermutationBasedCuckoo> Receiver::cuckoo_hashing(const vector<Item> &items)
        {
            unique_ptr<PermutationBasedCuckoo> cuckoo(
                new PermutationBasedCuckoo(params_.hash_func_count(), params_.hash_func_seed(), params_.log_table_size(), params_.item_bit_length(), params_.max_probe()));
            bool insertionSuccess;
            for (int i = 0; i < items.size(); i++)
            {
                insertionSuccess = cuckoo->insert(items[i].data());
                if (!insertionSuccess)
                    throw logic_error("cuck hashing failed.");
            }
            /* Lock to truncate the table items. */
            cuckoo->lock_table_final();
            
            return cuckoo;
        }

        std::vector<int> Receiver::cuckoo_indices(const std::vector<Item> &items, cuckoo::PermutationBasedCuckoo &cuckoo)
        {
            vector<int> indice(items.size(), -1);

            vector<uint64_t> locs;
            int bin_bit_length = cuckoo.bin_bit_length(), bin_uint64_count = cuckoo.bin_u64_length(),
                item_bit_length = cuckoo.item_bit_length(), log_capacity = cuckoo.log_capacity(),
                shifted_bin_uint64_count = (bin_bit_length - log_capacity + 63) / 64;
            unique_ptr<uint64_t> temp_item(new uint64_t[bin_uint64_count]);
            uint64_t top_u64_mask = (static_cast<uint64_t>(1) << ((item_bit_length - log_capacity) % 64)) - 1;
            for (int i = 0; i < items.size(); i++)
            {
                right_shift_uint(items[i].data(), temp_item.get(), log_capacity, bin_uint64_count); // Assuming item and bin have the same uint64_t count.
                zero_uint(temp_item.get() + shifted_bin_uint64_count, bin_uint64_count - shifted_bin_uint64_count);
                uint64_t *shifted_item_top_ptr = temp_item.get() + shifted_bin_uint64_count - 1;

                cuckoo.get_locations(items[i].data(), locs);
                for (int j = 0; j < locs.size(); j++)
                {
                    *shifted_item_top_ptr &= top_u64_mask;
                    *shifted_item_top_ptr ^= (static_cast<uint64_t>(j) << ((item_bit_length - log_capacity) % 64));

                    if (are_equal_uint(cuckoo.hash_table_item(locs[j]), temp_item.get(), bin_uint64_count))
                        indice[i] = locs[j];
                }
            }
            return indice;
        }

        vector<ExFieldElement> Receiver::exfield_encoding(const PermutationBasedCuckoo &cuckoo)
        {
            memory_backing_.emplace_back(Pointer());
            vector<ExFieldElement> exfield_items = ex_field_->allocate_elements(cuckoo.capacity(), memory_backing_.back());
            int bin_u64_len = cuckoo.bin_u64_length();
            Item item;
            for (int i = 0; i < cuckoo.capacity(); i++)
            {
                const uint64_t *cuckoo_item = cuckoo.hash_table_item(i);
                item[0] = *cuckoo_item;
                if (bin_u64_len > 1)
                    item[1] = *(cuckoo_item + 1);
                else
                    item[1] = 0;

                item.to_exfield_element(exfield_items[i]);
            }
            return exfield_items;
        }

        map<uint64_t, vector<ExFieldElement> > Receiver::generate_powers(const vector<ExFieldElement> &exfield_items)
        {
            map<uint64_t, vector<ExFieldElement> > result;
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
                        return result;
                    }
                    memory_backing_.emplace_back(Pointer());
                    result[i * (1 << (window_size * j))] = ex_field_->allocate_elements(current_power.size(), memory_backing_.back());
                    ex_field_->dyadic_multiply(result[(i - 1)*(1 << (window_size*j))], current_power, result[i * (1 << (window_size * j))]);
                }
                for (int k = 0; k < window_size; k++)
                {
                    ex_field_->dyadic_square_inplace(current_power);
                }
            }

            return result;
        }

        std::map<uint64_t, vector<Ciphertext>> Receiver::encrypt(std::map<uint64_t, std::vector<ExFieldElement>> &input)
        {
            map<uint64_t, vector<Ciphertext>> result;

            for (map<uint64_t, vector<ExFieldElement>>::iterator it = input.begin(); it != input.end(); it++)
            {
                result[it->first] = encrypt(it->second);
            }

            return result;
        }

        vector<Ciphertext> Receiver::encrypt(const vector<ExFieldElement> &input)
        {
            int batch_size = exfieldpolycrtbuilder_->slot_count(), num_of_batches = (input.size() + batch_size - 1) / batch_size;
            Pointer tmp_backing;
            vector<ExFieldElement> batch = ex_field_->allocate_elements(batch_size, tmp_backing);
            vector<uint64_t> integer_batch(batch_size, 0);
            vector<Ciphertext> result;
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
                result.emplace_back(
                    encryptor_->encrypt(plain));
            }
            return result;
        }

        vector<vector<ExFieldElement>> Receiver::bulk_decrypt(const vector<vector<Ciphertext>> &result_ciphers)
        {
            if (result_ciphers.size() != params_.number_of_splits() || result_ciphers[0].size() != params_.number_of_batches())
                throw invalid_argument("Result ciphers have unexpexted sizes.");

            int slot_count = exfieldpolycrtbuilder_->slot_count();
            memory_backing_.emplace_back(Pointer());
            vector<vector<ExFieldElement>> result = ex_field_->allocate_elements(
                result_ciphers.size(), result_ciphers[0].size() * slot_count, memory_backing_.back());
            Pointer tmp_backing;
            vector<ExFieldElement> temp = ex_field_->allocate_elements(slot_count, tmp_backing);
            for (int i = 0; i < result_ciphers.size(); i++)
                for(int j = 0; j < result_ciphers[0].size(); j++)
                {
                    decrypt(result_ciphers[i][j], temp);
                    for (int k = 0; k < temp.size(); k++)
                        result[i][j * slot_count + k] = temp[k];
                }
            cout << "Remaining Nosie Budget: " << decryptor_->invariant_noise_budget(result_ciphers[0][0]) << endl;

            return result;
        }

        vector<vector<ExFieldElement>> Receiver::stream_decrypt(Channel &channel)
        {
            vector<vector<ExFieldElement>> result;
            stream_decrypt(channel, result);
            return result;
        }

        void Receiver::stream_decrypt(Channel &channel, vector<vector<ExFieldElement>> &result)
        {
            vector<vector<Plaintext>> plaintext_matrix;
            stream_decrypt(channel, plaintext_matrix);
            decompose(plaintext_matrix, result);
        }

        void Receiver::stream_decrypt(apsi::network::Channel &channel, std::vector<std::vector<seal::Plaintext>> &result)
        {
            int num_of_splits = params_.number_of_splits(), num_of_batches = params_.number_of_batches();
            result.resize(num_of_splits, vector<Plaintext>(num_of_batches));
            
            int block_count = num_of_splits * num_of_batches, split_idx = 0, batch_idx = 0;
            Ciphertext tmp;

            /*atomic<int> running_threads = 0;
            auto decrypt_computation = [&](unique_ptr<Ciphertext> cipher, Plaintext &plain)
            {
                decrypt(*cipher, plain);
                running_threads--;
            };*/

            while (block_count-- > 0)
            {
                //unique_ptr<Ciphertext> tmp(new Ciphertext());

                receive_int(split_idx, channel);
                receive_int(batch_idx, channel);
                receive_ciphertext(tmp, channel);
                decrypt(tmp, result[split_idx][batch_idx]);
                //receive_ciphertext(*tmp, channel);

                /*while (running_threads >= params_.receiver_thread_count())
                    this_thread::sleep_for(chrono::milliseconds(10));
                running_threads++;
                thread decrypt_thread(decrypt_computation, move(tmp), ref(result[split_idx][batch_idx]));
                decrypt_thread.detach();*/
            }
            /*while (running_threads > 0)
                this_thread::sleep_for(chrono::milliseconds(10));*/
        }

        vector<ExFieldElement> Receiver::decrypt(const vector<Ciphertext> &ciphers)
        {
            int slot_count = exfieldpolycrtbuilder_->slot_count();
            memory_backing_.emplace_back(Pointer());
            vector<ExFieldElement> result = ex_field_->allocate_elements(ciphers.size() * slot_count, memory_backing_.back());
            Pointer tmp_backing;
            vector<ExFieldElement> temp = ex_field_->allocate_elements(slot_count, tmp_backing);
            for (int i = 0; i < ciphers.size(); i++)
            {
                if (polycrtbuilder_)
                {
                    vector<uint64_t> integer_batch = polycrtbuilder_->decompose(decryptor_->decrypt(ciphers[i]));
                    for (int j = 0; j < integer_batch.size(); j++)
                        *temp[j].pointer(0) = integer_batch[j];
                }
                else
                {
                    exfieldpolycrtbuilder_->decompose(decryptor_->decrypt(ciphers[i]), temp);
                }
                for(int j = 0; j < temp.size(); j++)
                    result[i * slot_count + j] = temp[j];
            }
            return result;
        }

        void Receiver::decrypt(const seal::Ciphertext &cipher, vector<ExFieldElement> &batch)
        {
            Plaintext plain;
            decrypt(cipher, plain);
            decompose(plain, batch);
        }

        void Receiver::decrypt(const seal::Ciphertext &cipher, Plaintext &plain)
        {
            decryptor_->decrypt(cipher, plain);
        }

        void Receiver::decompose(const Plaintext &plain, std::vector<seal::util::ExFieldElement> &batch)
        {
            if (polycrtbuilder_)
            {
                vector<uint64_t> integer_batch = polycrtbuilder_->decompose(plain);
                for (int j = 0; j < integer_batch.size(); j++)
                    *batch[j].pointer(0) = integer_batch[j];
            }
            else
            {
                exfieldpolycrtbuilder_->decompose(plain, batch);
            }
        }

        void Receiver::decompose(const std::vector<std::vector<seal::Plaintext>> &plain_matrix,
            std::vector<std::vector<seal::util::ExFieldElement>> &result)
        {
            int num_of_splits = params_.number_of_splits(), num_of_batches = params_.number_of_batches(),
                slot_count = exfieldpolycrtbuilder_->slot_count();
            memory_backing_.emplace_back(Pointer());
            result = ex_field_->allocate_elements(
                num_of_splits, num_of_batches * slot_count, memory_backing_.back());
            Pointer batch_backing;
            vector<ExFieldElement> batch = ex_field_->allocate_elements(slot_count, batch_backing);

            for (int i = 0; i < num_of_splits; i++)
            {
                for (int j = 0; j < num_of_batches; j++)
                {
                    decompose(plain_matrix[i][j], batch);
                    for (int k = 0; k < batch.size(); k++)
                    {
                        result[i][j * slot_count + k] = batch[k];
                    }
                }
            }
        }

    }
}