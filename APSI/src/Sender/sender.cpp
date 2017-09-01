#include "Sender/sender.h"
#include "apsidefines.h"
#include <thread>
#include <mutex>
#include "Network/boost_endpoint.h"
#include "Network/network_utils.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace apsi::network;

namespace apsi
{
    namespace sender
    {
        Sender::Sender(const PSIParams &params, const MemoryPoolHandle &pool)
            :params_(params),
            pool_(pool),
            ex_field_(ExField::acquire_field(params.exfield_characteristic(), params.exfield_polymod(), pool)),
            sender_db_(params, ex_field_),
            thread_contexts_(params.sender_total_thread_count()),
            ios_(new BoostIOService(0)),
            stopped_(false)
        {
            initialize();
        }

        void Sender::initialize()
        {
            enc_params_.set_poly_modulus("1x^" + to_string(params_.poly_degree()) + " + 1");
            enc_params_.set_coeff_modulus(params_.coeff_modulus());
            enc_params_.set_plain_modulus(ex_field_->coeff_modulus()); // Assume the prime 'p' is always smaller than 64 bits.
            enc_params_.set_decomposition_bit_count(params_.decomposition_bit_count());

            seal_context_.reset(new RNSContext(enc_params_));
            local_session_.reset(new SenderSessionContext(seal_context_, params_.sender_total_thread_count()));

            ex_field_->init_frobe_table();
            const BigPoly poly_mod(ex_field_->coeff_count(), ex_field_->coeff_uint64_count() * bits_per_uint64, 
                const_cast<uint64_t*>(ex_field_->poly_modulus().get()));

            /* Set local exfields for multithreaded efficient use of memory pools. */
            for (int i = 0; i < params_.sender_total_thread_count(); i++)
            {
                available_thread_contexts_.push_back(i);

                thread_contexts_[i].set_id(i);

                thread_contexts_[i].set_exfield(ExField::acquire_field(ex_field_->characteristic(),
                    poly_mod, MemoryPoolHandle::acquire_new(false)));
                thread_contexts_[i].exfield()->set_frobe_table(ex_field_->frobe_table());

                if(seal_context_->get_qualifiers().enable_batching)
                    thread_contexts_[i].set_builder(make_shared<RNSPolyCRTBuilder>(*seal_context_, MemoryPoolHandle::acquire_new(false)));

                thread_contexts_[i].set_exbuilder(make_shared<ExFieldPolyCRTBuilder>(thread_contexts_[i].exfield(), params_.log_poly_degree()));

            }

            apsi_endpoint_.reset(new BoostEndpoint(*ios_, "127.0.0.1", params_.apsi_port(), true, params_.apsi_endpoint()));
        }

        Sender::~Sender()
        {
            apsi_endpoint_->stop();
        }

        void Sender::set_public_key(const PublicKey &public_key)
        {
            local_session_->set_public_key(public_key);
        }

        void Sender::set_evaluation_keys(const seal::RNSEvaluationKeys &evaluation_keys)
        {
            /* This is a special local session with maximum threads. */
            local_session_->set_evaluation_keys(evaluation_keys, params_.sender_total_thread_count());
        }

        void Sender::set_secret_key(const SecretKey &secret_key)
        {
            local_session_->set_secret_key(secret_key);
        }

        void Sender::load_db(const std::vector<Item> &data)
        {
            sender_db_.set_data(data);

            offline_compute();
        }

        
        void Sender::offline_compute()
        {
            /* Offline pre-processing. */
            atomic<int> block_index = 0;
            auto block_computation = [&](SenderThreadContext& context)
            {
                int next_block = 0;
                while (true)
                {
                    next_block = block_index++;
                    if (next_block >= params_.number_of_splits() * params_.number_of_batches())
                        break;
                    int split = next_block / params_.number_of_batches(), batch = next_block % params_.number_of_batches();
                    sender_db_.batched_randomized_symmetric_polys(split, batch, context);
                }
                /* After this point, this thread will no longer use the context resource, so it is free to return it. */
                release_thread_context(context.id());
            };

            vector<thread> thread_pool;
            for (int i = 0; i < params_.sender_total_thread_count(); i++)
            {
                int thread_context_idx = acquire_thread_context();

                /* Update the context with the session's specific keys. */
                thread_contexts_[thread_context_idx].set_encryptor(local_session_->encryptor_);
                thread_contexts_[thread_context_idx].set_evaluator(local_session_->local_evaluators_[i]);

                // Must use 'std::ref' to pass by reference when we construct thread with a lambda function that takes reference arguments.
                // But if we just call the lambda function, then we don't need 'std::ref'.
                thread_pool.push_back(thread(block_computation, std::ref(thread_contexts_[thread_context_idx])));
            }

            for (int i = 0; i < thread_pool.size(); i++)
                thread_pool[i].join();
        }


        void Sender::query_engine(BoostEndpoint* sharing_endpoint)
        {
            while (true && !stopped_)
            {
                Channel* server_channel = apsi_endpoint_->getNextQueuedChannel();
                if (server_channel == nullptr)
                {
                    this_thread::sleep_for(chrono::milliseconds(50));
                    continue;
                }
                Channel* sharing_channel = nullptr;
                if (sharing_endpoint)
                {
                    receive_int(current_receiver_id_, *server_channel);
                    if(current_receiver_id_ != ((sender_id_ + 1) % 3)) // Only pass the other share if the target is not the receiver.
                        sharing_channel = &(sharing_endpoint->addChannel("-", "-"));
                }
                
                thread session(&Sender::query_session, this, server_channel, sharing_channel);
                session.detach();
            }
        }

        void Sender::query_session(Channel *server_channel, Channel *sharing_channel)
        {
            /* Set up keys. */
            PublicKey pub;
            RNSEvaluationKeys eval;
            receive_pubkey(pub, *server_channel);
            receive_evalkeys(eval, *server_channel);
            SenderSessionContext session_context(seal_context_, pub, eval, params_.sender_session_thread_count());

            /* Receive client's query data. */
            int num_of_powers = 0;
            receive_int(num_of_powers, *server_channel);
            map<uint64_t, vector<Ciphertext>> query;
            while (num_of_powers-- > 0)
            {
                uint64_t power = 0;
                receive_uint64(power, *server_channel);
                query[power] = vector<Ciphertext>();
                receive_ciphertext(query[power], *server_channel);
            }

            /* Answer to the query. */
            respond(query, session_context, server_channel, sharing_channel);

            server_channel->close();
            if(sharing_channel)
                sharing_channel->close();
        }

        void Sender::stop()
        {
            stopped_ = true;
        }

        vector<vector<Ciphertext>> Sender::respond(
            const map<uint64_t, vector<Ciphertext>> &query, SenderSessionContext &session_context, 
            Channel *channel, Channel *sharing_channel)
        {
            vector<vector<Ciphertext>> result(params_.number_of_splits(), vector<Ciphertext>(params_.number_of_batches()));

            vector<vector<Ciphertext>> powers;
            compute_all_powers(query, powers, session_context);

            atomic<int> block_index = 0;
            mutex mtx1, mtx2;
            auto block_computation = [&](SenderThreadContext &context)
            {
                int next_block = 0;
                while (true)
                {
                    next_block = block_index++;
                    if (next_block >= params_.number_of_splits() * params_.number_of_batches())
                        break;
                    int split = next_block / params_.number_of_batches(), batch = next_block % params_.number_of_batches();
                    compute_dot_product(split, batch, powers, result[split][batch], context);

                    if (channel)
                    {
                        if (sharing)
                        {
                            vector<Plaintext> shares = share(result[split][batch], session_context);
                            unique_lock<mutex> net_lock1(mtx1);
                            if(sharing_channel)
                                send_share(split, batch, shares[0], sharing_channel);
                            else
                                insert_share(split, batch, move(shares[0]));
                        }

                        unique_lock<mutex> net_lock2(mtx2);
                        send_int(split, *channel);
                        send_int(batch, *channel);
                        send_ciphertext(result[split][batch], *channel);
                    }
                }
                /* After this point, this thread will no longer use the context resource, so it is free to return it. */
                release_thread_context(context.id());
            };
            
            vector<thread> thread_pool;
            for (int i = 0; i < params_.sender_session_thread_count(); i++)
            {
                /* Multiple client sessions can enter this function to compete for thread context resources. */
                int thread_context_idx = acquire_thread_context();

                /* Update the context with the session's specific keys. */
                thread_contexts_[thread_context_idx].set_encryptor(session_context.encryptor_);
                thread_contexts_[thread_context_idx].set_evaluator(session_context.local_evaluators_[i]);

                // Must use 'std::ref' to pass by reference when we construct thread with a lambda function that takes reference arguments.
                // But if we just call the lambda function, then we don't need 'std::ref'.
                thread_pool.push_back(thread(block_computation, std::ref(thread_contexts_[thread_context_idx]))); 
            }

            for (int i = 0; i < thread_pool.size(); i++)
                thread_pool[i].join();

            return result;
        }

        void Sender::compute_all_powers(const map<uint64_t, vector<Ciphertext>> &input, 
            vector<vector<Ciphertext>> &all_powers,
            SenderSessionContext &session_context)
        {
            all_powers.resize(params_.number_of_batches());
            atomic<int> batch_index = 0;
            auto batch_computation = [&](SenderThreadContext &context)
            {
                int next_batch = 0;
                while (true)
                {
                    next_batch = batch_index++;
                    if (next_batch >= params_.number_of_batches())
                        break;
                    compute_batch_powers(next_batch, input, all_powers[next_batch], context);
                }
                /* After this point, this thread will no longer use the context resource, so it is free to return it. */
                release_thread_context(context.id());
            };

            vector<thread> thread_pool;
            for (int i = 0; i < params_.sender_session_thread_count() && i < params_.number_of_batches(); i++)
            {
                /* Multiple client sessions can enter this function to compete for thread context resources. */
                int thread_context_idx = acquire_thread_context();

                /* Update the context with the session's specific keys. */
                thread_contexts_[thread_context_idx].set_encryptor(session_context.encryptor_);
                thread_contexts_[thread_context_idx].set_evaluator(session_context.local_evaluators_[i]);

                // Must use 'std::ref' to pass by reference when we construct thread with a lambda function that takes reference arguments.
                // But if we just call the lambda function, then we don't need 'std::ref'.
                thread_pool.push_back(thread(batch_computation, std::ref(thread_contexts_[thread_context_idx])));
            }

            for (int i = 0; i < thread_pool.size(); i++)
                thread_pool[i].join();
        }

        void Sender::compute_batch_powers(int batch, const std::map<uint64_t, std::vector<seal::Ciphertext>> &input,
            std::vector<seal::Ciphertext> &batch_powers, SenderThreadContext &context)
        {
            batch_powers.resize(params_.split_size() + 1);
            shared_ptr<RNSEvaluator> local_evaluator = context.evaluator();
            batch_powers[0] = context.encryptor()->rns_encrypt(BigPoly("1"));
            for (int i = 1; i <= params_.split_size(); i++)
            {
                int i1 = optimal_split(i, 1 << params_.window_size());
                int i2 = i - i1;
                if (i1 == 0 || i2 == 0)
                {
                    batch_powers[i] = input.at(i)[batch];
                }
                else
                {
                    local_evaluator->multiply(batch_powers[i1], batch_powers[i2], batch_powers[i]);
                    local_evaluator->relinearize(batch_powers[i], batch_powers[i]);

                }

            }
            for (int i = 0; i <= params_.split_size(); i++)
                local_evaluator->transform_to_ntt(batch_powers[i]);
        }

        void Sender::compute_dot_product(int split, int batch, const vector<vector<Ciphertext>> &all_powers, 
            Ciphertext &result, SenderThreadContext &context)
        {
            vector<Plaintext>& sender_coeffs = sender_db_.batched_randomized_symmetric_polys(split, batch, context);
            
            Ciphertext tmp;

            shared_ptr<RNSEvaluator> local_evaluator = context.evaluator();

            local_evaluator->multiply_plain_ntt(all_powers[batch][0], sender_coeffs[0], result);
           
            for (int s = 1; s <= params_.split_size(); s++)
            {
                local_evaluator->multiply_plain_ntt(
                    all_powers[batch][s],
                    sender_coeffs[s],
                    tmp);
                local_evaluator->add(tmp, result, result);
            }

            local_evaluator->transform_from_ntt(result);

            /* TODO: Noise truncation? */

        }

        int Sender::acquire_thread_context()
        {
            /* Multiple threads can enter this function to compete for thread context resources. */
            int thread_context_idx = -1;
            while (thread_context_idx == -1)
            {
                if (!available_thread_contexts_.empty())
                {
                    unique_lock<mutex> lock(thread_context_mtx_);
                    if (!available_thread_contexts_.empty())
                    {
                        thread_context_idx = available_thread_contexts_.front();
                        available_thread_contexts_.pop_front();
                    }
                }
                else
                    this_thread::sleep_for(chrono::milliseconds(50));
            }

            return thread_context_idx;
        }

        void Sender::release_thread_context(int idx)
        {
            unique_lock<mutex> lock(thread_context_mtx_);
            available_thread_contexts_.push_back(idx);
        }



        /********************Below for secret sharing*****************************/

        vector<Plaintext> Sender::share(Ciphertext& cipher, SenderSessionContext &session_contex, int num_of_shares)
        {
            if (num_of_shares != 2)
                throw invalid_argument("Invalid number of shares.");

            vector<Plaintext> shares;
            Plaintext random_share = random_plaintext(enc_params_);
            /*Ciphertext enc_share = session_contex.encryptor_->rns_encrypt(random_share);
            session_contex.evaluator_->sub(cipher, enc_share, cipher);*/
            session_contex.evaluator_->sub_plain(cipher, random_share, cipher);
            shares.emplace_back(move(random_share));
            return shares;
        }

        void Sender::insert_share(int split, int batch, Plaintext&& plain_share)
        {
            shares_[make_pair(split, batch)] = move(plain_share);
        }

        void Sender::send_share(int split, int batch, const seal::Plaintext& share, apsi::network::Channel *channel)
        {
            send_int(split, *channel);
            send_int(batch, *channel);
            send_plaintext(share, *channel);
        }

        Plaintext& Sender::get_share(int split, int batch)
        {
            return shares_.at(make_pair(split, batch));
        }

    }
}