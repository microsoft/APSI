#include "Sender/sender.h"
#include "apsidefines.h"
#include <thread>
#include <mutex>

#include "Network/network_utils.h"
#include "cryptoTools/Common/Log.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace oc;

namespace apsi
{
    namespace sender
    {
        Sender::Sender(const PSIParams &params, const MemoryPoolHandle &pool, bool dummy_init)
            :params_(params),
            pool_(pool),
            ex_field_(ExField::Acquire(params.exfield_characteristic(), params.exfield_polymod(), pool)),
            sender_db_(params, ex_field_, dummy_init),
            thread_contexts_(params.sender_total_thread_count()),
            stopped_(false)
        {
            initialize();
        }

        void Sender::initialize()
        {
            enc_params_.set_poly_modulus("1x^" + to_string(params_.poly_degree()) + " + 1");
            enc_params_.set_coeff_modulus(params_.coeff_modulus());
            enc_params_.set_plain_modulus(ex_field_->coeff_modulus()); // Assume the prime 'p' is always smaller than 64 bits.

            seal_context_.reset(new SEALContext(enc_params_));
            local_session_.reset(new SenderSessionContext(seal_context_, params_.sender_total_thread_count()));

            ex_field_->init_frob_table();
            const BigPoly poly_mod(ex_field_->coeff_count(), ex_field_->coeff_uint64_count() * bits_per_uint64,
                const_cast<uint64_t*>(ex_field_->poly_modulus().get()));


            std::vector<std::thread> thrds(params_.sender_total_thread_count());
            /* Set local exfields for multithreaded efficient use of memory pools. */
            for (int i = 0; i < params_.sender_total_thread_count(); i++)
            {
                available_thread_contexts_.push_back(i);
                thrds[i] = std::thread([&, i]()
                {

                    auto local_mph = MemoryPoolHandle::New(false);

                    thread_contexts_[i].set_id(i);

                    thread_contexts_[i].set_exfield(ExField::Acquire(ex_field_->characteristic(),
                        poly_mod, local_mph));
                    thread_contexts_[i].exfield()->set_frob_table(ex_field_->frobe_table());

                    if (seal_context_->qualifiers().enable_batching)
                        thread_contexts_[i].set_builder(make_shared<PolyCRTBuilder>(*seal_context_, local_mph));

                    thread_contexts_[i].set_exbuilder(make_shared<ExFieldPolyCRTBuilder>(thread_contexts_[i].exfield(), params_.log_poly_degree()));

                    thread_contexts_[i].construct_variables(params_);
                });
            }

            for (auto& thrd : thrds)
                thrd.join();


            prng_.SetSeed(oc::ZeroBlock);
            //curve_.setParameters(oc::Curve25519);


        }

        Sender::~Sender()
        {
            //apsi_endpoint_->stop();
        }

        void Sender::set_public_key(const PublicKey &public_key)
        {
            local_session_->set_public_key(public_key);
        }

        void Sender::set_evaluation_keys(const seal::EvaluationKeys &evaluation_keys)
        {
            /* This is a special local session with maximum threads. */
            local_session_->set_evaluation_keys(evaluation_keys);
        }

        void Sender::set_secret_key(const SecretKey &secret_key)
        {
            local_session_->set_secret_key(secret_key);
        }

        void Sender::load_db(const std::vector<Item> &data)
        {
            sender_db_.set_data(data);
            stop_watch.set_time_point("Sender set-data");

            offline_compute();
        }


        void Sender::offline_compute()
        {
            vector<thread> thread_pool(params_.sender_total_thread_count());
            for (int i = 0; i < params_.sender_total_thread_count(); i++)
            {
                thread_pool[i] = std::thread([&, i]()
                {
                    int thread_context_idx = acquire_thread_context();
                    auto& context = thread_contexts_[thread_context_idx];
                    context.construct_variables(params_);

                    /* Update the context with the session's specific keys. */
                    context.set_encryptor(local_session_->encryptor_);
                    context.set_evaluator(local_session_->local_evaluators_[i]);

                    sender_db_.batched_randomized_symmetric_polys(context);

                    release_thread_context(context.id());
                });
            }

            for (int i = 0; i < thread_pool.size(); i++)
                thread_pool[i].join();
        }


        void Sender::query_engine(std::string ipPort, IOService& ios)
        {
            std::list<std::thread> thrds;
            while (true)
            {
                // create a new session with a client
                Session newSession(ios, ipPort, SessionMode::Server);
                Channel chl = newSession.addChannel();

                // wait for the socket to connect
                while (chl.waitForConnection(chrono::milliseconds(500)) == false)
                {
                    // abort if we stop the Sender
                    if (stopped_)
                    {
                        // cancel the pending connection
                        chl.cancel();

                        // join the pending threads
                        for (auto& t : thrds) t.join();

                        return;
                    }
                }

                // splin off a thread to process the client's request.
                thrds.emplace_back(thread([this, chl]() mutable
                {
                    query_session(chl);

                }));
            }
        }

        void Sender::query_session(Channel &chl)
        {
            if (params_.use_pk_oprf())
            {
                EllipticCurve curve(p256k1, prng_.get<oc::block>());
                PRNG pp(oc::CCBlock);
                oc::EccNumber key_(curve, pp);

                auto step = curve.getGenerator().sizeBytes();
                std::vector<u8> buff;
                chl.recv(buff);

                //ostreamLock out(std::cout);
                auto iter = buff.data();
                oc::EccPoint x(curve);
                u64 num = buff.size() / step;
                for (u64 i = 0; i < num; ++i)
                {
                    x.fromBytes(iter);

                    x *= key_;

                    //out << "x " << i << " " << x << std::endl;

                    x.toBytes(iter);

                    iter += step;
                }

                chl.asyncSend(buff);
            }



            /* Set up keys. */
            PublicKey pub;
            EvaluationKeys eval;
            receive_pubkey(pub, chl);
            receive_evalkeys(eval, chl);
            SenderSessionContext session_context(seal_context_, pub, eval, params_.sender_session_thread_count());

            /* Receive client's query data. */
            int num_of_powers = 0;
            chl.recv(num_of_powers);
            map<uint64_t, vector<Ciphertext>> query;
            while (num_of_powers-- > 0)
            {
                uint64_t power = 0;
                chl.recv(power);
                query[power] = vector<Ciphertext>();
                receive_ciphertext(query[power], chl);
            }

            /* Answer to the query. */
            respond(query, session_context, chl);



            try
            {
                std::array<int, 2> printIdx;

                while (true)
                {
                    chl.recv(printIdx);
                    if (printIdx[0] == -1) return;

                    auto start = printIdx[1] * params_.split_size();
                    auto end = start + params_.split_size();

                    ostreamLock o(std::cout);

                    for (int i = start; i < end; ++i)
                    {
                        o << "s[" << printIdx[0] << "][" << i << "] = " << sender_db_.simple_hashing_db2_(i, printIdx[0]) << std::endl;
                    }

                    o << "---------------------------------------" << std::endl;
                    //if (sender_db_.has_item(printIdx[0], printIdx[1]))
                    //{
                    //    std::cout << "sender has an item at " << printIdx[0] << " " << printIdx[1] << std::endl;
                    //}
                    //else
                    //{
                    //    std::cout << "sender does NOT have an item at " << printIdx[0] << " " << printIdx[1] << std::endl;

                    //}
                }
            }
            catch (std::exception& e) {
                std::cout << "channel: " << e.what() << std::endl;
            }

        }

        void Sender::stop()
        {
            stopped_ = true;
        }

        void Sender::respond(
            const map<uint64_t, vector<Ciphertext>> &query, SenderSessionContext &session_context,
            Channel &channel)
        {
            //vector<vector<Ciphertext>> resultVec(params_.number_of_splits());
            //for (auto& v : resultVec) v.resize(params_.number_of_batches());
            vector<vector<Ciphertext>> powers(params_.number_of_batches());

            std::vector<std::pair<std::promise<void>, std::shared_future<void>>>
                batch_powers_computed(params_.number_of_batches());
            for (auto& pf : batch_powers_computed) pf.second = pf.first.get_future();

            auto number_of_batches = params_.number_of_batches();
            int split_size_plus_one = params_.split_size() + 1;
            int	splitStep = params_.number_of_batches() * split_size_plus_one;
            int total_blocks = params_.number_of_splits() * params_.number_of_batches();

            mutex mtx;
            vector<thread> thread_pool(params_.sender_session_thread_count());
            for (int i = 0; i < thread_pool.size(); i++)
            {
                thread_pool[i] = thread([&, i]()
                {
                    /* Multiple client sessions can enter this function to compete for thread context resources. */
                    int thread_context_idx = acquire_thread_context();
                    auto& context = thread_contexts_[thread_context_idx];
                    context.construct_variables(params_);

                    /* Update the context with the session's specific keys. */
                    context.set_encryptor(session_context.encryptor_);
                    context.set_evaluator(session_context.local_evaluators_[i]);

                    Ciphertext tmp;
                    shared_ptr<Evaluator>& local_evaluator = context.evaluator();

                    auto batch_start = i * number_of_batches / thread_pool.size();
                    auto batch_end = (i + 1) * number_of_batches / thread_pool.size();

                    for (auto batch = batch_start; batch < batch_end; ++batch)
                    {
                        compute_batch_powers(batch, query, powers[batch], context);
                        batch_powers_computed[batch].first.set_value();
                    }

                    for (auto& b : batch_powers_computed)
                        b.second.get();

                    // Check if we need to re-batch things. This happens if we do an update.
                    //sender_db_.batched_randomized_symmetric_polys(context);

                    int start_block = i * total_blocks / params_.sender_total_thread_count();
                    int end_block = (i + 1) * total_blocks / params_.sender_total_thread_count();

                    // constuct two ciphertext to store the result.  One keeps track of the current result, 
                    // one is used as a temp. Their roles switch each iteration. Saved needing to make a 
                    // copy in eval->add(...)
                    std::array<seal::Ciphertext, 2> runningResults;

                    for (int block = start_block; block < end_block; block++)
                    {
                        int batch = block / params_.number_of_splits(),
                            split = block % params_.number_of_splits();

                        // if we are starting a new batch, then make sure that the batch is ready
                        //if(block== start_block || split == 0)
                        //    batch_powers_computed[batch].second.get();

                        // get the pointer to the first poly of this batch.
                        Plaintext* sender_coeffs(
                            &sender_db_.batch_random_symm_polys()[split * splitStep + batch * split_size_plus_one]);


                        //  Iterate over the coeffs multiplying them with the query powers  and summing the results
                        char currResult = 0;

                        local_evaluator->multiply_plain_ntt(powers[batch][0], sender_coeffs[0], runningResults[currResult]);
                        for (int s = 1; s <= params_.split_size(); s++)
                        {
                            local_evaluator->multiply_plain_ntt(
                                powers[batch][s],
                                sender_coeffs[s],
                                tmp);
                            local_evaluator->add(tmp, runningResults[currResult], runningResults[currResult ^ 1]);

                            currResult ^= 1;
                        }
                        //auto& result = resultVec[split][batch];
                        //result = runningResults[currResult];

                        // transform back from ntt form.
                        local_evaluator->transform_from_ntt(runningResults[currResult]);

                        // send the result over the network if needed.
                        unique_lock<mutex> net_lock2(mtx);
                        channel.asyncSendCopy(split);
                        channel.asyncSendCopy(batch);
                        send_ciphertext(runningResults[currResult], channel);
                    }

                    /* After this point, this thread will no longer use the context resource, so it is free to return it. */
                    release_thread_context(context.id());
                });
            }

            for (int i = 0; i < thread_pool.size(); i++)
                thread_pool[i].join();

            //return std::move(resultVec);
        }

        void Sender::compute_batch_powers(int batch, const std::map<uint64_t, std::vector<seal::Ciphertext>> &input,
            std::vector<seal::Ciphertext> &batch_powers, SenderThreadContext &context)
        {
            batch_powers.resize(params_.split_size() + 1);
            shared_ptr<Evaluator> local_evaluator = context.evaluator();
            context.encryptor()->encrypt(BigPoly("1"), batch_powers[0], pool_);
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
                    local_evaluator->relinearize(batch_powers[i], local_session_->evaluation_keys_, batch_powers[i]);

                }

            }
            for (int i = 0; i <= params_.split_size(); i++)
                local_evaluator->transform_to_ntt(batch_powers[i]);
        }

        //void Sender::compute_dot_product(int split, int batch, const vector<vector<Ciphertext>> &all_powers, 
        //    Ciphertext &result, SenderThreadContext &context)
        //{            


        //}

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
    }
}
