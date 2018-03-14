#include <thread>
#include <future>
#include <chrono>
#include <array>

#include "apsi/sender/sender.h"
#include "apsi/apsidefines.h"
#include "apsi/network/network_utils.h"

#include "cryptoTools/Common/Log.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace oc;

namespace apsi
{
    namespace sender
    {
        Sender::Sender(const PSIParams &params, const MemoryPoolHandle &pool) : 
            params_(params),
            pool_(pool),
            ex_field_(ExField::Acquire(params.exfield_characteristic(), params.exfield_polymod(), pool)),
            sender_db_(params, ex_field_),
            thread_contexts_(params.sender_total_thread_count()),
            stopped_(false)
        {
            initialize();
        }

        void Sender::initialize()
        {
            enc_params_.set_poly_modulus("1x^" + to_string(params_.poly_degree()) + " + 1");
            enc_params_.set_coeff_modulus(params_.coeff_modulus());
            enc_params_.set_plain_modulus(ex_field_->coeff_modulus());

            seal_context_.reset(new SEALContext(enc_params_));

            ex_field_->init_frob_table();

            // Create the poly_mod like this since seal::ExField constructor takes seal::BigPoly instead 
            // of seal::PolyModulus. Reason for this is that seal::PolyModulus does not manage its own memory.
            const BigPoly poly_mod(ex_field_->coeff_count(), ex_field_->coeff_uint64_count() * bits_per_uint64,
                const_cast<uint64_t*>(ex_field_->poly_modulus().get()));

            // Construct shared Evaluator and PolyCRTBuilder
            evaluator_.reset(new Evaluator(*seal_context_));
            builder_.reset(new PolyCRTBuilder(*seal_context_));

            vector<thread> thrds(params_.sender_total_thread_count());

            // Set local exfields for multi-threaded efficient use of memory pools.
            for (int i = 0; i < params_.sender_total_thread_count(); i++)
            {
                available_thread_contexts_.push_back(i);
                thrds[i] = thread([&, i]()
                {
                    auto local_pool = MemoryPoolHandle::New(false);
                    thread_contexts_[i].set_id(i);
                    thread_contexts_[i].set_pool(local_pool);
                    thread_contexts_[i].set_exfield(ExField::Acquire(ex_field_->characteristic(), poly_mod, local_pool));
                    thread_contexts_[i].exfield()->set_frob_table(ex_field_->frobe_table());

                    // We need the ExFIeldPolyCRTBuilder here since it creates ExFieldElements from the memory
                    // pool of its ExField. Cannot have a shared ExFieldPolyCRTBuilder with this design.
                    thread_contexts_[i].set_exbuilder(
                        make_shared<ExFieldPolyCRTBuilder>(thread_contexts_[i].exfield(), 
                            params_.log_poly_degree())
                    );
                    
                    // Allocate memory for repeated use from the given memory pool.
                    thread_contexts_[i].construct_variables(params_);
                });
            }

            for (auto &thrd : thrds)
            {
                thrd.join();
            }

            prng_.SetSeed(oc::ZeroBlock);
        }

        void Sender::load_db(const vector<Item> &data)
        {
            sender_db_.set_data(data);
            stop_watch.set_time_point("Sender set-data");

            // Compute symmetric polys and batch
            offline_compute();
        }

        void Sender::offline_compute()
        {
            vector<thread> thread_pool(params_.sender_total_thread_count());
            for (int i = 0; i < params_.sender_total_thread_count(); i++)
            {
                thread_pool[i] = thread([&, i]()
                {
                    int thread_context_idx = acquire_thread_context();
                    SenderThreadContext &context = thread_contexts_[thread_context_idx];

                    sender_db_.batched_randomized_symmetric_polys(context, evaluator_, builder_);

                    release_thread_context(context.id());
                });
            }

            for (int i = 0; i < thread_pool.size(); i++) 
            {
                thread_pool[i].join();
            }
        }

        void Sender::query_session(Channel &chl)
        {
            // Send the EC point when using OPRF
            if (params_.use_pk_oprf())
            {
                EllipticCurve curve(p256k1, prng_.get<oc::block>());
                PRNG pp(oc::CCBlock);
                oc::EccNumber key_(curve, pp);

                auto step = curve.getGenerator().sizeBytes();
                vector<u8> buff;
                chl.recv(buff);

                //ostreamLock out(cout);
                auto iter = buff.data();
                oc::EccPoint x(curve);
                u64 num = buff.size() / step;
                for (u64 i = 0; i < num; i++)
                {
                    x.fromBytes(iter);
                    x *= key_;
                    x.toBytes(iter);
                    iter += step;
                }

                chl.asyncSend(buff);
            }

            /* Set up and receive keys. */
            PublicKey pub;
            EvaluationKeys eval;
            receive_pubkey(pub, chl);
            receive_evalkeys(eval, chl);
            SenderSessionContext session_context(seal_context_, pub, eval);

            /* Receive client's query data. */
            int num_of_powers = 0;
            chl.recv(num_of_powers);
            map<uint64_t, vector<Ciphertext> > query;
            while (num_of_powers-- > 0)
            {
                uint64_t power = 0;
                chl.recv(power);
                query[power] = vector<Ciphertext>();
                receive_ciphertext(query[power], chl);
            }

            /* Answer the query. */
            respond(query, session_context, chl);
        }

        void Sender::stop()
        {
            stopped_ = true;
        }

        void Sender::respond(
            const map<uint64_t, vector<Ciphertext> > &query, 
            SenderSessionContext &session_context,
            Channel &channel)
        {
            //vector<vector<Ciphertext>> resultVec(params_.number_of_splits());
            //for (auto& v : resultVec) v.resize(params_.number_of_batches());
            vector<vector<Ciphertext> > powers(params_.number_of_batches());

            vector<pair<promise<void>, shared_future<void> > >
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
                    auto& thread_context = thread_contexts_[thread_context_idx];
                    thread_context.construct_variables(params_);

                    ///* Update the context with the session's specific keys. */
                    //context.set_encryptor(session_context.encryptor_);
                    //context.set_evaluator(session_context.evaluator_);

                    Ciphertext tmp(thread_context.pool());
                    //shared_ptr<Evaluator>& local_evaluator = context.evaluator();

                    auto batch_start = i * number_of_batches / thread_pool.size();
                    auto batch_end = (i + 1) * number_of_batches / thread_pool.size();

                    for (auto batch = batch_start; batch < batch_end; ++batch)
                    {
                        compute_batch_powers(batch, query, powers[batch], session_context, thread_context);
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
                    array<Ciphertext, 2> runningResults;

                    for (int block = start_block; block < end_block; block++)
                    {
                        int batch = block / params_.number_of_splits(),
                            split = block % params_.number_of_splits();

                        // Get the pointer to the first poly of this batch.
                        Plaintext* sender_coeffs(&sender_db_.batch_random_symm_polys()[split * splitStep + batch * split_size_plus_one]);

                        // Iterate over the coeffs multiplying them with the query powers  and summing the results
                        char currResult = 0;

                        evaluator_->multiply_plain_ntt(powers[batch][0], sender_coeffs[0], runningResults[currResult]);
                        for (int s = 1; s <= params_.split_size(); s++)
                        {
                            evaluator_->multiply_plain_ntt(powers[batch][s], sender_coeffs[s], tmp);
                            evaluator_->add(tmp, runningResults[currResult], runningResults[currResult ^ 1]);
                            currResult ^= 1;
                        }

                        // Transform back from ntt form.
                        evaluator_->transform_from_ntt(runningResults[currResult]);

                        // Send the result over the network if needed.
                        unique_lock<mutex> net_lock2(mtx);
                        channel.asyncSendCopy(split);
                        channel.asyncSendCopy(batch);
                        send_ciphertext(runningResults[currResult], channel);
                    }

                    /* After this point, this thread will no longer use the context resource, so it is free to return it. */
                    release_thread_context(thread_context.id());
                });
            }

            for (int i = 0; i < thread_pool.size(); i++)
            { 
                thread_pool[i].join();
            }
        }

        void Sender::compute_batch_powers(
            int batch, 
            const map<uint64_t, vector<Ciphertext> > &input, 
            vector<Ciphertext> &batch_powers, 
            SenderSessionContext &session_context, 
            SenderThreadContext &thread_context)
        {
            batch_powers.resize(params_.split_size() + 1);
            MemoryPoolHandle local_pool = thread_context.pool();

            //shared_ptr<Evaluator> local_evaluator = context.evaluator();
            session_context.encryptor()->encrypt(BigPoly("1"), batch_powers[0], local_pool);

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
                    evaluator_->multiply(batch_powers[i1], batch_powers[i2], batch_powers[i], local_pool);
                    evaluator_->relinearize(batch_powers[i], session_context.evaluation_keys_, batch_powers[i], local_pool);
                }

            }
            for (int i = 0; i <= params_.split_size(); i++)
            {
                evaluator_->transform_to_ntt(batch_powers[i]);
            }
        }

        int Sender::acquire_thread_context()
        {
            // Multiple threads can enter this function to compete for thread context resources.
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
                {
                    this_thread::sleep_for(chrono::milliseconds(50));
                }
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
