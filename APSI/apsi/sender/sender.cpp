#include <thread>
#include <future>
#include <chrono>
#include <array>

#include "apsi/sender/sender.h"
#include "apsi/apsidefines.h"
#include "apsi/network/network_utils.h"

#include "seal/util/common.h"

#include "cryptoTools/Common/Log.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace oc;

namespace apsi
{
    namespace sender
    {
        Sender::Sender(const PSIParams &params, int total_thread_count,
            int session_thread_count, const MemoryPoolHandle &pool) :
            params_(params),
            pool_(pool),
            total_thread_count_(total_thread_count),
            session_thread_count_(session_thread_count),
            ex_field_(FField::Acquire(params.exfield_characteristic(), params.exfield_polymod())),
            sender_db_(params, ex_field_),
            thread_contexts_(total_thread_count_),
            stopped_(false)
        {
            if (session_thread_count_ <= 0 || (session_thread_count_ > total_thread_count_))
            {
                throw invalid_argument("invalid thread count");
            }
            initialize();
        }

        void Sender::initialize()
        {
            seal_context_.reset(new SEALContext(params_.encryption_params()));

            // Create the poly_mod like this since FField constructor takes seal::BigPoly instead 
            // of seal::PolyModulus. Reason for this is that seal::PolyModulus does not manage its own memory.
            // const BigPoly poly_mod(ex_field_->length(), ex_field_->ch().bit_count(),
            //     const_cast<uint64_t*>(ex_field_->poly_modulus().get()));

            // Construct shared Evaluator and PolyCRTBuilder
            evaluator_.reset(new Evaluator(*seal_context_));
            vector<shared_ptr<FField> > field_vec;
            if (seal_context_->qualifiers().enable_batching)
            {
                builder_.reset(new PolyCRTBuilder(*seal_context_));
                for(unsigned i = 0; i < builder_->slot_count(); i++)
                {
                    field_vec.emplace_back(ex_field_);
                }
            }
            else
            {
                ex_builder_.reset(new FFieldFastCRTBuilder(
                    ex_field_->ch(),
                    ex_field_->d(), 
                    get_power_of_two(params_.encryption_params().poly_modulus().coeff_count() - 1) 
                ));
                field_vec = ex_builder_->fields();
            }
            vector<thread> thrds(total_thread_count_);

#ifdef USE_SECURE_SEED
            prng_.SetSeed(oc::sysRandomSeed());
#else
            TODO("***************** INSECURE *****************, define USE_SECURE_SEED to fix");
            prng_.SetSeed(oc::ZeroBlock);
#endif

            // Set local exfields for multi-threaded efficient use of memory pools.
            for (int i = 0; i < total_thread_count_; i++)
            {
                available_thread_contexts_.push_back(i);
                auto seed = prng_.get<oc::block>();
                thrds[i] = thread([&, i, seed]()
                {
                    auto local_pool = MemoryPoolHandle::New(false);
                    thread_contexts_[i].set_id(i);
                    thread_contexts_[i].set_prng(seed);
                    thread_contexts_[i].set_pool(local_pool);
                    thread_contexts_[i].set_exfield(field_vec);

                    // // We need the EdPolyCRTBuilder here since it creates ExFieldElements from the memory
                    // // pool of its ExField. Cannot have a shared ExFieldPolyCRTBuilder with this design.
                    // thread_contexts_[i].set_exbuilder(
                    //     make_shared<FFieldCRTBuilder>(thread_contexts_[i].exfield(),
                    //         get_power_of_two(params_.encryption_params().poly_modulus().coeff_count() - 1), FFieldElt(thread_contexts_[i].exfield(), "1x^1")
                    // ));

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

        void Sender::load_db(const vector<Item> &data, oc::MatrixView<u8> vals)
        {
            sender_db_.set_data(data, vals, total_thread_count_);
            stop_watch.set_time_point("Sender set-data");

            // Compute symmetric polys and batch
            offline_compute();
        }

        void Sender::offline_compute()
        {
            vector<thread> thread_pool(total_thread_count_);
            for (int i = 0; i < total_thread_count_; i++)
            {
                thread_pool[i] = thread([&, i]()
                {
                    if(i == 0)
                        stop_watch.set_time_point("symmpoly_start");

                    setThreadName("sender_offline_" + std::to_string(i));
                    int thread_context_idx = acquire_thread_context();
                    SenderThreadContext &context = thread_contexts_[thread_context_idx];
                    sender_db_.batched_randomized_symmetric_polys(context, evaluator_, builder_, ex_builder_, total_thread_count_);

                    if (i == 0)
                        stop_watch.set_time_point("symmpoly_done");
                    if (params_.get_label_bit_count())
                    {
                        sender_db_.batched_interpolate_polys(context, total_thread_count_, evaluator_, builder_, ex_builder_);

                        if (i == 0)
                            stop_watch.set_time_point("interpolation_done");
                    }
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

            FFieldArray* ptr = nullptr;
            if (params_.debug())
            {
                ptr = new FFieldArray(ex_field_, params_.table_size());
                receive_ffield_array(*ptr, chl);
            }
            /* Set up and receive keys. */
            PublicKey pub;
            EvaluationKeys eval;
            receive_pubkey(pub, chl);
            receive_evalkeys(eval, chl);
            SenderSessionContext session_context(seal_context_, pub, eval);

            if (params_.debug())
            {

                seal::SecretKey k;
                receive_prvkey(k, chl);
                session_context.set_secret_key(k);

                session_context.debug_plain_query_.reset(ptr);
            }

            /* Receive client's query data. */
            int num_of_powers = 0;
            chl.recv(num_of_powers);
            map<uint64_t, vector<Ciphertext> > query;
            while (num_of_powers-- > 0)
            {
                uint64_t power = 0;
                chl.recv(power);
                receive_ciphertext(query[power], chl);
            }

            /* Answer the query. */
            respond(query, session_context, chl);
        }

        void Sender::stop()
        {
            stopped_ = true;
        }

        void Sender::debug_decrypt(
            SenderSessionContext &session_context,
            const Ciphertext& c,
            FFieldArray& dest)
        {
            Plaintext p;
            if (!session_context.decryptor_)
                throw std::runtime_error(LOCATION);

            session_context.decryptor_->decrypt(c, p);

            if(builder_)
            {
                std::vector<u64> integer_batch;
                builder_->decompose(p, integer_batch, pool_);

                dest.set_zero();

                for (int i = 0; i < dest.size(); ++i)
                {
                    dest.set_coeff_of(i, 0, integer_batch[i]);
                }
            }
            else
            {
                ex_builder_->decompose(p, dest);
            }


        }

        u64 pow(u64 x, u64 p, const seal::SmallModulus& mod)
        {
            u64 r = 1;
            while (p--)
            {
                r = (r * x) % mod.value();
            }
            return x;
        }
        std::vector<oc::u64> Sender::debug_eval_term(
            int term, 
            oc::MatrixView<u64> coeffs, 
            oc::span<u64> x, 
            const seal::SmallModulus& mod, 
            bool print)
        {
            if (x.size() != coeffs.rows())
                throw std::runtime_error(LOCATION);

            std::vector<u64> r(x.size());

            for (int i = 0; i < x.size(); ++i)
            {
                auto xx = pow(x[i], term, mod);
                
                r[i] = (xx * coeffs(term, i)) % mod.value();

                if (i == 0 && print)
                {
                    std::cout << xx << " * " << coeffs(term, i) << " -> " << r[i]  << " " << term << std::endl;
                }
            }


            return r;
        }


        bool Sender::debug_not_equals(FFieldArray& true_x, const Ciphertext& c, SenderSessionContext& ctx)
        {
            FFieldArray cc(true_x.field(0), true_x.size());
            debug_decrypt(ctx, c, cc);

            //for (int i = 0; i < true_x.size(); ++i)
            //{
            //    if (true_x[i] != cc[i])
            //        return false;
            //}

            return true_x == cc;
        }


        std::vector<u64> add(span<u64> x, span<u64> y, const seal::SmallModulus& mod)
        {
            std::vector<u64> r(x.size());
            for (int i = 0; i < r.size(); ++i)
            {
                r[i] = x[i] + y[i] % mod.value();
            }

            return r;
        }

        void Sender::respond(
            const map<uint64_t, vector<Ciphertext> > &query,
            SenderSessionContext &session_context,
            Channel &channel)
        {
            //vector<vector<Ciphertext>> resultVec(params_.split_count());
            //for (auto& v : resultVec) v.resize(params_.batch_count());
            stop_watch.set_time_point("sender online start");
            vector<vector<Ciphertext> > powers(params_.batch_count());

            vector<pair<promise<void>, shared_future<void>>>
                batch_powers_computed(params_.batch_count());

            for (auto& pf : batch_powers_computed) pf.second = pf.first.get_future();

            auto batch_count = params_.batch_count();
            int split_size_plus_one = params_.split_size() + 1;
            int	splitStep = params_.batch_count() * split_size_plus_one;
            int total_blocks = params_.split_count() * params_.batch_count();

            std::vector<std::vector<u64> > debug_query(params_.batch_count());
            auto& plain_mod = params_.encryption_params().plain_modulus();

            mutex mtx;
            vector<thread> thread_pool(session_thread_count_);
            for (int i = 0; i < thread_pool.size(); i++)
            {
                thread_pool[i] = thread([&, i]()
                {
                    /* Multiple client sessions can enter this function to compete for thread context resources. */
                    int thread_context_idx = acquire_thread_context();
                    auto& thread_context = thread_contexts_[thread_context_idx];
                    thread_context.construct_variables(params_);

                    Ciphertext tmp(thread_context.pool());

                    auto batch_start = i * batch_count / thread_pool.size();
                    auto batch_end = (i + 1) * batch_count / thread_pool.size();

                    for (auto batch = batch_start; batch < batch_end; ++batch)
                    {
                        compute_batch_powers(batch, query, powers[batch], session_context, thread_context);
                        batch_powers_computed[batch].first.set_value();

                    }

                    for (auto& b : batch_powers_computed)
                        b.second.get();

                    int start_block = i * total_blocks / total_thread_count_;
                    int end_block = (i + 1) * total_blocks / total_thread_count_;

                    // constuct two ciphertext to store the result.  One keeps track of the current result, 
                    // one is used as a temp. Their roles switch each iteration. Saved needing to make a 
                    // copy in eval->add(...)
                    array<Ciphertext, 2> runningResults{ thread_context.pool(), thread_context.pool() }, 
                        label_results { thread_context.pool(), thread_context.pool() };
                    

                    for (int block_idx = start_block; block_idx < end_block; block_idx++)
                    {
                        int batch = block_idx / params_.split_count(),
                            split = block_idx % params_.split_count();
                        auto& block = sender_db_.get_block(batch, split);

                        // Get the pointer to the first poly of this batch.
                        //Plaintext* sender_coeffs(&sender_db_.batch_random_symm_polys()[split * splitStep + batch * split_size_plus_one]);

                        // Iterate over the coeffs multiplying them with the query powers  and summing the results
                        char currResult = 0, curr_label = 0;

//#define DEBUG_SYMM_EVAL
#ifdef DEBUG_SYMM_EVAL
                        auto& query = *session_context.debug_plain_query_;
                        FFieldArray plain_batch(ex_field_, params_.batch_size()), dest(ex_field_, params_.batch_size());
                        for (int i = 0, j = plain_batch.size() * batch; i < plain_batch.size(); ++i, ++j)
                        {
                            auto xj = query.get(j);
                            plain_batch.set(i, xj);
                        }
                        auto power = plain_batch;
                        auto sum = block.debug_sym_block_[0];
                        
                        auto temp = powers[batch][1];
                        evaluator_->transform_from_ntt(temp);
                        debug_decrypt(session_context, temp, dest);
                        if (dest != plain_batch)
                        {
                            std::cout << "bad query "<< std::endl;

                            for (int i = 0; i < plain_batch.size(); ++i)
                            {
                                std::cout << i << "\n   exp[" << i << "]: " << sum.get(i) << "\n   act[" << i << "]: " << dest.get(i) << std::endl;
                            }
                            throw std::runtime_error("");
                        }

#endif

                        // TODO: optimize this to allow low degree poly? need to take into account noise levels.

                        // TODO: This can be optimized to reduce the number of multiply_plain_ntt by 1.
                        // Observe that the first call to mult is always multiplying coeff[0] by 1....
                        evaluator_->multiply_plain_ntt(powers[batch][0], block.batch_random_symm_poly_[0], runningResults[currResult]);
#ifdef DEBUG_SYMM_EVAL
                        temp = runningResults[currResult];
                        evaluator_->transform_from_ntt(temp);
                        debug_decrypt(session_context, temp, dest);
                        if (sum != dest)
                        {
                            std::cout << "power " << 0 << std::endl;

                            for (int i = 0; i < plain_batch.size(); ++i)
                            {
                                std::cout << i << "\n   exp[" << i << "]: " << sum.get(i) << "\n   act[" << i << "]: " << dest.get(i) << std::endl;
                            }
                            throw std::runtime_error("");
                        }
#endif


                        for (int s = 1; s <= params_.split_size(); s++)
                        {
                            evaluator_->multiply_plain_ntt(powers[batch][s], block.batch_random_symm_poly_[s], tmp);
                            evaluator_->add(tmp, runningResults[currResult], runningResults[currResult ^ 1]);
                            currResult ^= 1;

#ifdef DEBUG_SYMM_EVAL
                            sum = sum + power * block.debug_sym_block_[s];

                            temp = runningResults[currResult];
                            evaluator_->transform_from_ntt(temp);
                            debug_decrypt(session_context, temp, dest);
                            if (sum != dest)
                            {
                                std::cout << "power " << s << std::endl;

                                for (int i = 0; i < plain_batch.size(); ++i)
                                {
                                    std::cout << i << "\n   exp[" << i << "]: " << sum.get(i) << "\n   act[" << i << "]: " << dest.get(i) << std::endl;
                                }
                                throw std::runtime_error("");
                            }

                            // x^s+1 = x^s * x
                            power = power * plain_batch;
#endif
                        }


                        if (params_.get_label_bit_count())
                        {

                            if (block.batched_label_coeffs_.size() > 1)
                            {
                                // TODO: This can be optimized to reduce the number of multiply_plain_ntt by 1.
                                // Observe that the first call to mult is always multiplying coeff[0] by 1....

                                // TODO: edge case where all block.batched_label_coeffs_[s] are zero.

                                // label_result = coeff[0] * x^0 = coeff[0];
                                int s = 0;
                                while (block.batched_label_coeffs_[s].is_zero()) ++s;


                                evaluator_->multiply_plain_ntt(powers[batch][s], block.batched_label_coeffs_[s], label_results[curr_label]);

                                // debug
                                //bool print = batch == 0 && split == 0;
                                //std::vector<u64> debug_label_results = debug_eval_term(s, block.label_coeffs, debug_query[batch], plain_mod, print);
                                //if (debug_not_equals(debug_label_results, label_results[curr_label], session_context))
                                //    throw std::runtime_error(LOCATION);

                                //if(debug_label_results.size() != params_.batch_size())
                                //    throw std::runtime_error(LOCATION);


                                while(++s < block.batched_label_coeffs_.size())
                                {
                                    // label_result += coeff[s] * x^s;
                                    if (block.batched_label_coeffs_[s].is_zero() == false)
                                    {
                                        evaluator_->multiply_plain_ntt(powers[batch][s], block.batched_label_coeffs_[s], tmp);
                                        evaluator_->add(tmp, label_results[curr_label], label_results[curr_label ^ 1]);
                                        curr_label ^= 1;


                                        // debug
                                        //{
                                        //    auto debug_term = debug_eval_term(s, block.label_coeffs, debug_query[batch], plain_mod, print);
                                        //    if (debug_not_equals(debug_term, tmp, session_context))
                                        //        throw std::runtime_error(LOCATION);

                                        //    debug_label_results = add(debug_label_results, debug_term, plain_mod);
                                        //    if (debug_not_equals(debug_label_results, label_results[curr_label], session_context))
                                        //        throw std::runtime_error(LOCATION);
                                        //}
                                    }
                                }


                                //// label_result += coeff[0];
                                //evaluator_->add_plain(label_results[curr_label], block.batched_label_coeffs_[0], label_results[curr_label ^ 1]);
                                //curr_label ^= 1;
                            }
                            else if (block.batched_label_coeffs_.size())
                            {
                                // only reachable if user calls PSIParams.set_use_low_degree_poly(true);

                                // TODO: This can be optimized to reduce the number of multiply_plain_ntt by 1.
                                // Observe that the first call to mult is always multiplying coeff[0] by 1....

                                // TODO: edge case where block.batched_label_coeffs_[0] is zero. 

                                evaluator_->multiply_plain_ntt(powers[batch][0], block.batched_label_coeffs_[0], label_results[curr_label]);
                            }
                            else
                            {
                                // only reachable if user calls PSIParams.set_use_low_degree_poly(true);
                                // doesn't matter what we set... this will due.
                                label_results[curr_label] = powers[batch][0];
                            }

                            // TODO: multiply with running_result


                            evaluator_->transform_from_ntt(label_results[curr_label]);

                        }

                        // Transform back from ntt form.
                        evaluator_->transform_from_ntt(runningResults[currResult]);

                        // Send the result over the network if needed.

                        unique_lock<mutex> net_lock2(mtx);
                        channel.asyncSendCopy(split);
                        channel.asyncSendCopy(batch);
                        send_ciphertext(runningResults[currResult], channel);

                        if (params_.get_label_bit_count())
                        {
                            send_ciphertext(label_results[curr_label], channel);
                        }
                    }

                    /* After this point, this thread will no longer use the context resource, so it is free to return it. */
                    release_thread_context(thread_context.id());
                });
            }

            for (int i = 0; i < thread_pool.size(); i++)
            {
                thread_pool[i].join();
            }

            stop_watch.set_time_point("sender online done");

        }

        void Sender::compute_batch_powers(
            int batch,
            const map<uint64_t, vector<Ciphertext> > &input,
            vector<Ciphertext> &batch_powers,
            SenderSessionContext &session_context,
            SenderThreadContext &thread_context)
        {
            batch_powers.clear();
            batch_powers.reserve(params_.split_size() + 1);
            MemoryPoolHandle local_pool = thread_context.pool();

            //shared_ptr<Evaluator> local_evaluator = context.evaluator();
            Ciphertext temp(local_pool);
            session_context.encryptor()->encrypt(BigPoly("1"), temp, local_pool);
            batch_powers.push_back(temp);

            for (int i = 1; i <= params_.split_size(); i++)
            {
                int i1 = optimal_split(i, 1 << params_.window_size());
                int i2 = i - i1;
                if (i1 == 0 || i2 == 0)
                {
                    batch_powers.emplace_back(input.at(i)[batch]);
                }
                else
                {
                    batch_powers.emplace_back(local_pool);
                    evaluator_->multiply(batch_powers[i1], batch_powers[i2], batch_powers.back(), local_pool);
                    evaluator_->relinearize(batch_powers[i], session_context.evaluation_keys_, batch_powers.back(), local_pool);
                }

            }

#ifdef DEBUG_POWERS
            if (params_.debug() && session_context.debug_plain_query_)
            {

                Plaintext p;
                if (!session_context.decryptor_)
                    throw std::runtime_error(LOCATION);


                auto& query = *session_context.debug_plain_query_;
                FFieldArray plain_batch(ex_field_, params_.batch_size()), dest(ex_field_, params_.batch_size());
                for (int i = 0, j = plain_batch.size() * batch; i < plain_batch.size(); ++i, ++j)
                {
                    auto xj = query.get(j);
                    plain_batch.set(i, xj);
                }

                auto cur_power = plain_batch;
                for (int i = 1; i < batch_powers.size(); ++i)
                {
                    session_context.decryptor_->decrypt(batch_powers[i], p);
                    ex_builder_->decompose(dest, p);

                    if (dest != cur_power)
                    {
                        std::cout << "power = " <<i << std::endl;

                        for (u64 j = 0; j < cur_power.size(); ++j)
                        {
                            std::cout << "exp["<<j<<"]: " << cur_power.get(j) << "\t act[" << j << "]: " << dest.get(j) << std::endl;

                        }

                        throw std::runtime_error("bad power");
                    }

                    cur_power = cur_power * plain_batch;
                }
            }
#endif

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
