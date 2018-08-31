// STD
#include <thread>
#include <future>
#include <chrono>
#include <array>

// APSI
#include "apsi/sender/sender.h"
#include "apsi/apsidefines.h"
#include "apsi/network/network_utils.h"
#include "apsi/tools/ec_utils.h"
#include "apsi/tools/utils.h"
#include "apsi/tools/prng.h"
#include "apsi/result_package.h"

// SEAL
#include "seal/util/common.h"

// FourQ
#include "FourQ_api.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace apsi::tools;
using namespace apsi::network;

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
            seal_context_ = SEALContext::Create(params_.encryption_params());

            // Create the poly_mod like this since FField constructor takes seal::BigPoly instead 
            // of seal::PolyModulus. Reason for this is that seal::PolyModulus does not manage its own memory.
            // const BigPoly poly_mod(ex_field_->length(), ex_field_->ch().bit_count(),
            //     const_cast<uint64_t*>(ex_field_->poly_modulus().get()));

            // Construct shared Evaluator and BatchEncoder
            evaluator_.reset(new Evaluator(seal_context_));
            vector<shared_ptr<FField> > field_vec;
            if (seal_context_->context_data()->qualifiers().enable_batching)
            {
                auto ex_field = FField::Acquire(
                    params_.exfield_characteristic(),
                    params_.exfield_degree());
                batch_encoder_.reset(new BatchEncoder(seal_context_));
                for (unsigned i = 0; i < batch_encoder_->slot_count(); i++)
                {
                    field_vec.emplace_back(ex_field);
                }
            }
            else
            {
                ex_batch_encoder_.reset(new FFieldFastBatchEncoder(
                    params_.exfield_characteristic(),
                    params_.exfield_degree(),
                    get_power_of_two(params_.encryption_params().poly_modulus_degree())
                ));
                field_vec = ex_batch_encoder_->fields();
            }

            // Create SenderDB
            sender_db_.reset(new SenderDB(params_, seal_context_, field_vec));

            compressor_.reset(new CiphertextCompressor(seal_context_, evaluator_));

            vector<thread> thrds(total_thread_count_);

#ifdef USE_SECURE_SEED
            prng_.set_seed(sysRandomSeed());
#else
            TODO("***************** INSECURE *****************, define USE_SECURE_SEED to fix");
            prng_.set_seed(ZeroBlock);
#endif

            // Set local exfields for multi-threaded efficient use of memory pools.
            for (int i = 0; i < total_thread_count_; i++)
            {
                available_thread_contexts_.push_back(i);
                auto seed = prng_.get<block>();
                thrds[i] = thread([&, i, seed]()
                {
                    auto local_pool = MemoryPoolHandle::New();
                    thread_contexts_[i].set_id(i);
                    thread_contexts_[i].set_prng(seed);
                    thread_contexts_[i].set_pool(local_pool);
                    thread_contexts_[i].set_exfield(field_vec);

                    // Allocate memory for repeated use from the given memory pool.
                    thread_contexts_[i].construct_variables(params_);
                });
            }

            for (auto &thrd : thrds)
            {
                thrd.join();
            }

            prng_.set_seed(ZeroBlock);
        }

        void Sender::load_db(const vector<Item> &data, MatrixView<u8> vals)
        {
            sender_db_->set_data(data, vals, total_thread_count_);
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
                    if (i == 0)
                        stop_watch.set_time_point("symmpoly_start");

                    //setThreadName("sender_offline_" + std::to_string(i));
                    int thread_context_idx = acquire_thread_context();
                    SenderThreadContext &context = thread_contexts_[thread_context_idx];
                    sender_db_->batched_randomized_symmetric_polys(context, evaluator_, batch_encoder_, ex_batch_encoder_, total_thread_count_);

                    if (i == 0)
                        stop_watch.set_time_point("symmpoly_done");
                    if (params_.get_label_bit_count())
                    {
                        sender_db_->batched_interpolate_polys(context, total_thread_count_, evaluator_, batch_encoder_, ex_batch_encoder_);

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
                vector<u8> buff;
                chl.receive(buff);

                PRNG pp(CCBlock);
                digit_t key[NWORDS_ORDER];
                random_fourq(key, pp);
                auto iter = buff.data();
                auto step = (sizeof(digit_t) * NWORDS_ORDER) - 1;
                digit_t x[NWORDS_ORDER];
                u64 num = buff.size() / step;

                for (u64 i = 0; i < num; i++)
                {
                    buffer_to_eccoord(iter, x);
                    Montgomery_multiply_mod_order(x, key, x);
                    eccoord_to_buffer(x, iter);

                    iter += step;
                }

                chl.send(buff);
            }

            FFieldArray* ptr = nullptr;
            // if (params_.debug())
            // {
            //     ptr = new FFieldArray(ex_field_);
            //     receive_ffield_array(*ptr, chl);
            // }
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
            int num_of_powers;
            chl.receive(num_of_powers);

            vector<vector<Ciphertext>> powers(params_.batch_count());
            auto split_size_plus_one = params_.split_size() + 1;

            for (u64 i = 0; i < powers.size(); ++i)
            {
                powers[i].reserve(split_size_plus_one);
                for (u64 j = 0; j < split_size_plus_one; ++j)
                    powers[i].emplace_back(params_.encryption_params(), pool_);

            }
            while (num_of_powers-- > 0)
            {
                uint64_t power;
                chl.receive(power);

                for (u64 i = 0; i < powers.size(); ++i)
                {
                    receive_ciphertext(powers[i][power], chl);
                }
            }

            /* Answer the query. */
            respond(powers, session_context, chl);
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
                throw std::runtime_error("No decryptor available");

            session_context.decryptor_->decrypt(c, p);

            if (batch_encoder_)
            {
                std::vector<u64> integer_batch;
                batch_encoder_->decompose(p, integer_batch, pool_);

                dest.set_zero();

                for (int i = 0; i < dest.size(); ++i)
                {
                    dest.set_coeff_of(i, 0, integer_batch[i]);
                }
            }
            else
            {
                ex_batch_encoder_->decompose(p, dest);
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
        std::vector<u64> Sender::debug_eval_term(
            int term,
            MatrixView<u64> coeffs,
            gsl::span<u64> x,
            const seal::SmallModulus& mod,
            bool print)
        {
            if (x.size() != coeffs.rows())
                throw std::runtime_error("Size of x should be same as coeffs.rows");

            std::vector<u64> r(x.size());

            for (int i = 0; i < x.size(); ++i)
            {
                auto xx = pow(x[i], term, mod);

                r[i] = (xx * coeffs(term, i)) % mod.value();

                if (i == 0 && print)
                {
                    std::cout << xx << " * " << coeffs(term, i) << " -> " << r[i] << " " << term << std::endl;
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


        std::vector<u64> add(gsl::span<u64> x, gsl::span<u64> y, const seal::SmallModulus& mod)
        {
            std::vector<u64> r(x.size());
            for (int i = 0; i < r.size(); ++i)
            {
                r[i] = x[i] + y[i] % mod.value();
            }

            return r;
        }





        void Sender::respond(
            vector<vector<Ciphertext>>& powers,
            SenderSessionContext &session_context,
            Channel &channel)
        {
            //vector<vector<Ciphertext>> resultVec(params_.split_count());
            //for (auto& v : resultVec) v.resize(params_.batch_count());
            stop_watch.set_time_point("sender online start");

            //vector<pair<promise<void>, shared_future<void>>>
            //    batch_powers_computed(params_.batch_count());
            //for (auto& pf : batch_powers_computed) pf.second = pf.first.get_future();

            auto batch_count = params_.batch_count();
            int split_size_plus_one = params_.split_size() + 1;
            int	splitStep = batch_count * split_size_plus_one;
            int total_blocks = params_.split_count() * batch_count;


            session_context.encryptor()->encrypt(BigPoly(string("1")), powers[0][0]);
            for (u64 i = 1; i < powers.size(); ++i)
            {
                powers[i][0] = powers[0][0];
            }


            auto& plain_mod = params_.encryption_params().plain_modulus();

            WindowingDag dag(params_.split_size(), params_.window_size());
            std::vector<WindowingDag::State> states; states.reserve(batch_count);
            for (u64 i = 0; i < batch_count; ++i)
                states.emplace_back(dag);

            atomic<int> remaining_batches(session_thread_count_);
            promise<void> batches_done_prom;
            auto batches_done_fut = batches_done_prom.get_future().share();

            vector<thread> thread_pool(session_thread_count_);
            for (int i = 0; i < thread_pool.size(); i++)
            {
                thread_pool[i] = thread([&, i]()
                {
                    /* Multiple client sessions can enter this function to compete for thread context resources. */
                    int thread_context_idx = acquire_thread_context();
                    auto& thread_context = thread_contexts_[thread_context_idx];
                    thread_context.construct_variables(params_);
                    auto local_pool = thread_context.pool();

                    Ciphertext tmp(local_pool);
                    Ciphertext compressedResult(
                        seal_context_->context_data(seal_context_->last_parms_id())->parms(), local_pool);

                    u64 batch_start = i * batch_count / thread_pool.size();
                    auto thread_idx = std::this_thread::get_id();

                    for (u64 batch = batch_start, loop_idx = 0ul; loop_idx < batch_count; ++loop_idx)
                    {
                        compute_batch_powers(batch, powers[batch], session_context, thread_context, dag, states[batch]);
                        batch = (batch + 1) % batch_count;
                    }

                    auto count = remaining_batches--;
                    if(count == 1)
                    {
                        batches_done_prom.set_value();
                    }
                    else
                    {
                        batches_done_fut.get();
                    }

                    int start_block = i * total_blocks / total_thread_count_;
                    int end_block = (i + 1) * total_blocks / total_thread_count_;

                    // constuct two ciphertext to store the result.  One keeps track of the current result, 
                    // one is used as a temp. Their roles switch each iteration. Saved needing to make a 
                    // copy in eval->add(...)
                    array<Ciphertext, 2> runningResults{ thread_context.pool(), thread_context.pool() },
                        label_results{ thread_context.pool(), thread_context.pool() };


                    for (int block_idx = start_block; block_idx < end_block; block_idx++)
                    {
                        int batch = block_idx / params_.split_count(),
                            split = block_idx % params_.split_count();
                        auto& block = sender_db_->get_block(batch, split);

                        // Get the pointer to the first poly of this batch.
                        //Plaintext* sender_coeffs(&sender_db_.batch_random_symm_polys()[split * splitStep + batch * split_size_plus_one]);

                        // Iterate over the coeffs multiplying them with the query powers  and summing the results
                        char currResult = 0, curr_label = 0;

                        // TODO: optimize this to allow low degree poly? need to take into account noise levels.

                        // TODO: This can be optimized to reduce the number of multiply_plain_ntt by 1.
                        // Observe that the first call to mult is always multiplying coeff[0] by 1....
                        // IMPORTANT: Both inputs are in NTT transformed form so internally SEAL will call multiply_plain_ntt
                        evaluator_->multiply_plain(powers[batch][0], block.batch_random_symm_poly_[0], runningResults[currResult]);

                        for (int s = 1; s <= params_.split_size(); s++)
                        {
                            // IMPORTANT: Both inputs are in NTT transformed form so internally SEAL will call multiply_plain_ntt
                            evaluator_->multiply_plain(powers[batch][s], block.batch_random_symm_poly_[s], tmp);
                            evaluator_->add(tmp, runningResults[currResult], runningResults[currResult ^ 1]);
                            currResult ^= 1;
                        }


                        if (params_.get_label_bit_count())
                        {
                            if (block.batched_label_coeffs_.size() > 1)
                            {
                                if (i == 0)
                                    stop_watch.set_time_point("online interpolate start");

                                // TODO: This can be optimized to reduce the number of multiply_plain_ntt by 1.
                                // Observe that the first call to mult is always multiplying coeff[0] by 1....

                                // TODO: edge case where all block.batched_label_coeffs_[s] are zero.

                                // label_result = coeff[0] * x^0 = coeff[0];
                                int s = 0;
                                while (block.batched_label_coeffs_[s].is_zero()) ++s;

                                // IMPORTANT: Both inputs are in NTT transformed form so internally SEAL will call multiply_plain_ntt
                                evaluator_->multiply_plain(powers[batch][s], block.batched_label_coeffs_[s], label_results[curr_label]);


                                while (++s < block.batched_label_coeffs_.size())
                                {
                                    // label_result += coeff[s] * x^s;
                                    if (block.batched_label_coeffs_[s].is_zero() == false)
                                    {
                                        // IMPORTANT: Both inputs are in NTT transformed form so internally SEAL will call multiply_plain_ntt
                                        evaluator_->multiply_plain(powers[batch][s], block.batched_label_coeffs_[s], tmp);
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
                                if (i == 0)
                                    stop_watch.set_time_point("online interpolate done");
                            }
                            else if (block.batched_label_coeffs_.size())
                            {
                                // only reachable if user calls PSIParams.set_use_low_degree_poly(true);

                                // TODO: This can be optimized to reduce the number of multiply_plain_ntt by 1.
                                // Observe that the first call to mult is always multiplying coeff[0] by 1....

                                // TODO: edge case where block.batched_label_coeffs_[0] is zero. 

                                // IMPORTANT: Both inputs are in NTT transformed form so internally SEAL will call multiply_plain_ntt
                                evaluator_->multiply_plain(powers[batch][0], block.batched_label_coeffs_[0], label_results[curr_label]);
                            }
                            else
                            {
                                // only reachable if user calls PSIParams.set_use_low_degree_poly(true);
                                // doesn't matter what we set... this will due.
                                label_results[curr_label] = powers[batch][0];
                            }

                            // TODO: We need to randomize the result. This is fine for now.
                            evaluator_->add(runningResults[currResult], label_results[curr_label], label_results[curr_label ^ 1]);
                            curr_label ^= 1;

                            evaluator_->transform_from_ntt(label_results[curr_label]);

                        }

                        // Transform back from ntt form.
                        evaluator_->transform_from_ntt(runningResults[currResult]);

                        // Send the result over the network if needed.
                        
                        // First compress
                        compressor_->mod_switch(runningResults[currResult], compressedResult);

                        // Send the compressed result
                        ResultPackage pkg;
                        pkg.split_idx = split;
                        pkg.batch_idx = batch;

                        {
                            stringstream ss;
                            compressor_->compressed_save(compressedResult, ss);
                            pkg.data = ss.str();
                        }

                        if (params_.get_label_bit_count())
                        {
                            // Compress label
                            compressor_->mod_switch(label_results[currResult], compressedResult);

                            stringstream ss;
                            compressor_->compressed_save(compressedResult, ss);
                            pkg.label_data = ss.str();
                        }

                        channel.send(pkg);
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
            vector<Ciphertext> &batch_powers,
            SenderSessionContext &session_context,
            SenderThreadContext &thread_context,
            const WindowingDag& dag,
            WindowingDag::State & state)
        {
            auto thrdIdx = std::this_thread::get_id();

            if (batch_powers.size() != params_.split_size() + 1)
            {
                std::cout << batch_powers.size() << " != " << params_.split_size() + 1 << std::endl;
                throw std::runtime_error("");
            }

            MemoryPoolHandle local_pool = thread_context.pool();

            int idx = (*state.next_node_)++;
            while (idx < dag.nodes_.size())
            {
                auto& node = dag.nodes_[idx];
                auto& node_state = state.nodes_[node.output_];
                //ostreamLock(std::cout) << thrdIdx << " " << idx << " " << node.output_ << std::endl;

                // a simple write should be sufficient but lets be safe
                auto exp = WindowingDag::NodeState::Ready;
                bool r = node_state.compare_exchange_strong(exp, WindowingDag::NodeState::Pending);//, std::memory_order::memory_order_relaxed);
                if (r == false)
                {
                    std::cout << int(exp) << std::endl;
                    throw std::runtime_error("");
                }
                // spin lock on the input nodes
                for (u64 i = 0; i < 2; ++i)
                    while (state.nodes_[node.inputs_[i]] != WindowingDag::NodeState::Done);//, std::memory_order::memory_order_acquire);

                //std::cout << node.inputs_[0] << " * " << node.inputs_[2] << " -> " << node.output_ << std::endl;


                evaluator_->multiply(batch_powers[node.inputs_[0]], batch_powers[node.inputs_[1]], batch_powers[node.output_], local_pool);
                evaluator_->relinearize(batch_powers[node.output_], session_context.evaluation_keys_, local_pool);

                // a simple write should be sufficient but lets be safe
                exp = WindowingDag::NodeState::Pending;
                r = node_state.compare_exchange_strong(exp, WindowingDag::NodeState::Done);//, std::memory_order::memory_order_release);
                if (r == false)
                    throw std::runtime_error("");

                idx = (*state.next_node_)++;

            }

            //// splin lock until all nodes are compute. We may want to do something smarter here.
            for (u64 i = 0; i < state.nodes_.size(); ++i)
                while (state.nodes_[i] != WindowingDag::NodeState::Done);

            //for (int i = 1; i <= params_.split_size(); i++)
            //{
            //    int i1 = optimal_split(i, 1 << params_.window_size());
            //    int i2 = i - i1;
            //    if (i1 == 0 || i2 == 0)
            //    {
            //        //batch_powers2.emplace_back(batch_powers[i]);
            //    }
            //    else
            //    {
            //        //batch_powers2.emplace_back(local_pool);
            //        std::cout << i1 << " * " << i2 << " -> " << i << std::endl;
            //        //evaluator_->multiply(batch_powers[i1], batch_powers[i2], batch_powers[i], local_pool);
            //        //evaluator_->relinearize(batch_powers[i], session_context.evaluation_keys_, batch_powers[i], local_pool);
            //    }
            //}


            //#define DEBUG_POWERS
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
                    ex_batch_encoder_->decompose(p, dest);

                    if (dest != cur_power)
                    {
                        std::cout << "power = " << i << std::endl;

                        for (u64 j = 0; j < cur_power.size(); ++j)
                        {
                            std::cout << "exp[" << j << "]: " << cur_power.get(j) << "\t act[" << j << "]: " << dest.get(j) << std::endl;

                        }

                        throw std::runtime_error("bad power");
                    }

                    cur_power = cur_power * plain_batch;
                }
            }
#endif

            auto end = dag.nodes_.size() + batch_powers.size();
            while (idx < end)
            {
                auto i = idx - dag.nodes_.size();

            //for(u64 i =0; i< batch_powers.size(); ++i)
            //{
                //ostreamLock(std::cout) << "transform[" << i << "] " << batch_powers[i].hash_block()[0] << std::endl;
                evaluator_->transform_to_ntt(batch_powers[i]);
                idx = (*state.next_node_)++;
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

        u64 WindowingDag::pow(u64 base, u64 e)
        {
            u64 r = 1;
            while (e--) r *= base;
            return r;
        }
        uint64_t WindowingDag::optimal_split(uint64_t x, int base)
        {
            vector<uint64_t> digits = conversion_to_digits(x, base);
            int ndigits = digits.size();
            int hammingweight = 0;
            for (int i = 0; i < ndigits; i++)
            {
                hammingweight += static_cast<int>(digits[i] != 0);
            }
            int target = hammingweight / 2;
            int now = 0;
            uint64_t result = 0;
            for (int i = 0; i < ndigits; i++)
            {
                if (digits[i] != 0)
                {
                    now++;
                    result += pow(base, i)*digits[i];
                }
                if (now >= target)
                {
                    break;
                }
            }
            return result;
        }
        vector<uint64_t> WindowingDag::conversion_to_digits(uint64_t input, int base)
        {
            vector<uint64_t> result;
            while (input > 0)
            {
                result.push_back(input % base);
                input /= base;
            }
            return result;
        }
        void WindowingDag::compute_dag()
        {
            std::vector<int>
                depth(max_power_ + 1),
                splits(max_power_ + 1),
                items_per(max_power_, 0);

            for (int i = 1; i <= max_power_; i++)
            {
                int i1 = optimal_split(i, 1 << window_);
                int i2 = i - i1;
                splits[i] = i1;

                if (i1 == 0 || i2 == 0)
                {
                    base_powers_.emplace_back(i);
                    //std::cout << "s[" << i << "] = input[" << i << "]" << std::endl;
                    depth[i] = 1;
                }
                else
                {
                    depth[i] = depth[i1] + depth[i2];
                    ++items_per[depth[i]];

                    //std::cout << std::string(depth[i], ' ') << "s[" << i << "] = s[" << i1 << "] s[" << i2 << "]" << std::endl;
                }
            }

            for (int i = 3; i < max_power_ && items_per[i]; ++i)
            {
                items_per[i] += items_per[i - 1];
            }
            //for (int i = 0; i < max_power_; ++i)
            //{
            //    std::cout << "items_per[" << i << "] " << items_per[i] << std::endl;
            //}

            int size = max_power_ - base_powers_.size();
            nodes_.resize(size);

            for (int i = 1; i <= max_power_; i++)
            {
                int i1 = splits[i];
                int i2 = i - i1;

                if (i1 && i2)
                {
                    auto d = depth[i] - 1;
                    //std::cout
                    //    << "i " << i
                    //    << " d" << d
                    //    << " idx" << items_per[d] << std::endl;

                    auto idx = items_per[d]++;
                    if (nodes_[idx].output_)
                        throw std::runtime_error("");

                    nodes_[idx].inputs_ = { i1,i2 };
                    nodes_[idx].output_ = i;

                }
            }

            //for (auto& n : nodes_)
            //{
            //    std::cout << "n[" << n.output_ << "] = n[" << n.inputs_[0] << "] n[" << n.inputs_[1] << "]" << std::endl;
            //}

        }

        WindowingDag::State::State(WindowingDag & dag)
        {
            next_node_.reset(new std::atomic<int>);
            *next_node_ = 0;
            node_state_storage_.reset(new std::atomic<NodeState>[dag.max_power_ + 1]);
            nodes_ = { node_state_storage_.get(), dag.max_power_ + 1 };

            for (auto& n : nodes_)
                n = NodeState::Ready;

            nodes_[0] = NodeState::Done;
            for (auto& n : dag.base_powers_)
            {
                nodes_[n] = NodeState::Done;
            }
        }
    }
}
