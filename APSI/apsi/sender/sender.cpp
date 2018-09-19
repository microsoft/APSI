// STD
#include <thread>
#include <future>
#include <chrono>
#include <array>

// APSI
#include "apsi/sender/sender.h"
#include "apsi/apsidefines.h"
#include "apsi/logging/log.h"
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
using namespace apsi;
using namespace apsi::logging;
using namespace apsi::tools;
using namespace apsi::network;
using namespace apsi::sender;


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

    // Construct shared Evaluator and BatchEncoder
    evaluator_ = make_shared<Evaluator>(seal_context_);
    vector<shared_ptr<FField> > field_vec;
    ex_batch_encoder_ = make_shared<FFieldFastBatchEncoder>(
        params_.exfield_characteristic(),
        params_.exfield_degree(),
        get_power_of_two(params_.encryption_params().poly_modulus_degree())
    );
    field_vec = ex_batch_encoder_->fields();

    // Create SenderDB
    sender_db_ = make_unique<SenderDB>(params_, seal_context_, field_vec);

    compressor_ = make_shared<CiphertextCompressor>(seal_context_, evaluator_);

    vector<thread> thrds(total_thread_count_);

#ifdef USE_SECURE_SEED
    prng_.set_seed(sys_random_seed());
#else
    TODO("***************** INSECURE *****************, define USE_SECURE_SEED to fix");
    prng_.set_seed(zero_block);
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

    prng_.set_seed(zero_block);
}

void Sender::load_db(const vector<Item> &data, MatrixView<u8> vals)
{
    sender_db_->set_data(data, vals, total_thread_count_);

    // Compute symmetric polys and batch
    offline_compute();
}

void Sender::offline_compute()
{
    StopwatchScope offline_compute_scope(sender_stop_watch, "Sender::offline_compute");
    Log::info("Offline compute started");

    vector<thread> thread_pool(total_thread_count_);
    for (int i = 0; i < total_thread_count_; i++)
    {
        thread_pool[i] = thread([&]()
        {
            offline_compute_work();
        });
    }

    atomic<bool> work_finished = false;
    thread progress_thread([&]()
    {
        report_offline_compute_progress(total_thread_count_, work_finished);
    });

    for (int i = 0; i < thread_pool.size(); i++)
    {
        thread_pool[i].join();
    }

    // Signal progress thread work is done
    work_finished = true;
    progress_thread.join();

    Log::info("Offline compute finished.");
}

void Sender::offline_compute_work()
{
    StopwatchScope worker_scope(sender_stop_watch, "Sender::offline_compute_work");

    int thread_context_idx = acquire_thread_context();

    SenderThreadContext &context = thread_contexts_[thread_context_idx];
    int start_block = static_cast<int>(thread_context_idx * sender_db_->get_block_count() / total_thread_count_);
    int end_block = static_cast<int>((thread_context_idx + 1) * sender_db_->get_block_count() / total_thread_count_);

    int blocks_to_process = end_block - start_block;
    Log::debug("Thread %i processing %i blocks.", thread_context_idx, blocks_to_process);

    context.clear_processed_counts();
    context.set_total_randomized_polys(blocks_to_process);
    if (params_.get_label_bit_count())
    {
        context.set_total_interpolate_polys(blocks_to_process);
    }

    {
        StopwatchScope symmpoly_scope(sender_stop_watch, "Sender::offline_compute_work::calc_symmpoly");
        sender_db_->batched_randomized_symmetric_polys(context, start_block, end_block, evaluator_, ex_batch_encoder_);
    }

    if (params_.get_label_bit_count())
    {
        StopwatchScope interp_scope(sender_stop_watch, "Sender::offline_compute_work::calc_interpolation");
        sender_db_->batched_interpolate_polys(context, start_block, end_block, evaluator_, ex_batch_encoder_);
    }

    release_thread_context(context.id());
}

void Sender::report_offline_compute_progress(int total_threads, atomic<bool>& work_finished)
{
    int progress = 0;
    while (!work_finished)
    {
        float threads_progress = 0.0f;
        for (int i = 0; i < total_threads; i++)
        {
            threads_progress += thread_contexts_[i].get_progress();
        }

        int int_progress = static_cast<int>((threads_progress / total_threads) * 100.0f);

        if (int_progress > progress)
        {
            progress = int_progress;
            Log::info("Offline compute progress: %i%%", progress);
        }

        // Check for progress 10 times per second
        this_thread::sleep_for(100ms);
    }
}

void Sender::handshake(Channel& chl)
{
    // Receive start of session by Receiver.
    int receiver_version;
    chl.receive(receiver_version);

    // Send bin size so client can configure itself correctly.
    chl.send(params_.sender_bin_size());
}

void Sender::query_session(Channel &chl)
{
    handshake(chl);

    Log::info("Starting session");
    StopwatchScope sndr_query_sess_scope(sender_stop_watch, "Sender::query_session");

    // Send the EC point when using OPRF
    if (params_.use_oprf())
    {
        StopwatchScope sndr_oprf_preproc(sender_stop_watch, "Sender::query_session::OPRF");
        Log::info("Starting OPRF query pre-processing");

        vector<u8> buff;
        chl.receive(buff);

        PRNG pp(cc_block);
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
        Log::info("OPRF query pre-processing done");
    }

    /* Set up and receive keys. */
    PublicKey pub;
    RelinKeys relin;
    receive_pubkey(pub, chl);
    receive_relinkeys(relin, chl);

    SenderSessionContext session_context(seal_context_, pub, relin);

    if (params_.debug())
    {
        seal::SecretKey k;
        receive_prvkey(k, chl);
        session_context.set_secret_key(k);
        session_context.debug_plain_query_ = nullptr;
    }

    /* Receive client's query data. */
    int num_of_powers;
    chl.receive(num_of_powers);
    Log::debug("Received powers: %i", num_of_powers);
    Log::debug("Current batch count: %i", params_.batch_count());

    vector<vector<Ciphertext>> powers(params_.batch_count());
    auto split_size_plus_one = params_.split_size() + 1;

    for (u64 i = 0; i < powers.size(); ++i)
    {
        powers[i].reserve(split_size_plus_one);
        for (u64 j = 0; j < split_size_plus_one; ++j)
            powers[i].emplace_back(seal_context_, pool_);

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
    Log::info("Finished processing session");
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

    ex_batch_encoder_->decompose(p, dest);
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
    StopwatchScope respond_scope(sender_stop_watch, "Sender::respond");

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
        thread_pool[i] = thread([&]()
        {
            respond_work(batch_count,
                         static_cast<int>(thread_pool.size()),
                         total_blocks,
                         batches_done_prom,
                         batches_done_fut,
                         powers,
                         session_context,
                         dag,
                         states,
                         remaining_batches,
                         channel);
        });
    }

    for (int i = 0; i < thread_pool.size(); i++)
    {
        thread_pool[i].join();
    }
}

void Sender::respond_work(
    int batch_count,
    int total_threads,
    int total_blocks,
    promise<void>& batches_done_prom,
    shared_future<void>& batches_done_fut,
    vector<vector<Ciphertext>>& powers,
    SenderSessionContext &session_context,
    WindowingDag& dag,
    vector<WindowingDag::State>& states,
    atomic<int>& remaining_batches,
    Channel& channel)
{
    StopwatchScope respond_work_scope(sender_stop_watch, "Sender::respond_work");

    /* Multiple client sessions can enter this function to compete for thread context resources. */
    int thread_context_idx = acquire_thread_context();
    auto& thread_context = thread_contexts_[thread_context_idx];
    thread_context.construct_variables(params_);
    auto local_pool = thread_context.pool();

    Ciphertext tmp(local_pool);
    Ciphertext compressedResult(seal_context_, local_pool);

    u64 batch_start = thread_context_idx * batch_count / total_threads;
    auto thread_idx = std::this_thread::get_id();

    for (u64 batch = batch_start, loop_idx = 0ul; loop_idx < batch_count; ++loop_idx)
    {
        compute_batch_powers(static_cast<int>(batch), powers[batch], session_context, thread_context, dag, states[batch]);
        batch = (batch + 1) % batch_count;
    }

    auto count = remaining_batches--;
    if (count == 1)
    {
        batches_done_prom.set_value();
    }
    else
    {
        batches_done_fut.get();
    }

    int start_block = thread_context_idx * total_blocks / total_thread_count_;
    int end_block = (thread_context_idx + 1) * total_blocks / total_thread_count_;

    // Constuct two ciphertext to store the result.  One keeps track of the current result, 
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
                StopwatchScope online_interp_scope(sender_stop_watch, "Sender::respond_work::online_interpolate");

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
                    }
                }
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
}

void Sender::compute_batch_powers(
    int batch,
    vector<Ciphertext>& batch_powers,
    SenderSessionContext& session_context,
    SenderThreadContext& thread_context,
    const WindowingDag& dag,
    WindowingDag::State& state)
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

        // a simple write should be sufficient but lets be safe
        auto exp = WindowingDag::NodeState::Ready;
        bool r = node_state.compare_exchange_strong(exp, WindowingDag::NodeState::Pending);
        if (r == false)
        {
            std::cout << int(exp) << std::endl;
            throw std::runtime_error("");
        }

        // spin lock on the input nodes
        for (u64 i = 0; i < 2; ++i)
            while (state.nodes_[node.inputs_[i]] != WindowingDag::NodeState::Done);

        evaluator_->multiply(batch_powers[node.inputs_[0]], batch_powers[node.inputs_[1]], batch_powers[node.output_], local_pool);
        evaluator_->relinearize(batch_powers[node.output_], session_context.relin_keys_, local_pool);

        // a simple write should be sufficient but lets be safe
        exp = WindowingDag::NodeState::Pending;
        r = node_state.compare_exchange_strong(exp, WindowingDag::NodeState::Done);
        if (r == false)
            throw std::runtime_error("");

        idx = (*state.next_node_)++;
    }

    // splin lock until all nodes are compute. We may want to do something smarter here.
    for (i64 i = 0; i < state.nodes_.size(); ++i)
        while (state.nodes_[i] != WindowingDag::NodeState::Done);


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
    int ndigits = static_cast<int>(digits.size());
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
        int i1 = static_cast<int>(optimal_split(i, 1 << window_));
        int i2 = i - i1;
        splits[i] = i1;

        if (i1 == 0 || i2 == 0)
        {
            base_powers_.emplace_back(i);
            depth[i] = 1;
        }
        else
        {
            depth[i] = depth[i1] + depth[i2];
            ++items_per[depth[i]];
        }
    }

    for (int i = 3; i < max_power_ && items_per[i]; ++i)
    {
        items_per[i] += items_per[i - 1];
    }

    int size = static_cast<int>(max_power_ - base_powers_.size());
    nodes_.resize(size);

    for (int i = 1; i <= max_power_; i++)
    {
        int i1 = splits[i];
        int i2 = i - i1;

        if (i1 && i2)
        {
            auto d = depth[i] - 1;

            auto idx = items_per[d]++;
            if (nodes_[idx].output_)
                throw std::runtime_error("");

            nodes_[idx].inputs_ = { i1,i2 };
            nodes_[idx].output_ = i;

        }
    }
}

WindowingDag::State::State(WindowingDag & dag)
{
    next_node_ = make_unique<std::atomic<int>>();
    *next_node_ = 0;
    node_state_storage_ = make_unique<std::atomic<NodeState>[]>(dag.max_power_ + 1);
    nodes_ = { node_state_storage_.get(), dag.max_power_ + 1 };

    for (auto& n : nodes_)
        n = NodeState::Ready;

    nodes_[0] = NodeState::Done;
    for (auto& n : dag.base_powers_)
    {
        nodes_[n] = NodeState::Done;
    }
}
