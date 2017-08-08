#include "Sender/sender.h"
#include "keygenerator.h"
#include "apsidefines.h"
#include <thread>
#include <mutex>

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
	namespace sender
	{
		Sender::Sender(const PSIParams &params, const MemoryPoolHandle &pool)
			:params_(params),
			pool_(pool),
			ex_ring_(ExRing::acquire_ring(params.exring_characteristic(), params.exring_exponent(), params.exring_polymod(), pool)),
			sender_db_(params, ex_ring_),
			thread_contexts_(params.sender_thread_count())
		{
			initialize();
		}

		void Sender::initialize()
		{
			enc_params_.set_poly_modulus("1x^" + to_string(params_.poly_degree()) + " + 1");
			enc_params_.set_coeff_modulus(params_.coeff_modulus());
			enc_params_.set_plain_modulus(params_.exring_characteristic());
			enc_params_.set_decomposition_bit_count(params_.decomposition_bit_count());

			seal_context_.reset(new SEALContext(enc_params_));

			ex_ring_->init_frobe_table();
			const BigPoly poly_mod(ex_ring_->coeff_count(), ex_ring_->coeff_uint64_count() * bits_per_uint64, 
				const_cast<uint64_t*>(ex_ring_->poly_modulus().get()));

			/* Set local exrings for multithreaded efficient use of memory pools. */
			for (int i = 0; i < params_.sender_thread_count(); i++)
			{
				thread_contexts_[i].set_exring(ExRing::acquire_ring(ex_ring_->characteristic(),
					ex_ring_->exponent(), poly_mod, MemoryPoolHandle::acquire_new(false)));
				thread_contexts_[i].exring()->set_frobe_table(ex_ring_->frobe_table());

				thread_contexts_[i].set_batcher(make_shared<ExPolyCRTBuilder>(thread_contexts_[i].exring(), params_.log_poly_degree()));
			}
		}

		void Sender::set_public_key(const PublicKey &public_key)
		{
			public_key_ = public_key;
			encryptor_.reset(new Encryptor(*seal_context_, public_key_));
		}

		void Sender::set_evaluation_keys(const seal::EvaluationKeys &evaluation_keys)
		{
			evaluation_keys_ = evaluation_keys;
			evaluator_.reset(new Evaluator(*seal_context_, evaluation_keys_));

			for (int i = 0; i < params_.sender_thread_count(); i++)
			{
				thread_contexts_[i].set_evaluator(make_shared<Evaluator>(*seal_context_, evaluation_keys_, MemoryPoolHandle::acquire_new(false)));
			}
		}

		void Sender::set_secret_key(const SecretKey &secret_key)
		{
			secret_key_ = secret_key;
			decryptor_.reset(new Decryptor(*seal_context_, secret_key_));
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
			};

			vector<thread> thread_pool;
			for (int i = 0; i < params_.sender_thread_count(); i++)
			{
				// Must use 'std::ref' to pass by reference when we construct thread with a lambda function that takes reference arguments.
				// But if we just call the lambda function, then we don't need 'std::ref'.
				thread_pool.push_back(thread(block_computation, std::ref(thread_contexts_[i])));
			}

			for (int i = 0; i < thread_pool.size(); i++)
				thread_pool[i].join();
		}

		vector<vector<Ciphertext>> Sender::respond(const std::map<uint64_t, std::vector<seal::Ciphertext>> &query)
		{
			vector<vector<Ciphertext>> result(params_.number_of_splits(), vector<Ciphertext>(params_.number_of_batches()));

			vector<vector<Ciphertext>> powers;
			compute_all_powers(query, powers);

			atomic<int> block_index = 0;
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
				}
			};
			
			vector<thread> thread_pool;
			for (int i = 0; i < params_.sender_thread_count(); i++)
			{
				// Must use 'std::ref' to pass by reference when we construct thread with a lambda function that takes reference arguments.
				// But if we just call the lambda function, then we don't need 'std::ref'.
				thread_pool.push_back(thread(block_computation, std::ref(thread_contexts_[i]))); 
			}

			for (int i = 0; i < thread_pool.size(); i++)
				thread_pool[i].join();

			return result;
		}

		void Sender::compute_all_powers(const map<uint64_t, vector<Ciphertext>> &input, vector<vector<Ciphertext>> &all_powers)
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
			};

			vector<thread> thread_pool;
			for (int i = 0; i < params_.sender_thread_count() && i < params_.number_of_batches(); i++)
			{
				// Must use 'std::ref' to pass by reference when we construct thread with a lambda function that takes reference arguments.
				// But if we just call the lambda function, then we don't need 'std::ref'.
				thread_pool.push_back(thread(batch_computation, std::ref(thread_contexts_[i])));
			}

			for (int i = 0; i < thread_pool.size(); i++)
				thread_pool[i].join();
		}

		void Sender::compute_batch_powers(int batch, const std::map<uint64_t, std::vector<seal::Ciphertext>> &input,
			std::vector<seal::Ciphertext> &batch_powers, SenderThreadContext &context)
		{
			batch_powers.resize(params_.split_size() + 1);
			shared_ptr<Evaluator> local_evaluator = context.evaluator();
			batch_powers[0] = encryptor_->encrypt(BigPoly("1"));
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
			vector<Plaintext> &sender_coeffs = sender_db_.batched_randomized_symmetric_polys(split, batch, context);
			
			Ciphertext tmp;

			shared_ptr<Evaluator> local_evaluator = context.evaluator();

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

	}
}