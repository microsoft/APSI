#pragma once

#include "psiparams.h"
#include "memorypoolhandle.h"
#include "encryptor.h"
#include "decryptor.h"
#include "util/exring.h"
#include "util/expolycrt.h"
#include "Sender/senderdb.h"
#include "Sender/senderthreadcontext.h"
#include "publickey.h"
#include "secretkey.h"


namespace apsi
{
	namespace sender
	{
		class Sender
		{
		public:
			Sender(const PSIParams &params, const seal::MemoryPoolHandle &pool = seal::MemoryPoolHandle::acquire_global());

			void set_public_key(const seal::PublicKey &public_key);

			void set_evaluation_keys(const seal::EvaluationKeys &evaluation_keys);

			/**
			This function is only for testing purpose. Sender should not have the secret key.
			*/
			void set_secret_key(const seal::SecretKey &secret_key);

			void set_keys(const seal::PublicKey &public_key, const seal::EvaluationKeys &evaluation_keys)
			{
				set_public_key(public_key);
				set_evaluation_keys(evaluation_keys);
			}

			/**
			Clears data in sender's database.
			*/
			void clear_sender_db()
			{
				sender_db_.clear_db();
			}

			/**
			Loads the input data into sender's database, and precomputes all necessary components for the PSI protocol,
			including symmetric polynomials, batching, etc.
			*/
			void load_db(const std::vector<Item> &data);

			/**
			Adds the data items to sender's database.
			*/
			void add_data(const std::vector<Item> &data)
			{
				sender_db_.add_data(data);
			}

			/**
			Adds one item to sender's database.
			*/
			void add_data(const Item &item)
			{
				sender_db_.add_data(item);
			}

			/**
			Precomputes all necessary components for the PSI protocol, including symmetric polynomials, batching, etc.
			This function is expensive and can be called after sender finishes adding items to the database.
			*/
			void offline_compute();

			/**
			Responds to a query from the receiver. Input is a map of powers of receiver's items, from k to y^k, where k is an 
			exponent, y is an item in receiver's cuckoo hashing table.

			Returns (#splits x #batches) ciphertexts, each of which is a result of the compoute_dot_product function.

			@see compute_dot_product for an explanation of the result.
			*/
			std::vector<std::vector<seal::Ciphertext>> respond(const std::map<uint64_t, std::vector<seal::Ciphertext>> &query);

			/**
			Constructs all powers of receiver's items, based on the powers sent from the receiver. For example, if the desired highest 
			exponent (determined by PSIParams) is 15, the input exponents are {1, 2, 4, 8}, then this function will compute powers from 0
			to 15, by multiplying appropriate powers in {1, 2, 4, 8}.

			@params[in] input Map from exponent (k) to a vector of Ciphertext, each of which encrypts a batch of items of the same power (y^k). 
							  The size of the vector is the number of batches.
			@params[out] all_powers All powers computed from the input.
			*/
			void compute_all_powers(const std::map<uint64_t, std::vector<seal::Ciphertext>> &input, std::vector<std::vector<seal::Ciphertext>> &all_powers);

			/**
			Computes dot product between sender's symmetric polynomial terms and receiver's powers, for the specified split and the specified batch
			of sender's database. The result essentially tells: for each sub-bin, is there a sender item that is the same as the receiver 
			item in this sub-bin? If yes, then the result for this bin is an encryption of 0, otherwise, it is an encryption of a random number.

			@param[out] result A ciphertext encrypting a batch of results for a consecutive range of sub-bins. 
			*/
			void compute_dot_product(int split, int batch, const std::vector<std::vector<seal::Ciphertext>> &all_powers,
				seal::Ciphertext &result, SenderThreadContext &context);

			seal::Evaluator& evaluator() const
			{
				return *evaluator_;
			}

		private:
			void initialize();

			PSIParams params_;

			seal::MemoryPoolHandle pool_;

			std::shared_ptr <seal::util::ExRing > ex_ring_;

			seal::PublicKey public_key_;

			std::unique_ptr<seal::Encryptor> encryptor_;

			seal::SecretKey secret_key_;

			std::unique_ptr<seal::Decryptor> decryptor_;

			seal::EvaluationKeys evaluation_keys_;

			std::unique_ptr<seal::Evaluator> evaluator_;

			seal::EncryptionParameters enc_params_;

			std::unique_ptr<seal::SEALContext> seal_context_;

			/* Sender's database, including raw data, hashed data, ExRing data, and symmetric polynomials. */
			SenderDB sender_db_;

			/* One context for one thread, to improve preformance by using single-thread memory pool. */
			std::vector<SenderThreadContext> thread_contexts_;


			///* One evaluator for one thread, to improve performance by using single-thread memory pool. */
			//std::vector<seal::Evaluator> thread_evaluators_;

			///* One generalized batcher for one thread, to improve performance by using single-thread memory pool. */
			//std::vector<seal::util::ExPolyCRTBuilder> thread_batchers_;

			///* One exring for one thread, to improve performance by using single-thread memory pool. */
			//std::vector<std::shared_ptr<seal::util::ExRing>> thread_ex_rings_;
		};
	}
}