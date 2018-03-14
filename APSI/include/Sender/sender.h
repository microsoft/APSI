#pragma once

#include "psiparams.h"
#include "seal/memorypoolhandle.h"
#include "seal/encryptor.h"
#include "seal/decryptor.h"
#include "seal/util/exfield.h"
#include "seal/util/exfieldpolycrt.h"
#include "seal/util/exring.h"
#include "seal/util/exringpolycrt.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"

#include "Sender/senderdb.h"
#include "Sender/senderthreadcontext.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Crypto/Curve.h"
#include "Sender/sendersessioncontext.h"
#include <deque>
#include <mutex>


namespace apsi
{
    namespace sender
    {
        class Sender
        {
        public:
            Sender(const PSIParams &params,
                const seal::MemoryPoolHandle &pool = seal::MemoryPoolHandle::Global(), 
                bool dummy_init = false);

            ~Sender();

            ///**
            //Set public key for offline testing.
            //*/
            //void set_public_key(const seal::PublicKey &public_key);

            ///**
            //Set evaluation keys for offline testing.
            //*/
            //void set_evaluation_keys(const seal::EvaluationKeys &evaluation_keys);

            ///**
            //This function is only for testing purpose. Sender should not have the secret key.
            //*/
            //void set_secret_key(const seal::SecretKey &secret_key);

            ///**
            //Set public key and evaluation keys for offline testing.
            //*/
            //void set_keys(const seal::PublicKey &public_key, const seal::EvaluationKeys &evaluation_keys)
            //{
            //    set_public_key(public_key);
            //    set_evaluation_keys(evaluation_keys);
            //}

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
            Deletes the data items in sender's database. Items are ignored if they don't exist in the database.
            */
            void delete_data(const std::vector<Item> &data)
            {
                sender_db_.delete_data(data);
            }

            /**
            Deletes one item in sender's database. The item is ignored if it doesn't exist in the database.
            */
            void delete_data(const Item &item)
            {
                sender_db_.delete_data(item);
            }

            /**
            Precomputes all necessary components for the PSI protocol, including symmetric polynomials, batching, etc.
            This function is expensive and can be called after sender finishes adding items to the database.
            */
            void offline_compute();

            void query_session(oc::Channel& channel);

            void stop();

            /**
            Responds to a query from the receiver. Input is a map of powers of receiver's items, from k to y^k, where k is an 
            exponent, y is an item in receiver's cuckoo hashing table.

            Returns (#splits x #batches) ciphertexts, each of which is a result of the compoute_dot_product function.

            @see compute_dot_product for an explanation of the result.
            */
            //std::vector<std::vector<seal::Ciphertext>> respond(const std::map<uint64_t, std::vector<seal::Ciphertext>> &query)
            //{
            //    return respond(query, *local_session_, nullptr);
            //}

            void respond(const std::map<uint64_t, std::vector<seal::Ciphertext>> &query,
                apsi::sender::SenderSessionContext &session_context, oc::Channel &channel);

            /**
            Constructs all powers of receiver's items, based on the powers sent from the receiver. For example, if the desired highest 
            exponent (determined by PSIParams) is 15, the input exponents are {1, 2, 4, 8}, then this function will compute powers from 0
            to 15, by multiplying appropriate powers in {1, 2, 4, 8}.

            @params[in] input Map from exponent (k) to a vector of Ciphertext, each of which encrypts a batch of items of the same power (y^k). 
                              The size of the vector is the number of batches.
            @params[out] all_powers All powers computed from the input, with outer index indicating the batch, and inner index indicating the power.
            */
            //void compute_all_powers(const std::map<uint64_t, std::vector<seal::Ciphertext>> &input,
            //    std::vector<std::vector<seal::Ciphertext>> &all_powers)
            //{
            //    compute_all_powers(input, all_powers, *local_session_);
            //}

            //void compute_all_powers(const std::map<uint64_t, std::vector<seal::Ciphertext>> &input, 
            //    std::vector<std::vector<seal::Ciphertext>> &all_powers,
            //    apsi::sender::SenderSessionContext &session_context);

            /**
            Constructs all powers of receiver's items for the specified batch, based on the powers sent from the receiver. For example, if the 
            desired highest exponent (determined by PSIParams) is 15, the input exponents are {1, 2, 4, 8}, then this function will compute powers 
            from 0 to 15, by multiplying appropriate powers in {1, 2, 4, 8}.

            @params[in] input Map from exponent (k) to a vector of Ciphertext, each of which encrypts a batch of items of the same power (y^k).
                              The size of the vector is the number of batches.
            @params[out] all_powers All powers computed from the input for the specified batch.
            */
            void compute_batch_powers(int batch, const std::map<uint64_t, 
                std::vector<seal::Ciphertext>> &input, std::vector<seal::Ciphertext> &batch_powers, 
                SenderSessionContext &session_context, SenderThreadContext &thread_context);

            /**
            Computes dot product between sender's symmetric polynomial terms and receiver's powers, for the specified split and the specified batch
            of sender's database. The result essentially tells: for each sub-bin, is there a sender item that is the same as the receiver 
            item in this sub-bin? If yes, then the result for this bin is an encryption of 0, otherwise, it is an encryption of a random number.

            @param[out] result A ciphertext encrypting a batch of results for a consecutive range of sub-bins. 
            */
            //void compute_dot_product(int split, int batch, const std::vector<std::vector<seal::Ciphertext>> &all_powers,
            //    seal::Ciphertext &result, SenderThreadContext &context);

            //SenderSessionContext& local_session()
            //{
            //    return *local_session_;
            //}

            //std::shared_ptr<seal::util::ExField> ex_field() const
            //{
            //    return ex_field_;
            //}

            std::shared_ptr<seal::SEALContext> seal_context() const
            {
                return seal_context_;
            }

            void save_db(std::ostream &stream) const
            {
                sender_db_.save(stream);
            }

            void load_db(std::istream &stream)
            {
                sender_db_.load(stream);
            }


        private:
            void initialize();

            int acquire_thread_context();

            void release_thread_context(int idx);

            PSIParams params_;

            seal::MemoryPoolHandle pool_;

            std::shared_ptr <seal::util::ExField > ex_field_;

            ///* This is a special local session for offline testing. */
            //std::unique_ptr<SenderSessionContext> local_session_;

            seal::EncryptionParameters enc_params_;

            std::shared_ptr<seal::SEALContext> seal_context_;

            std::shared_ptr<seal::Evaluator> evaluator_;

            std::shared_ptr<seal::PolyCRTBuilder> builder_;

            /* Sender's database, including raw data, hashed data, ExField data, and symmetric polynomials. */
            SenderDB sender_db_;

            /* One context for one thread, to improve preformance by using single-thread memory pool. */
            std::vector<SenderThreadContext> thread_contexts_;

            std::deque<int> available_thread_contexts_;

            std::mutex thread_context_mtx_;

            oc::PRNG prng_;

            //oc::EllipticCurve curve_;

            bool stopped_;
        };
    }
}