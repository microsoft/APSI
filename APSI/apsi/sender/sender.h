#pragma once

// STD
#include <deque>
#include <mutex>
#include <memory>
#include <vector>
#include <iostream>
#include <map>

// APSI
#include "apsi/item.h"
#include "apsi/psiparams.h"
#include "apsi/sender/senderdb.h"
#include "apsi/sender/sendersessioncontext.h"
#include "apsi/sender/senderthreadcontext.h"

// SEAL
#include "seal/memorypoolhandle.h"
#include "seal/encryptionparams.h"
#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/polycrt.h"
#include "seal/util/exfield.h"
#include "seal/util/exfieldpolycrt.h"

// CryptoTools
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/PRNG.h"

namespace apsi
{
    namespace sender
    {
        class Sender
        {
        public:
            Sender(const PSIParams &params,
                int total_thread_count,
                int session_thread_count,
                const seal::MemoryPoolHandle &pool = seal::MemoryPoolHandle::Global());

            /**
            Clears data in sender's database.
            */
            inline void clear_db()
            {
                sender_db_.clear_db();
            }

            /**
            Loads the input data into sender's database, and precomputes all necessary components for the PSI protocol,
            including symmetric polynomials, batching, etc.
            */
            void load_db(const std::vector<Item> &data, oc::MatrixView<const u8> vals = {});

            void query_session(oc::Channel& channel);

            void stop();

            //void save_db(std::ostream &stream) const
            //{
            //    sender_db_.save(stream);
            //}

            //void load_db(std::istream &stream)
            //{
            //    sender_db_.load(stream);
            //}

        private:
            void initialize();

            int acquire_thread_context();

            void release_thread_context(int idx);

            /**
            Adds the data items to sender's database.
            */
            inline void add_data(const std::vector<Item> &data)
            {
                sender_db_.add_data(data, total_thread_count_);
            }

            /**
            Adds one item to sender's database.
            */
            inline void add_data(const Item &item)
            {
                sender_db_.add_data(item, total_thread_count_);
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
            void respond(const std::map<std::uint64_t, std::vector<seal::Ciphertext> > &query,
                apsi::sender::SenderSessionContext &session_context, oc::Channel &channel);

            /**
            Constructs all powers of receiver's items for the specified batch, based on the powers sent from the receiver. For example, if the
            desired highest exponent (determined by PSIParams) is 15, the input exponents are {1, 2, 4, 8}, then this function will compute powers
            from 0 to 15, by multiplying appropriate powers in {1, 2, 4, 8}.

            @params[in] input Map from exponent (k) to a vector of Ciphertext, each of which encrypts a batch of items of the same power (y^k).
            The size of the vector is the number of batches.
            @params[out] all_powers All powers computed from the input for the specified batch.
            */
            void compute_batch_powers(int batch, const std::map<std::uint64_t,
                std::vector<seal::Ciphertext>> &input, std::vector<seal::Ciphertext> &batch_powers,
                SenderSessionContext &session_context, SenderThreadContext &thread_context);

            PSIParams params_;

            int total_thread_count_;

            int session_thread_count_;

            seal::MemoryPoolHandle pool_;

            std::shared_ptr<seal::util::ExField> ex_field_;

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

            bool stopped_;



            void Sender::debug_decrypt(
                SenderSessionContext &session_context,
                seal::Ciphertext& c,
                std::vector<oc::u64>& dest);

            std::vector<oc::u64> Sender::debug_eval_term(int term, oc::MatrixView<apsi::u64> coeffs, oc::span<oc::u64> x, const seal::SmallModulus& mod);

        };
    }
}