#pragma once

#include <map>
#include "cuckoo.h"
#include "biguint.h"
#include "item.h"
#include "psiparams.h"
#include "bigpolyarray.h"
#include "encryptor.h"
#include "decryptor.h"
#include "util/expolycrt.h"
#include "Sender/sender.h"
#include "publickey.h"
#include "secretkey.h"
#include "Network/boost_ioservice.h"
#include "Network/boost_endpoint.h"
#include "Network/boost_channel.h"

namespace apsi
{
    namespace receiver
    {
        class Receiver
        {
        public:
            Receiver(const PSIParams &params, const seal::MemoryPoolHandle &pool = seal::MemoryPoolHandle::acquire_global());

            /**
            Sends a query to the specified sender, and get the intersection result. The query is a vector of items, and the result
            is a same-size vector of bool values. If an item is in the intersection, the corresponding bool value is true on the 
            same position in the result vector .
            */
            std::vector<bool> query(const std::vector<Item> &items, apsi::sender::Sender &sender);

            /**
            Sends a query to the remote sender, and get the intersection result. The query is a vector of items, and the result
            is a same-size vector of bool values. If an item is in the intersection, the corresponding bool value is true on the
            same position in the result vector .
            */
            std::vector<bool> query(const std::vector<Item> &items, std::string ip, uint64_t port);

            /**
            Hash all items in the input vector into a cuckoo hashing table.
            */
            std::unique_ptr<cuckoo::PermutationBasedCuckoo> cuckoo_hashing(const std::vector<Item> &items);

            /**
            Gets the indice of the items in the cuckoo hashing table. If an item is not in the table, the index is -1.
            */
            std::vector<int> cuckoo_indices(const std::vector<Item> &items, cuckoo::PermutationBasedCuckoo &cuckoo);

            /**
            Encodes items in the cuckoo hashing table into ExRing elements.
            */
            std::vector<seal::util::ExRingElement> exring_encoding(const cuckoo::PermutationBasedCuckoo &cuckoo_);

            /**
            Generates powers y^k, where y is an element in the input vector, k = i*2^{jw}, (i = 1, 2, ..., 2^w - 1), 
            (j = 0, 1, ..., bound - 1), (w is the window size in PSIParams), (bound is the number of segments when 
            we break the bits of sender's split_size into segment of window size).
            The return result is a map from k to y^k.
            */
            std::map<uint64_t, std::vector<seal::util::ExRingElement> > generate_powers(const std::vector<seal::util::ExRingElement> &exring_items);

            /**
            Encrypts every vector of elements in the input map to a corresponding vector of SEAL Ciphertext, using generalized batching. The number of 
            ciphertexts in a vector depends on the slot count in generalized batching. For example, if an input vector has size 1024, the slot count 
            is 256, then there are 1024/256 = 4 ciphertext in the Ciphertext vector.
            */
            std::map<uint64_t, std::vector<seal::Ciphertext>> encrypt(std::map<uint64_t, std::vector<seal::util::ExRingElement>> &input);

            /**
            Encrypts a vector of elements to a corresponding vector of SEAL Ciphertext, using generalized batching. The number of
            ciphertexts in the vector depends on the slot count in generalized batching. For example, if an input vector has size 1024, 
            the slot count is 256, then there are 1024/256 = 4 ciphertext in the Ciphertext vector.
            */
            std::vector<seal::Ciphertext> encrypt(const std::vector<seal::util::ExRingElement> &input);

            /**
            Bulk decryption of all ciphers from the sender. Receiver is responsible to collect all ciphers before calling this function.

            For every vector of ciphertext in the input matrix, decrypts it to a vector of ExRing elements, using generalized un-batching. 
            One ciphertext will be decrypted into multiple elements. For example, if the slot count in generalized batching is 256, then a 
            ciphertext is decrypted into 256 elements. One row in the return result is a concatenation of decrypted elements from all 
            ciphertext in the corresponding input row.

            @return Matrix of size (#splits x table_size_ceiling). Here table_size_ceiling is defined as (#batches x batch_size), which might be
            larger than table_size.
            */
            std::vector<std::vector<seal::util::ExRingElement>> bulk_decrypt(const std::vector<std::vector<seal::Ciphertext>> &result_ciphers);

            /**
            Stream decryption of ciphers from the sender. Ciphertext will be acquired from the sender in a streaming fashion one by one in
            this function.

            One ciphertext will be decrypted into multiple elements. For example, if the slot count in generalized batching is 256, then a
            ciphertext is decrypted into 256 elements.

            @return Matrix of size (#splits x table_size_ceiling). Here table_size_ceiling is defined as (#batches x batch_size), which might be
                    larger than table_size.
            */
            std::vector<std::vector<seal::util::ExRingElement>> stream_decrypt(apsi::network::Channel &channel);

            /**
            Decrypts a vector of SEAL Ciphertext to a vector of ExRing elements, using generalized un-batching. One ciphertext will be 
            decrypted into multiple elements. For example, if the slot count in generalized batching is 256, then a ciphertext is decrypted
            into 256 elements. The return result is a concatenation of decrypted elements from all ciphertext in the input vector.
            */
            std::vector<seal::util::ExRingElement> decrypt(const std::vector<seal::Ciphertext> &ciphers);

            /**
            Decrypts a SEAL Ciphertext to a batch of ExRing elements, using generalized un-batching. One ciphertext will be
            decrypted into multiple elements. For example, if the slot count in generalized batching is 256, then a ciphertext is decrypted
            into 256 elements.

            @param[out] batch The vector to hold the decrypted elements. It is assumed to be pre-allocated with appropriate size.
            */
            void decrypt(const seal::Ciphertext &cipher, std::vector<seal::util::ExRingElement> &batch);

            std::shared_ptr<seal::util::ExRing> exring() const
            {
                return ex_ring_;
            }

            const seal::PublicKey& public_key() const
            {
                return public_key_;
            }

            const seal::EvaluationKeys& evaluation_keys() const
            {
                return evaluation_keys_;
            }

            const seal::SecretKey& secret_key() const
            {
                return secret_key_;
            }

            void clear_memory_backing()
            {
                memory_backing_.clear();
            }

        private:
            void initialize();

            void send_query(std::map<uint64_t, std::vector<seal::Ciphertext>> &query, apsi::network::Channel &channel);

            PSIParams params_;

            seal::MemoryPoolHandle pool_;
            
            std::shared_ptr<seal::util::ExRing> ex_ring_;

            seal::PublicKey public_key_;

            std::unique_ptr<seal::Encryptor> encryptor_;

            seal::SecretKey secret_key_;

            std::unique_ptr<seal::Decryptor> decryptor_;

            seal::EvaluationKeys evaluation_keys_;

            std::unique_ptr<seal::util::ExPolyCRTBuilder> expolycrtbuilder_;

            std::unique_ptr<seal::PolyCRTBuilder> polycrtbuilder_;

            /* Pointers to temporary memory allocated during execution of queries. */
            std::vector<seal::util::Pointer> memory_backing_;

            std::unique_ptr<apsi::network::BoostIOService> ios_;

        };

    }
}