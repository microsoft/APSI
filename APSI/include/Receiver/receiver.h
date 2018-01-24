#pragma once

#include <map>
#include <memory>
#include "seal/biguint.h"
#include "seal/bigpolyarray.h"
#include "seal/encryptor.h"
#include "seal/decryptor.h"
#include "seal/util/exfieldpolycrt.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"
#include "seal/evaluationkeys.h"
#include "seal/polycrt.h"
#include "item.h"
#include "psiparams.h"
#include "cuckoo.h"
//#include "Sender/sender.h"
#include "cryptoTools/Network/Channel.h"

namespace apsi
{
    namespace receiver
    {
        class Receiver
        {
        public:
            Receiver(const PSIParams &params, const seal::MemoryPoolHandle &pool = seal::MemoryPoolHandle::Global());

            /**
            Sends a query to the remote sender, and get the intersection result. The query is a vector of items, and the result
            is a same-size vector of bool values. If an item is in the intersection, the corresponding bool value is true on the
            same position in the result vector .
            */
			std::vector<bool> query(std::vector<Item> &items, oc::Channel& chl);

            /**
            Preprocesses the PSI items. Returns the powr map of the items, and the indices of them in the hash table.
            */
            std::pair<
                std::map<uint64_t, std::vector<seal::Ciphertext>>, 
				std::unique_ptr<cuckoo::CuckooInterface>
            > preprocess(std::vector<Item> &items, oc::Channel& channel);

            void send(const std::map<uint64_t, std::vector<seal::Ciphertext>> &query_data, oc::Channel &channel);

            /**
            Hash all items in the input vector into a cuckoo hashing table.
            */
            std::unique_ptr<cuckoo::CuckooInterface> cuckoo_hashing(const std::vector<Item> &items);

            /**
            Returns a map: table index -> input index.
            */
            std::vector<int> cuckoo_indices(const std::vector<Item> &items, cuckoo::CuckooInterface &cuckoo);

            /**
            Encodes items in the cuckoo hashing table into ExField elements.
            */
            void exfield_encoding(
				cuckoo::CuckooInterface &cuckoo_,
				std::vector<seal::util::ExFieldElement>& ret,
				seal::util::Pointer& data);

            /**
            Generates powers y^k, where y is an element in the input vector, k = i*2^{jw}, (i = 1, 2, ..., 2^w - 1), 
            (j = 0, 1, ..., bound - 1), (w is the window size in PSIParams), (bound is the number of segments when 
            we break the bits of sender's split_size into segment of window size).
            The return result is a map from k to y^k.
            */
            void generate_powers(const std::vector<seal::util::ExFieldElement> &exfield_items,
				std::map<uint64_t, std::vector<seal::util::ExFieldElement> >& ret,
				std::list<seal::util::Pointer>& data);

            /**
            Encrypts every vector of elements in the input map to a corresponding vector of SEAL Ciphertext, using generalized batching. The number of 
            ciphertexts in a vector depends on the slot count in generalized batching. For example, if an input vector has size 1024, the slot count 
            is 256, then there are 1024/256 = 4 ciphertext in the Ciphertext vector.
            */
            std::map<uint64_t, std::vector<seal::Ciphertext>> encrypt(std::map<uint64_t, std::vector<seal::util::ExFieldElement>> &input);

            /**
            Encrypts a vector of elements to a corresponding vector of SEAL Ciphertext, using generalized batching. The number of
            ciphertexts in the vector depends on the slot count in generalized batching. For example, if an input vector has size 1024, 
            the slot count is 256, then there are 1024/256 = 4 ciphertext in the Ciphertext vector.
            */
            std::vector<seal::Ciphertext> encrypt(const std::vector<seal::util::ExFieldElement> &input);

            /**
            Stream decryption of ciphers from the sender. Ciphertext will be acquired from the sender in a streaming fashion one by one in
            this function.

            One ciphertext will be decrypted into multiple elements. For example, if the slot count in generalized batching is 256, then a
            ciphertext is decrypted into 256 elements.

            @result Matrix of size (#splits x table_size_ceiling). Here table_size_ceiling is defined as (#batches x batch_size), which might be
                    larger than table_size.
            */
            void stream_decrypt(
				oc::Channel &channel, 
				std::vector<std::vector<seal::util::ExFieldElement>> &result,
				seal::util::Pointer& backing);

            /**
            Stream decryption of ciphers from the sender. Ciphertext will be acquired from the sender in a streaming fashion one by one in
            this function.

            @param[out] result Plaintext matrix of size (#splits x #batches).
            */
            // void stream_decrypt(oc::Channel &channel, std::vector<std::vector<seal::Plaintext>> &result);


            /**
            Decrypts a SEAL Ciphertext to a Plaintext.

            @param[out] plain The plaintext to hold the decrypted data.
            */
            void decrypt(const seal::Ciphertext &cipher, seal::Plaintext &plain);

            /**
            Decomposes a SEAL plaintext to a batch of ExField elements, using generalized un-batching. One plaintext will be
            decomposed into multiple elements. For example, if the slot count in generalized batching is 256, then a plaintext is decomposed
            into 256 elements.

            @param[out] batch The vector to hold the decomposed elements. It is assumed to be pre-allocated with appropriate size.
            */
            //void decompose(const seal::Plaintext &plain, std::vector<seal::util::ExFieldElement> &batch);


            std::shared_ptr<seal::util::ExField> ex_field() const
            {
                return ex_field_;
            }

            std::shared_ptr<seal::util::ExFieldPolyCRTBuilder> ex_builder() const
            {
                return exfieldpolycrtbuilder_;
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

            //void clear_memory_backing()
            //{
            //    memory_backing_.clear();
            //}

        private:
            void initialize();

            PSIParams params_;

            seal::MemoryPoolHandle pool_;
            
            std::shared_ptr<seal::util::ExField> ex_field_;

            seal::PublicKey public_key_;

            std::unique_ptr<seal::Encryptor> encryptor_;

            seal::SecretKey secret_key_;

            std::unique_ptr<seal::Decryptor> decryptor_;

            seal::EvaluationKeys evaluation_keys_;

            std::shared_ptr<seal::util::ExFieldPolyCRTBuilder> exfieldpolycrtbuilder_;

            std::unique_ptr<seal::PolyCRTBuilder> polycrtbuilder_;


            /* Pointers to temporary memory allocated during execution of queries. */
            //std::vector<seal::util::Pointer> memory_backing_;


        };

    }
}