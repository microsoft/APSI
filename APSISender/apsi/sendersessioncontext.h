#pragma once

// STD
#include <memory>
#include <unordered_map>

// SEAL
#include "seal/context.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"
#include "seal/relinkeys.h"
#include "seal/encryptor.h"
#include "seal/decryptor.h"

// apsi
#include  "apsi/ffield/ffield_array.h"

namespace apsi
{
    namespace sender
    {
        class SenderSessionContext
        {
        friend class Sender;

        public:
            SenderSessionContext(std::shared_ptr<seal::SEALContext> context, const seal::PublicKey &pub_key, 
                const seal::RelinKeys &relin_keys) : 
                seal_context_(std::move(context)), 
                public_key_(pub_key), 
                relin_keys_(relin_keys)
            {
                encryptor_ = std::make_shared<seal::Encryptor>(seal_context_, public_key_);
            }

            SenderSessionContext(std::shared_ptr<seal::SEALContext> context) : 
                seal_context_(std::move(context))
            {
            }

            void set_public_key(const seal::PublicKey &public_key)
            {
                public_key_ = public_key;
                encryptor_ = std::make_shared<seal::Encryptor>(seal_context_, public_key_);
            }

            void set_relin_keys(const seal::RelinKeys &relin_keys)
            {
                relin_keys_ = relin_keys;
            }

            /**
            This function is only for testing purpose. Sender should not have the secret key.
            */
            void set_secret_key(const seal::SecretKey &secret_key)
            {
                secret_key_ = secret_key;
                decryptor_ = std::make_shared<seal::Decryptor>(seal_context_, secret_key_);
            }

            const std::shared_ptr<seal::Encryptor> &encryptor()
            {
                return encryptor_;
            }
            
            // the plaintext of the receiver's query. Used to debug.
            std::unique_ptr<FFieldArray> debug_plain_query_;

        private:
            std::shared_ptr<seal::SEALContext> seal_context_;

            seal::PublicKey public_key_;

            std::shared_ptr<seal::Encryptor> encryptor_;

            seal::SecretKey secret_key_;

            std::shared_ptr<seal::Decryptor> decryptor_;

            seal::RelinKeys relin_keys_;
        };
    }
}
