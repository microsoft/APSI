#pragma once

// STD
#include <memory>

// SEAL
#include "seal/context.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"
#include "seal/evaluationkeys.h"
#include "seal/encryptor.h"
#include "seal/decryptor.h"

namespace apsi
{
    namespace sender
    {
        class SenderSessionContext
        {
        friend class Sender;

        public:
            SenderSessionContext(std::shared_ptr<seal::SEALContext> context, const seal::PublicKey &pub_key, 
                const seal::EvaluationKeys &eval_keys) : 
                seal_context_(std::move(context)), 
                public_key_(pub_key), 
                evaluation_keys_(eval_keys)
            {
                encryptor_.reset(new seal::Encryptor(*seal_context_, public_key_));
            }

            SenderSessionContext(std::shared_ptr<seal::SEALContext> context) : 
                seal_context_(std::move(context))
            {
            }

            void set_public_key(const seal::PublicKey &public_key)
            {
                public_key_ = public_key;
                encryptor_.reset(new seal::Encryptor(*seal_context_, public_key_));
            }

            void set_evaluation_keys(const seal::EvaluationKeys &evaluation_keys)
            {
                evaluation_keys_ = evaluation_keys;
            }

            /**
            This function is only for testing purpose. Sender should not have the secret key.
            */
            void set_secret_key(const seal::SecretKey &secret_key)
            {
                secret_key_ = secret_key;
                decryptor_.reset(new seal::Decryptor(*seal_context_, secret_key_));
            }

            const std::shared_ptr<seal::Encryptor> &encryptor()
            {
                return encryptor_;
            }

        private:
            std::shared_ptr<seal::SEALContext> seal_context_;

            seal::PublicKey public_key_;

            std::shared_ptr<seal::Encryptor> encryptor_;

            seal::SecretKey secret_key_;

            std::shared_ptr<seal::Decryptor> decryptor_;

            seal::EvaluationKeys evaluation_keys_;
        };
    }
}