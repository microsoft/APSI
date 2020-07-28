// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <string>

// SEAL
#include "seal/context.h"
#include "seal/batchencoder.h"
#include "seal/keygenerator.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"
#include "seal/relinkeys.h"
#include "seal/encryptor.h"
#include "seal/decryptor.h"
#include "seal/evaluator.h"

// APSI
#include "apsi/network/network_utils.h"

namespace apsi
{
    namespace sender
    {
        class CryptoContext
        {
        public:
            CryptoContext(
                std::shared_ptr<seal::SEALContext> context) : seal_context_(std::move(context))
            {
                encoder_ = std::make_shared<seal::BatchEncoder>(seal_context_);
            }

            void set_evaluator(const std::string &relin_keys)
            {
                relin_keys_ = std::make_shared<seal::RelinKeys>();
                from_string(seal_context_, relin_keys, *relin_keys_);
                evaluator_ = std::make_shared<seal::Evaluator>(seal_context_);
            }

            void set_evaluator(const seal::RelinKeys &relin_keys)
            {
                relin_keys_ = std::make_shared<seal::RelinKeys>(relin_keys);
                evaluator_ = std::make_shared<seal::Evaluator>(seal_context_);
            }

            void set_secret(const std::string &secret_key)
            {
                seal::SecretKey sk;
                from_string(seal_context_, secret_key, sk);
                encryptor_ = std::make_shared<seal::Encryptor>(seal_context_, sk);
                decryptor_ = std::make_shared<seal::Decryptor>(seal_context_, sk);
            }

            void set_secret(const seal::SecretKey &secret_key)
            {
                encryptor_ = std::make_shared<seal::Encryptor>(seal_context_, secret_key);
                decryptor_ = std::make_shared<seal::Decryptor>(seal_context_, secret_key);
            }

            const std::shared_ptr<seal::SEALContext> &seal_context() const
            {
                return seal_context_;
            }

            const std::shared_ptr<seal::BatchEncoder> &encoder() const
            {
                return encoder_;
            }

            const std::shared_ptr<seal::Encryptor> &encryptor() const
            {
                return encryptor_;
            }

            const std::shared_ptr<seal::Decryptor> &decryptor() const
            {
                return decryptor_;
            }

            const std::shared_ptr<seal::Evaluator> &evaluator() const
            {
                return evaluator_;
            }

        private:
            std::shared_ptr<seal::SEALContext> seal_context_;

            std::shared_ptr<seal::RelinKeys> relin_keys_;

            std::shared_ptr<seal::Encryptor> encryptor_;

            std::shared_ptr<seal::Decryptor> decryptor_;

            std::shared_ptr<seal::Evaluator> evaluator_;

            std::shared_ptr<seal::BatchEncoder> encoder_;
        };
    } // namespace sender
} // namespace apsi
