// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <string>
#include <utility>

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

namespace apsi
{
    class CryptoContext
    {
    public:
        CryptoContext(
            std::shared_ptr<seal::SEALContext> context) : seal_context_(std::move(context))
        {
            encoder_ = std::make_shared<seal::BatchEncoder>(seal_context_);
        }

        void set_evaluator()
        {
            relin_keys_.reset();
            evaluator_ = std::make_shared<seal::Evaluator>(seal_context_);
        }

        void set_evaluator(seal::RelinKeys relin_keys)
        {
            relin_keys_ = std::make_shared<seal::RelinKeys>(std::move(relin_keys));
            evaluator_ = std::make_shared<seal::Evaluator>(seal_context_);
        }

        void set_secret(seal::SecretKey secret_key)
        {
            secret_key_ = std::make_shared<seal::SecretKey>(secret_key);
            encryptor_ = std::make_shared<seal::Encryptor>(seal_context_, *secret_key_);
            decryptor_ = std::make_shared<seal::Decryptor>(seal_context_, *secret_key_);
        }

        void clear_secret()
        {
            secret_key_.reset();
            encryptor_.reset();
            decryptor_.reset();
        }

        void clear_evaluator()
        {
            relin_keys_.reset();
            evaluator_.reset();
        }

        const std::shared_ptr<seal::SEALContext> &seal_context() const
        {
            return seal_context_;
        }

        const std::shared_ptr<seal::RelinKeys> &relin_keys() const
        {
            return relin_keys_;
        }

        const std::shared_ptr<seal::BatchEncoder> &encoder() const
        {
            return encoder_;
        }

        const std::shared_ptr<seal::SecretKey> &secret_key() const
        {
            return secret_key_;
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

        std::shared_ptr<seal::SecretKey> secret_key_;

        std::shared_ptr<seal::Encryptor> encryptor_;

        std::shared_ptr<seal::Decryptor> decryptor_;

        std::shared_ptr<seal::Evaluator> evaluator_;

        std::shared_ptr<seal::BatchEncoder> encoder_;
    };
} // namespace apsi
