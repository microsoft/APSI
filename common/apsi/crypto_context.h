// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

// APSI
#include "apsi/psi_params.h"

// SEAL
#include "seal/batchencoder.h"
#include "seal/context.h"
#include "seal/decryptor.h"
#include "seal/encryptor.h"
#include "seal/evaluator.h"
#include "seal/keygenerator.h"
#include "seal/publickey.h"
#include "seal/relinkeys.h"
#include "seal/secretkey.h"

namespace apsi {
    class CryptoContext {
    public:
        CryptoContext() = default;

        CryptoContext(const PSIParams &parms)
            : seal_context_(std::make_shared<seal::SEALContext>(
                  parms.seal_params(), true, seal::sec_level_type::tc128))
        {
            encoder_ = std::make_shared<seal::BatchEncoder>(*seal_context_);
        }

        void set_evaluator()
        {
            relin_keys_.reset();
            evaluator_ = std::make_shared<seal::Evaluator>(*seal_context_);
        }

        void set_evaluator(seal::RelinKeys relin_keys)
        {
            relin_keys_ = std::make_shared<seal::RelinKeys>(std::move(relin_keys));
            evaluator_ = std::make_shared<seal::Evaluator>(*seal_context_);
        }

        void set_secret(seal::SecretKey secret_key)
        {
            secret_key_ = std::make_shared<seal::SecretKey>(std::move(secret_key));
            encryptor_ = std::make_shared<seal::Encryptor>(*seal_context_, *secret_key_);
            decryptor_ = std::make_shared<seal::Decryptor>(*seal_context_, *secret_key_);
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

        std::shared_ptr<seal::SEALContext> seal_context() const
        {
            return seal_context_;
        }

        std::shared_ptr<seal::RelinKeys> relin_keys() const
        {
            return relin_keys_;
        }

        std::shared_ptr<seal::BatchEncoder> encoder() const
        {
            return encoder_;
        }

        std::shared_ptr<seal::SecretKey> secret_key() const
        {
            return secret_key_;
        }

        std::shared_ptr<seal::Encryptor> encryptor() const
        {
            return encryptor_;
        }

        std::shared_ptr<seal::Decryptor> decryptor() const
        {
            return decryptor_;
        }

        std::shared_ptr<seal::Evaluator> evaluator() const
        {
            return evaluator_;
        }

        explicit operator bool() const noexcept
        {
            return !!seal_context_;
        }

    private:
        std::shared_ptr<seal::SEALContext> seal_context_ = nullptr;

        std::shared_ptr<seal::RelinKeys> relin_keys_ = nullptr;

        std::shared_ptr<seal::SecretKey> secret_key_ = nullptr;

        std::shared_ptr<seal::Encryptor> encryptor_ = nullptr;

        std::shared_ptr<seal::Decryptor> decryptor_ = nullptr;

        std::shared_ptr<seal::Evaluator> evaluator_ = nullptr;

        std::shared_ptr<seal::BatchEncoder> encoder_ = nullptr;
    };
} // namespace apsi
