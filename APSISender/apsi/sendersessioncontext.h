// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <unordered_map>

// SEAL
#include "seal/context.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"
#include "seal/relinkeys.h"
#include "seal/decryptor.h"
#include "seal/encryptor.h"
#include "seal/evaluator.h"

// APSI
#include "apsi/ffield/ffield_batch_encoder.h"
#include "apsi/tools/sealcompress.h"

namespace apsi
{
    namespace sender
    {
        class SenderSessionContext
        {
            friend class Sender;

        public:
            SenderSessionContext(std::shared_ptr<seal::SEALContext> context) : 
                seal_context_(std::move(context))
            {
                evaluator_ = std::make_unique<seal::Evaluator>(seal_context_);
                compressor_ = std::make_unique<CiphertextCompressor>(seal_context_);
            }

            void set_public_key(const seal::PublicKey &public_key)
            {
                public_key_ = public_key;
                encryptor_ = std::make_unique<seal::Encryptor>(seal_context_, public_key_);
            }

            void set_relin_keys(const seal::RelinKeys &relin_keys)
            {
                relin_keys_ = relin_keys;
            }

            void set_ffield(FField field)
            {
                field_ = std::make_unique<FField>(field);
                encoder_ = std::make_unique<FFieldBatchEncoder>(seal_context_, *field_);
            }

            /**
            This function is only for testing purpose. Sender should not have the secret key.
            */
            void set_secret_key(const seal::SecretKey &secret_key)
            {
                secret_key_ = secret_key;
                decryptor_ = std::make_unique<seal::Decryptor>(seal_context_, secret_key_);
            }

            std::shared_ptr<seal::SEALContext> seal_context()
            {
                return seal_context_;
            }

            const std::unique_ptr<seal::Encryptor> &encryptor()
            {
                return encryptor_;
            }

            const std::unique_ptr<seal::Decryptor> &decryptor()
            {
                return decryptor_;
            }

            const std::unique_ptr<seal::Evaluator> &evaluator()
            {
                return evaluator_;
            }

            const std::unique_ptr<FField> &ffield()
            {
                return field_;
            }

            const std::unique_ptr<FFieldBatchEncoder> &encoder()
            {
                return encoder_;
            }

            const std::unique_ptr<CiphertextCompressor> &compressor()
            {
                return compressor_;
            }
            
            // the plaintext of the receiver's query. Used to debug.
            std::unique_ptr<FFieldArray> debug_plain_query_;

        private:
            std::shared_ptr<seal::SEALContext> seal_context_;

            seal::PublicKey public_key_;

            seal::SecretKey secret_key_;

            seal::RelinKeys relin_keys_;

            std::unique_ptr<seal::Encryptor> encryptor_;

            std::unique_ptr<seal::Decryptor> decryptor_;

            std::unique_ptr<seal::Evaluator> evaluator_;

            std::unique_ptr<FField> field_;

            std::unique_ptr<FFieldBatchEncoder> encoder_;

            std::unique_ptr<CiphertextCompressor> compressor_;
        };
    }
}
