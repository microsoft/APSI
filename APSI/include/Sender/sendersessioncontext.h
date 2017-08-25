#pragma once

#include "publickey.h"
#include "rnsevaluationkeys.h"
#include "secretkey.h"
#include "rnscontext.h"
#include "rnsencryptor.h"
#include "rnsdecryptor.h"
#include "rnsevaluator.h"
#include "memorypoolhandle.h"

namespace apsi
{
    namespace sender
    {
        class SenderSessionContext
        {
            friend class Sender;

        public:
            SenderSessionContext(std::shared_ptr<seal::RNSContext> context, const seal::PublicKey &pub_key, 
                const seal::RNSEvaluationKeys &eval_keys, int local_evaluator_num = 0)
                :seal_context_(std::move(context)), public_key_(pub_key), evaluation_keys_(eval_keys), local_evaluators_(local_evaluator_num)
            {
                encryptor_.reset(new seal::RNSEncryptor(*seal_context_, public_key_));
                evaluator_.reset(new seal::RNSEvaluator(*seal_context_, evaluation_keys_));

                for (int i = 0; i < local_evaluator_num; i++)
                    local_evaluators_[i].reset(new seal::RNSEvaluator(*seal_context_, evaluation_keys_, seal::MemoryPoolHandle::acquire_new(false)));
            }

            SenderSessionContext(std::shared_ptr<seal::RNSContext> context, int local_evaluator_num = 0)
                :seal_context_(std::move(context)), local_evaluators_(local_evaluator_num)
            {
                for (int i = 0; i < local_evaluator_num; i++)
                    local_evaluators_[i].reset(new seal::RNSEvaluator(*seal_context_, seal::MemoryPoolHandle::acquire_new(false)));
            }

            void set_public_key(const seal::PublicKey &public_key)
            {
                public_key_ = public_key;
                encryptor_.reset(new seal::RNSEncryptor(*seal_context_, public_key_));
            }

            void set_evaluation_keys(const seal::RNSEvaluationKeys &evaluation_keys, int local_evaluator_num = 0)
            {
                evaluation_keys_ = evaluation_keys;
                evaluator_.reset(new seal::RNSEvaluator(*seal_context_, evaluation_keys_));

                local_evaluators_.resize(local_evaluator_num);
                for (int i = 0; i < local_evaluator_num; i++)
                    local_evaluators_[i].reset(new seal::RNSEvaluator(*seal_context_, evaluation_keys_, seal::MemoryPoolHandle::acquire_new(false)));
            }

            /**
            This function is only for testing purpose. Sender should not have the secret key.
            */
            void set_secret_key(const seal::SecretKey &secret_key)
            {
                secret_key_ = secret_key;
                decryptor_.reset(new seal::RNSDecryptor(*seal_context_, secret_key_));
            }

            std::shared_ptr<seal::RNSContext> seal_context_;

            seal::PublicKey public_key_;

            std::shared_ptr<seal::RNSEncryptor> encryptor_; /* Multi-thread encryptor. */

            seal::SecretKey secret_key_;

            std::shared_ptr<seal::RNSDecryptor> decryptor_;

            seal::RNSEvaluationKeys evaluation_keys_;

            std::shared_ptr<seal::RNSEvaluator> evaluator_; /* Multi-thread evaluator. */

            std::vector<std::shared_ptr<seal::RNSEvaluator>> local_evaluators_; /* Single-thread evaluators. */
        };
    }
}