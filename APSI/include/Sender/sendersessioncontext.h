#pragma once

#include "seal/publickey.h"
#include "seal/evaluationkeys.h"
#include "seal/secretkey.h"
#include "seal/context.h"
#include "seal/encryptor.h"
#include "seal/decryptor.h"
#include "seal/evaluator.h"
#include "seal/memorypoolhandle.h"

namespace apsi
{
    namespace sender
    {
        class SenderSessionContext
        {
            friend class Sender;

        public:
            SenderSessionContext(std::shared_ptr<seal::SEALContext> context, const seal::PublicKey &pub_key, 
                const seal::EvaluationKeys &eval_keys, int local_evaluator_num = 0) : 
                seal_context_(std::move(context)), 
                public_key_(pub_key), 
                evaluation_keys_(eval_keys)
                //local_evaluators_(local_evaluator_num)
            {
                encryptor_.reset(new seal::Encryptor(*seal_context_, public_key_));
                evaluator_.reset(new seal::Evaluator(*seal_context_));
                //for (int i = 0; i < local_evaluator_num; i++)
                //{
                //    //local_evaluators_[i].reset(new seal::Evaluator(*seal_context_, seal::MemoryPoolHandle::New(false)));
                //    local_evaluators_[i] = evaluator_;
                //}
            }

            SenderSessionContext(std::shared_ptr<seal::SEALContext> context, int local_evaluator_num = 0) : 
                seal_context_(std::move(context))
                //local_evaluators_(local_evaluator_num)
            {
                evaluator_.reset(new seal::Evaluator(*seal_context_));
                //for (int i = 0; i < local_evaluator_num; i++)
                //{
                //    //local_evaluators_[i].reset(new seal::Evaluator(*seal_context_, seal::MemoryPoolHandle::New(false)));
                //    local_evaluators_[i] = evaluator_;
                //}
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

            std::shared_ptr<seal::SEALContext> seal_context_;

            seal::PublicKey public_key_;

            std::shared_ptr<seal::Encryptor> encryptor_; /* Multi-thread encryptor. */

            seal::SecretKey secret_key_;

            std::shared_ptr<seal::Decryptor> decryptor_;

            seal::EvaluationKeys evaluation_keys_;

            std::shared_ptr<seal::Evaluator> evaluator_; /* Multi-thread evaluator. */

            //std::vector<std::shared_ptr<seal::Evaluator>> local_evaluators_; /* Single-thread evaluators. */
        };
    }
}