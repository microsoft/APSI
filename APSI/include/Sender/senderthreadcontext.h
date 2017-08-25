#pragma once

#include "util/exfield.h"
#include "util/exfieldpolycrt.h"
#include "rnsevaluator.h"
#include "rnspolycrt.h"

namespace apsi
{
    namespace sender
    {
        /**
        Manages the resources used in a single sender thread. This is intended to separate the resources for different
        threads, in order to avoid multi-threaded contension for resources and to improve performance.
        */
        class SenderThreadContext
        {
        public:
            SenderThreadContext()
            {

            }

            SenderThreadContext(int id,
                std::shared_ptr<seal::util::ExField> exfield,
                std::shared_ptr<seal::RNSEncryptor> encryptor,
                std::shared_ptr<seal::RNSEvaluator> evaluator,
                std::shared_ptr<seal::RNSPolyCRTBuilder> builder,
                std::shared_ptr<seal::util::ExFieldPolyCRTBuilder> exbuilder)
                :id_(id), exfield_(std::move(exfield)), encryptor_(std::move(encryptor)), evaluator_(std::move(evaluator)), 
                builder_(std::move(builder)), exbuilder_(std::move(exbuilder))
            {

            }

            int id()
            {
                return id_;
            }

            void set_id(int id)
            {
                id_ = id;
            }

            std::shared_ptr<seal::util::ExField> exfield()
            {
                return exfield_;
            }

            void set_exfield(std::shared_ptr<seal::util::ExField> exfield)
            {
                exfield_ = move(exfield);
            }

            std::shared_ptr<seal::RNSEncryptor> encryptor()
            {
                return encryptor_;
            }

            void set_encryptor(std::shared_ptr<seal::RNSEncryptor> encryptor)
            {
                encryptor_ = std::move(encryptor);
            }

            std::shared_ptr<seal::RNSEvaluator> evaluator()
            {
                return evaluator_;
            }

            void set_evaluator(std::shared_ptr<seal::RNSEvaluator> evaluator)
            {
                evaluator_ = std::move(evaluator);
            }

            std::shared_ptr<seal::util::ExFieldPolyCRTBuilder> exbuilder()
            {
                return exbuilder_;
            }

            void set_exbuilder(std::shared_ptr<seal::util::ExFieldPolyCRTBuilder> batcher)
            {
                exbuilder_ = std::move(batcher);
            }

            std::shared_ptr<seal::RNSPolyCRTBuilder> builder()
            {
                return builder_;
            }

            void set_builder(std::shared_ptr<seal::RNSPolyCRTBuilder> builder)
            {
                builder_ = std::move(builder);
            }

        private:
            int id_;
            std::shared_ptr<seal::util::ExField> exfield_;
            std::shared_ptr<seal::RNSEvaluator> evaluator_;
            std::shared_ptr<seal::RNSEncryptor> encryptor_;
            std::shared_ptr<seal::RNSPolyCRTBuilder> builder_;
            std::shared_ptr<seal::util::ExFieldPolyCRTBuilder> exbuilder_;
        };
    }
}