#pragma once

#include "util/exring.h"
#include "util/expolycrt.h"
#include "evaluator.h"
#include "polycrt.h"

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

            SenderThreadContext(std::shared_ptr<seal::util::ExRing> exring,
                std::shared_ptr<seal::Evaluator> evaluator,
                std::shared_ptr<seal::PolyCRTBuilder> builder,
                std::shared_ptr<seal::util::ExPolyCRTBuilder> exbuilder)
                :exring_(std::move(exring)), evaluator_(std::move(evaluator)), builder_(std::move(builder)), exbuilder_(std::move(exbuilder))
            {

            }

            std::shared_ptr<seal::util::ExRing> exring()
            {
                return exring_;
            }

            void set_exring(std::shared_ptr<seal::util::ExRing> exring)
            {
                exring_ = move(exring);
            }

            std::shared_ptr<seal::Evaluator> evaluator()
            {
                return evaluator_;
            }

            void set_evaluator(std::shared_ptr<seal::Evaluator> evaluator)
            {
                evaluator_ = std::move(evaluator);
            }

            std::shared_ptr<seal::util::ExPolyCRTBuilder> exbuilder()
            {
                return exbuilder_;
            }

            void set_exbuilder(std::shared_ptr<seal::util::ExPolyCRTBuilder> batcher)
            {
                exbuilder_ = std::move(batcher);
            }

            std::shared_ptr<seal::PolyCRTBuilder> builder()
            {
                return builder_;
            }

            void set_builder(std::shared_ptr<seal::PolyCRTBuilder> builder)
            {
                builder_ = std::move(builder);
            }

        private:
            std::shared_ptr<seal::util::ExRing> exring_;
            std::shared_ptr<seal::Evaluator> evaluator_;
            std::shared_ptr<seal::PolyCRTBuilder> builder_;
            std::shared_ptr<seal::util::ExPolyCRTBuilder> exbuilder_;
        };
    }
}