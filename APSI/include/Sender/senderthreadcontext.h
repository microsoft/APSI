#pragma once

// STD
#include <memory>
#include <stdexcept>
#include <vector>

// APSI
#include "psiparams.h"

// SEAL
#include "seal/memorypoolhandle.h"
#include "seal/util/exfield.h"
#include "seal/util/exfieldpolycrt.h"

// CryptoTools
#include "cryptoTools/Common/MatrixView.h"

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
            inline int id() const
            {
                return id_;
            }

            inline void set_id(int id)
            {
                id_ = id;
            }

            inline seal::MemoryPoolHandle pool() const
            {
                return pool_;
            }

            inline void set_pool(const seal::MemoryPoolHandle &pool)
            {
                pool_ = pool;
            }

            inline std::shared_ptr<seal::util::ExField> &exfield()
            {
                return exfield_;
            }

            inline void set_exfield(std::shared_ptr<seal::util::ExField> exfield)
            {
                exfield_ = std::move(exfield);
            }

            std::shared_ptr<seal::util::ExFieldPolyCRTBuilder> &exbuilder()
            {
                return exbuilder_;
            }

            void set_exbuilder(std::shared_ptr<seal::util::ExFieldPolyCRTBuilder> batcher)
            {
                exbuilder_ = std::move(batcher);
            }

            inline void construct_variables(PSIParams &params)
            {
                // Is the MPH initialized? It better be.
                if (!pool_)
                {
                    throw std::logic_error("MemoryPoolHandle is null");
                }

                if (symm_block_.size() == 0)
                {
                    symm_block_vec_ = std::move(exfield_->allocate_elements(params.batch_size() * (params.split_size() + 1), symm_block_backing_));
                    symm_block_ = oc::MatrixView<seal::util::ExFieldElement>(symm_block_vec_.begin(), symm_block_vec_.end(), params.split_size() + 1);

                    batch_vector_ = std::move(exfield_->allocate_elements(params.batch_size(), batch_backing_));
                    integer_batch_vector_.resize(params.batch_size(), 0);
                }
            }

            inline oc::MatrixView<seal::util::ExFieldElement> symm_block()
            {
                return symm_block_;
            }

            inline std::vector<seal::util::ExFieldElement> &batch_vector()
            {
                return batch_vector_;
            }

            inline std::vector<std::uint64_t> &integer_batch_vector()
            {
                return integer_batch_vector_;
            }

        private:
            int id_;

            seal::MemoryPoolHandle pool_;

            std::shared_ptr<seal::util::ExField> exfield_;

            std::shared_ptr<seal::util::ExFieldPolyCRTBuilder> exbuilder_;
            
            seal::util::Pointer symm_block_backing_;

            std::vector<seal::util::ExFieldElement> symm_block_vec_;
            
            oc::MatrixView<seal::util::ExFieldElement> symm_block_;

            seal::util::Pointer batch_backing_;

            std::vector<seal::util::ExFieldElement> batch_vector_;

            std::vector<std::uint64_t> integer_batch_vector_;
        };
    }
}
