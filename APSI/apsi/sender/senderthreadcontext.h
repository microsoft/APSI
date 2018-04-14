#pragma once

// STD
#include <memory>
#include <stdexcept>
#include <vector>

// APSI
#include "apsi/psiparams.h"
#include "apsi/ffield/ffield_elt.h"
#include "apsi/ffield/ffield_crt_builder.h"

#include "seal/memorypoolhandle.h"

// CryptoTools
#include "cryptoTools/Common/MatrixView.h"
#include "cryptoTools/Crypto/PRNG.h"

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

            inline std::shared_ptr<FField> &exfield()
            {
                return exfield_;
            }

            inline void set_exfield(std::shared_ptr<FField> exfield)
            {
                exfield_ = std::move(exfield);
            }

            void set_prng(oc::block block)
            {
                prng_.SetSeed(block, 256);
            }

            // std::shared_ptr<FFieldCRTBuilder> &exbuilder()
            // {
            //     return exbuilder_;
            // }
            //
            // void set_exbuilder(std::shared_ptr<FFieldCRTBuilder> batcher)
            // {
            //     exbuilder_ = std::move(batcher);
            // }

            inline void construct_variables(PSIParams &params)
            {
                // Is the MPH initialized? It better be.
                if (!pool_)
                {
                    throw std::logic_error("MemoryPoolHandle is null");
                }
                if (!symm_block_vec_)
                {
                    symm_block_vec_.reset(new FFieldArray(exfield_, params.batch_size() * (params.split_size() + 1)));
                    // symm_block_vec_.resize(params.batch_size() * (params.split_size() + 1), FFieldElt(exfield_));
                    symm_block_ = oc::MatrixView<_ffield_array_elt_t>(symm_block_vec_->data(), params.batch_size(), params.split_size() + 1);
                }
            }

            inline oc::MatrixView<_ffield_array_elt_t> symm_block()
            {
                return symm_block_;
            }

            oc::PRNG& prng()
            {
                return prng_;
            }

        private:
            int id_;

            seal::MemoryPoolHandle pool_;

            std::shared_ptr<FField> exfield_;

            std::unique_ptr<FFieldArray> symm_block_vec_;

            oc::MatrixView<_ffield_array_elt_t> symm_block_;
            
            oc::PRNG prng_;
        };
    }
}
