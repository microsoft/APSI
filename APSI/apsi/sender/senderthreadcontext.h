#pragma once

// STD
#include <memory>
#include <stdexcept>
#include <vector>

// APSI
#include "apsi/psiparams.h"
#include "apsi/ffield/ffield_elt.h"
#include "apsi/ffield/ffield_array.h"
#include "apsi/tools/matrixview.h"
#include "apsi/tools/prng.h"

// SEAL
#include "seal/memorypoolhandle.h"


namespace apsi
{
    namespace sender
    {
        /**
        Manages the resources used in a single sender thread. This is intended to separate the resources for different
        threads, in order to avoid multi-threaded contention for resources and to improve performance.
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

            inline std::vector<std::shared_ptr<FField> > &exfield()
            {
                return exfield_;
            }

            inline void set_exfield(std::vector<std::shared_ptr<FField> > exfield)
            {
                exfield_ = std::move(exfield);
            }

            void set_prng(apsi::block block)
            {
                prng_.set_seed(block, /* buffer_size */ 256);
            }

            inline void construct_variables(PSIParams &params)
            {
                // Is the MPH initialized? It better be.
                if (!pool_)
                {
                    throw std::logic_error("MemoryPoolHandle is null");
                }
                if (!symm_block_vec_)
                {
                    // Append field vectors after each other to form the matrix
                    std::vector<std::shared_ptr<FField> > field_matrix;
                    for(int i = 0; i < params.split_size() + 1; i++)
                    {
                        field_matrix.insert(field_matrix.end(), exfield_.begin(), exfield_.end()); 
                    }

                    symm_block_vec_ = std::make_unique<FFieldArray>(field_matrix);
                    symm_block_ = MatrixView<_ffield_array_elt_t>(symm_block_vec_->data(), params.batch_size(), params.split_size() + 1);
                }
            }

            inline MatrixView<_ffield_array_elt_t> symm_block()
            {
                return symm_block_;
            }

            apsi::tools::PRNG& prng()
            {
                return prng_;
            }

            void set_total_randomized_polys(int total)
            {
                total_randomized_polys_ = total;
            }

            void set_total_interpolate_polys(int total)
            {
                total_interpolate_polys_ = total;
            }

            void clear_processed_counts()
            {
                randomized_polys_processed_ = 0;
                interpolate_polys_processed_ = 0;
            }

            void inc_randomized_polys()
            {
                randomized_polys_processed_++;
            }

            void inc_interpolate_polys()
            {
                interpolate_polys_processed_++;
            }

            /**
            Get current progress of work in the thread serviced by this context.
            Progress is reported as a floating number between 0 and 1.
            */
            float get_progress() const
            {
                float randomized_polys_progress = static_cast<float>(randomized_polys_processed_) / total_randomized_polys_;

                // If we are not using labels, only report randomized polynomials progress
                if (total_interpolate_polys_ == 0)
                    return randomized_polys_progress;

                float interpolate_polys_progress = static_cast<float>(interpolate_polys_processed_) / total_interpolate_polys_;

                return (randomized_polys_progress + interpolate_polys_progress) / 2;
            }

        private:
            int id_;

            seal::MemoryPoolHandle pool_;

            std::vector<std::shared_ptr<FField> > exfield_;

            std::unique_ptr<FFieldArray> symm_block_vec_;

            MatrixView<_ffield_array_elt_t> symm_block_;
            
            apsi::tools::PRNG prng_;

            std::atomic<int> randomized_polys_processed_;
            std::atomic<int> interpolate_polys_processed_;
            int total_randomized_polys_;
            int total_interpolate_polys_;
        };
    }
}
