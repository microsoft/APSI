#pragma once

#include "seal/util/exfield.h"
#include "seal/util/exfieldpolycrt.h"
#include "seal/util/mempool.h"

#include "seal/evaluator.h"
#include "seal/polycrt.h"
#include "seal/encryptor.h"
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
			SenderThreadContext()
			{

			}

			SenderThreadContext(int id,
				std::shared_ptr<seal::util::ExField> exfield,
				std::shared_ptr<seal::Encryptor> encryptor,
				std::shared_ptr<seal::Evaluator> evaluator,
				std::shared_ptr<seal::PolyCRTBuilder> builder,
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

			std::shared_ptr<seal::util::ExField> &exfield()
			{
				return exfield_;
			}

			void set_exfield(std::shared_ptr<seal::util::ExField> exfield)
			{
				exfield_ = move(exfield);
			}

			std::shared_ptr<seal::Encryptor> &encryptor()
			{
				return encryptor_;
			}

			void set_encryptor(std::shared_ptr<seal::Encryptor> encryptor)
			{
				encryptor_ = std::move(encryptor);
			}

			std::shared_ptr<seal::Evaluator> &evaluator()
			{
				return evaluator_;
			}

			void set_evaluator(std::shared_ptr<seal::Evaluator> evaluator)
			{
				evaluator_ = std::move(evaluator);
			}

			std::shared_ptr<seal::util::ExFieldPolyCRTBuilder> &exbuilder()
			{
				return exbuilder_;
			}

			void set_exbuilder(std::shared_ptr<seal::util::ExFieldPolyCRTBuilder> batcher)
			{
				exbuilder_ = std::move(batcher);
			}

			std::shared_ptr<seal::PolyCRTBuilder> &builder()
			{
				return builder_;
			}

			void set_builder(std::shared_ptr<seal::PolyCRTBuilder> builder)
			{
				builder_ = std::move(builder);
			}

			void construct_variables(PSIParams& params)
			{
				if (symm_block_.size() == 0)
				{
					symm_block_vec_ = std::move(exfield_->allocate_elements(params.batch_size() * (params.split_size() + 1), symm_block_backing_));
					symm_block_ = oc::MatrixView<seal::util::ExFieldElement>(symm_block_vec_.begin(), symm_block_vec_.end(), params.split_size() + 1);

					batch_vector_ = std::move(exfield_->allocate_elements(params.batch_size(), batch_backing_));
					integer_batch_vector_.resize(params.batch_size(), 0);
				}
			}

			oc::MatrixView<seal::util::ExFieldElement> symm_block()
			{
				return symm_block_;
			}


			std::vector<seal::util::ExFieldElement>& batch_vector()
			{
				return batch_vector_;
			}
			std::vector<uint64_t>& integer_batch_vector()
			{
				return integer_batch_vector_;
			}

		private:
			int id_;
			std::shared_ptr<seal::util::ExField> exfield_;
			std::shared_ptr<seal::Evaluator> evaluator_;
			std::shared_ptr<seal::Encryptor> encryptor_;
			std::shared_ptr<seal::PolyCRTBuilder> builder_;
			std::shared_ptr<seal::util::ExFieldPolyCRTBuilder> exbuilder_;


			seal::util::Pointer symm_block_backing_;
			std::vector<seal::util::ExFieldElement> symm_block_vec_;// = exfield->allocate_elements(params_.batch_size(), params_.split_size() + 1, symm_block_backing);
			oc::MatrixView<seal::util::ExFieldElement> symm_block_;

			seal::util::Pointer batch_backing_;
			std::vector<seal::util::ExFieldElement > batch_vector_;// = context.exfield()->allocate_elements(params_.batch_size(), batch_backing);
			std::vector<uint64_t> integer_batch_vector_;// (params_.batch_size(), 0);

		};
	}
}
