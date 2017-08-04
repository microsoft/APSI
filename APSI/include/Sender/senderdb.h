#pragma once

#include "item.h"
#include "psiparams.h"
#include "cuckoo.h"
#include "util/exring.h"
#include "evaluator.h"
#include "util/expolycrt.h"
#include "senderthreadcontext.h"

namespace apsi
{
	namespace sender
	{
		class SenderDB
		{
		public:
			SenderDB(const PSIParams &params, std::shared_ptr<seal::util::ExRing> ex_ring);

			/**
			Clears sender's database and set all entries to sender's null item.
			*/
			void clear_db();

			/**
			Resets the flags for precomputed results to make them stale.
			*/
			void reset_precomputation()
			{
				for (int i = 0; i < params_.number_of_splits(); i++)
					for (int j = 0; j < params_.number_of_batches(); j++)
						symm_polys_stale_[i][j] = true;
			}

			/**
			Generates random indices for randomly permute sender items in each bin. 
			*/
			void shuffle();

			/**
			Sets the sender's database by hashing the data items with all hash functions.
			*/
			void set_data(const std::vector<Item> &data);

			/**
			Adds the data items to sender's database.
			*/
			void add_data(const std::vector<Item> &data);

			/**
			Adds one item to sender's database.
			*/
			void add_data(const Item &item);

			/**
			Computes the symmetric polynomials for the specified split in sender's database.
			One symmetric polynomial is computed for one sub-bin (because a bin is separated into splits).
			Input sub-bin: (a_1, a_2, ..., a_n)
			Output polynomial terms: (1, \sum_i a_i, \sum_{i,j} a_i*a_j, ...).
			*/
			std::vector<std::vector<seal::util::ExRingElement>>& symmetric_polys(int splitIndex, SenderThreadContext &context);

			/**
			Computes the symmetric polynomials for the specified split and the specified batch in sender's database.
			One symmetric polynomial is computed for one sub-bin (because a bin is separated into splits).
			Input sub-bin: (a_1, a_2, ..., a_n)
			Output polynomial terms: (1, \sum_i a_i, \sum_{i,j} a_i*a_j, ...).
			*/
			void symmetric_polys(int split, int batch, SenderThreadContext &context);

			/**
			Computes the randomized symmetric polynomials for the specified split in sender's database. Basically, it multiplies each term in a
			symmetric polynomial with the same random number. Different symmetric polynomials are multiplied with different random numbers.

			@see symmetric_polys for computing symmetric polynomials.
			*/
			std::vector<std::vector<seal::util::ExRingElement>>& randomized_symmetric_polys(int splitIndex, SenderThreadContext &context);

			/**
			Computes the randomized symmetric polynomials for the specified split and the specified batch in sender's database. Basically, it
			multiplies each term in a symmetric polynomial with the same random number. Different symmetric polynomials are multiplied with 
			different random numbers.

			@see symmetric_polys for computing symmetric polynomials.
			*/
			void randomized_symmetric_polys(int split, int batch, SenderThreadContext &context);

			/**
			Batches the randomized symmetric polynonmials for the specified split in sender's database.

			@see randomized_symmetric_polys for computing randomized symmetric polynomials.
			*/
			std::vector<std::vector<seal::Plaintext>>& batched_randomized_symmetric_polys(
				int split, SenderThreadContext &context);

			/**
			Batches the randomized symmetric polynonmials for the specified split and the specified batch in sender's database.

			@see randomized_symmetric_polys for computing randomized symmetric polynomials.
			*/
			std::vector<seal::Plaintext>& batched_randomized_symmetric_polys(
				int split, int batch, SenderThreadContext &context);

			const std::vector<std::vector<Item>>& simple_hashing_db() const
			{
				return simple_hashing_db_;
			}

		private:

			PSIParams params_;

			/* Null value for sender: 00..0011..11. The number of 1 is itemL.
			(Note: Null value for receiver is: 00..0010..00, with 1 on the itemL-th position.)
			*/
			Item sender_null_item_;

			cuckoo::PermutationBasedCuckoo cuckoo_;

			std::shared_ptr<seal::util::ExRing> global_ex_ring_;

			/* B x m, where B is sender's bin size, m is table size.
			This is actually a rotated view of the DB. We store it in this
			view so that multi-threading is more efficient for accessing data, 
			i.e., one thread will take care of several continuous complete rows. */
			std::vector<std::vector<Item>> simple_hashing_db_;

			/* m x B, where m is table size, B is sender's bin size. Keep in this view
			so that we can conveniently shuffle each row (bin) using STL. */
			std::vector<std::vector<int>> shuffle_index_;

			/* size m vector, where m is the table size. Each value is an incremental counter for the 
			corresponding bin in shuffle_index_. It points to the next value to be taken from shuffle_index_
			in the corresponding bin. */
			std::vector<int> next_shuffle_locs_;

			/* B x m, the corresponding ExRing version of the DB. Refer to simple_hashing_db_. */
			std::vector<std::vector<seal::util::ExRingElement>> exring_db_;
			seal::util::Pointer exring_db_backing_;

			/* Symmetric polynomial terms. 
			#splits x m x (split_size + 1). In fact, B = #splits x split_size. The table is 
			essentially split into '#splits' parts, and we add an extra row for each part to
			store the coefficient '1' of the highest degree terms in the symmetric polynomials. */
			std::vector<std::vector<std::vector<seal::util::ExRingElement>>> symm_polys_;
			seal::util::Pointer symm_polys_backing_;

			/* Randomized symmetric polynomial terms.
			#splits x m x (split_size + 1). In fact, B = #splits x split_size. The table is
			essentially split into '#splits' parts, and we add an extra row for each part to
			store the coefficient '1' of the highest degree terms in the symmetric polynomials.
			*/
			std::vector<std::vector<std::vector<seal::util::ExRingElement>>> random_symm_polys_;
			seal::util::Pointer random_symm_polys_backing_;
			
			/* Batched randomized symmetric polynomial terms.
			#splits x #batches x (split_size + 1). In fact, B = #splits x split_size. The table is
			essentially split into '#splits x #batches' blocks. Each block is related with a split
			and a batch.
			*/
			std::vector<std::vector<std::vector<seal::Plaintext>>> batch_random_symm_polys_;

			/*
			#splits x #batches. Flags indicating whether the blocks need to be re-computed or not.
			*/
			std::vector<std::vector<bool>> symm_polys_stale_;
		};
	}
}