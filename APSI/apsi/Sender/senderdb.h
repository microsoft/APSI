#pragma once

// STD
#include <memory>
#include <vector>
#include <iostream>
#include <atomic>

// APSI
#include "apsi/item.h"
#include "apsi/apsidefines.h"
#include "apsi/psiparams.h"
#include "apsi/sender/senderthreadcontext.h"

// Cuckoo
#include "cuckoo/cuckoo.h"

// SEAL
#include "seal/plaintext.h"
#include "seal/evaluator.h"
#include "seal/polycrt.h"
#include "seal/util/exfield.h"

// CryptoTools
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Crypto/PRNG.h"

namespace apsi
{
    namespace sender
    {
        class SenderDB
        {
        public:
            SenderDB(const PSIParams &params, std::shared_ptr<seal::util::ExField> &ex_field);

            /**
            Clears sender's database and set all entries to sender's null item.
            */
            void clear_db();

            /**
            Sets the sender's database by hashing the data items with all hash functions.
            */
            void set_data(oc::span<const Item> keys);
            void set_data(oc::span<const Item> keys, oc::span<const Item> values);


            /**
            Adds the data items to sender's database.
            */
            void add_data(oc::span<const Item> keys);
            void add_data(oc::span<const Item> keys, oc::span<const Item> values);

            /**
            Adds one item to sender's database.
            */
            void add_data(const Item &item);

            /**
            Deletes the data items in the sender's database. Items are ignored if they don't exist in the database.
            */
            //void delete_data(oc::span<const Item> data);

            /**
            Deletes one item in sender's database. The item is ignored if it doesn't exist in the database.
            */
            //void delete_data(const Item &item);

            //void save(std::ostream &stream) const;

            //void load(std::istream &stream);

            std::vector<seal::Plaintext> &batch_random_symm_polys()
            {
                return batch_random_symm_polys_;
            }

            /**
            Batches the randomized symmetric polynonmials for the specified split and the specified batch in sender's database.

            @see randomized_symmetric_polys for computing randomized symmetric polynomials.
            */
            void batched_randomized_symmetric_polys(
                SenderThreadContext &context,
                std::shared_ptr<seal::Evaluator> evaluator, 
                std::shared_ptr<seal::PolyCRTBuilder> builder);



            Item& get_key(u64 cuckoo_index, u64 position_idx) {
                return keys_(position_idx, cuckoo_index);
            }
            Item& get_value(u64 cuckoo_index, u64 position_idx) {
                return values_(position_idx, cuckoo_index);
            }

            const Item& get_key(u64 cuckoo_index, u64 position_idx) const {
                return keys_(position_idx, cuckoo_index);
            }
            const Item& get_value(u64 cuckoo_index, u64 position_idx) const {
                return values_(position_idx, cuckoo_index);
            }


        private:
            /**
            Computes the symmetric polynomials for the specified split and the specified batch in sender's database.
            One symmetric polynomial is computed for one sub-bin (because a bin is separated into splits).
            Input sub-bin: (a_1, a_2, ..., a_n)
            Output polynomial terms: (1, \sum_i a_i, \sum_{i,j} a_i*a_j, ...).
            */
            void symmetric_polys(
                int split, 
                int batch, 
                SenderThreadContext &context, 
                oc::MatrixView<seal::util::ExFieldElement> symm_block);

            /**
            Computes the randomized symmetric polynomials for the specified split and the specified batch in sender's database. Basically, it
            multiplies each term in a symmetric polynomial with the same random number. Different symmetric polynomials are multiplied with 
            different random numbers.

            @see symmetric_polys for computing symmetric polynomials.
            */
            void randomized_symmetric_polys(
                int split, 
                int batch, 
                SenderThreadContext &context, 
                oc::MatrixView<seal::util::ExFieldElement>symm_block);

            //const oc::Matrix<Item>& simple_hashing_db2() const
            //{
            //    return simple_hashing_db2_;
            //}

            PSIParams params_;

            cuckoo::PermutationBasedCuckoo::Encoder encoder_;

            int encoding_bit_length_;

            /* 
            Null value for sender: 00..0011..11. The number of 1 is itemL.
            (Note: Null value for receiver is: 00..0010..00, with 1 on the itemL-th position.)
            */
            Item sender_null_item_;

            /* The ExField encoding of the sender null value. */
            seal::util::ExFieldElement null_element_, neg_null_element_;

            std::shared_ptr<seal::util::ExField> global_ex_field_;

            /* 
            B x m, where B is sender's bin size, m is table size.
            This is actually a rotated view of the DB. We store it in this
            view so that multi-threading is more efficient for accessing data, 
            i.e., one thread will take care of several continuous complete rows. 
            */
            oc::Matrix<Item> keys_, values_;

            std::unique_ptr<std::atomic_bool[]> simple_hashing_db_has_item_;

            /* 
            Thread safe function to insert an item into the bin 
            index by cockooIndex. The PRNG and be any PRNG.  
            */
            int aquire_bin_location(int cockooIndex, oc::PRNG& prng);
            
            /* 
            Returns true if the position'th slot within the bin at cockooIndex 
            currently has an item. */
            bool has_item(int cockooIndex, int position);

            /* 
            Size m vector, where m is the table size. Each value is an incremental counter for the 
            corresponding bin in shuffle_index_. It points to the next value to be taken from shuffle_index_
            in the corresponding bin. */
            std::vector<int> next_locs_;

            /* 
            Batched randomized symmetric polynomial terms.
            #splits x #batches x (split_size + 1). In fact, B = #splits x split_size. The table is
            essentially split into '#splits x #batches' blocks. Each block is related with a split
            and a batch.
            */
            std::vector<seal::Plaintext> batch_random_symm_polys_;

            oc::PRNG prng_;
        };
    }
}
