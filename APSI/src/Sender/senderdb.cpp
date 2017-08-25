
#include "Sender/senderdb.h"
#include "apsidefines.h"
#include "util/uintcore.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    namespace sender
    {
        SenderDB::SenderDB(const PSIParams& params, shared_ptr<ExField> ex_field)
            :params_(params),
            global_ex_field_(ex_field),
            cuckoo_(params.hash_func_count(), params.hash_func_seed(), params.log_table_size(), params.item_bit_length(), params.max_probe()),
            simple_hashing_db_(params.sender_bin_size(), vector<Item>(params.table_size())),
            shuffle_index_(params.table_size(), vector<int>(params.sender_bin_size())),
            symm_polys_stale_(params.number_of_splits(), vector<bool>(params.number_of_batches(), true)),
            batch_random_symm_polys_(params.number_of_splits(), vector<vector<Plaintext>>(params.number_of_batches(), vector<Plaintext>(params.split_size() + 1)))
        {
            exfield_db_ = global_ex_field_->allocate_elements(params_.sender_bin_size(), params_.table_size(), exfield_db_backing_);

            symm_polys_ = global_ex_field_->allocate_elements(
                params_.number_of_splits(), params_.table_size(), params_.split_size() + 1, symm_polys_backing_);

            random_symm_polys_ = global_ex_field_->allocate_elements(
                params_.number_of_splits(), params_.table_size(), params_.split_size() + 1, random_symm_polys_backing_);

            /* Set null value for sender: 00..0011..11, with itemL's 1 */
            sender_null_item_.fill(~static_cast<uint64_t>(0));
            right_shift_uint(sender_null_item_.data(), sender_null_item_.data(),
                (sender_null_item_.bit_count() - cuckoo_.itemL_bit_length()), sender_null_item_.uint64_count());

            null_element_ = sender_null_item_.to_exfield_element(global_ex_field_);

            /* Set nature index */
            for (int i = 0; i < params_.table_size(); i++)
                for (int j = 0; j < params_.sender_bin_size(); j++)
                    shuffle_index_[i][j] = j;

        }

        void SenderDB::clear_db()
        {
            for (int i = 0; i < params_.sender_bin_size(); i++)
                for (int j = 0; j < params_.table_size(); j++)
                {
                    simple_hashing_db_[i][j] = sender_null_item_;
                    exfield_db_[i][j] = null_element_;
                }

            shuffle();

            reset_precomputation();
        }

        void SenderDB::set_data(const vector<Item> &data)
        {
            clear_db();
            
            add_data(data);
        }

        void SenderDB::add_data(const vector<Item> &data)
        {
            vector<uint64_t> hash_locations;
            for (int i = 0; i < data.size(); i++)
            {
                cuckoo_.get_locations(data[i].data(), hash_locations);
                for (int j = 0; j < hash_locations.size(); j++)
                {
                    if (next_shuffle_locs_[hash_locations[j]] >= params_.sender_bin_size())
                        throw logic_error("Simple hashing failed. Bin size too small.");
                    int index = shuffle_index_[hash_locations[j]][next_shuffle_locs_[hash_locations[j]]++];

                    simple_hashing_db_[index][hash_locations[j]] = data[i];
                    simple_hashing_db_[index][hash_locations[j]].to_itemL(cuckoo_, j);

                    /* Encode the item to an ExField element. */
                    simple_hashing_db_[index][hash_locations[j]].to_exfield_element(exfield_db_[index][hash_locations[j]]);

                    /* Set the block that contains this item to be stale. */
                    symm_polys_stale_[index / params_.split_size()][hash_locations[j] / params_.batch_size()] = true;
                }
            }
        }

        void SenderDB::add_data(const Item &item)
        {
            add_data(vector<Item>(1, item));
        }

        void SenderDB::delete_data(const std::vector<Item> &data)
        {
            vector<uint64_t> hash_locations;
            for (int i = 0; i < data.size(); i++)
            {
                cuckoo_.get_locations(data[i].data(), hash_locations);
                for (int j = 0; j < hash_locations.size(); j++)
                {
                    Item target_itemL = data[i].itemL(cuckoo_, j);
                    for (int k = 0; k < next_shuffle_locs_[hash_locations[j]]; k++)
                    {
                        int index = shuffle_index_[hash_locations[j]][k];
                        if (simple_hashing_db_[index][hash_locations[j]] == target_itemL) /* Item is found. Delete it. */
                        {
                            simple_hashing_db_[index][hash_locations[j]] = sender_null_item_;
                            exfield_db_[index][hash_locations[j]] = null_element_;

                            /* Set the block that contains this item to be stale. */
                            symm_polys_stale_[index / params_.split_size()][hash_locations[j] / params_.batch_size()] = true;
                        }
                    }
                }
            }
        }

        void SenderDB::delete_data(const Item &item)
        {
            delete_data(vector<Item>(1, item));
        }

        void SenderDB::shuffle()
        {
            for (int i = 0; i < params_.table_size(); i++)
                random_shuffle(shuffle_index_[i].begin(), shuffle_index_[i].end());
            next_shuffle_locs_.assign(params_.table_size(), 0);
        }

        vector<vector<ExFieldElement>>& SenderDB::symmetric_polys(int split, SenderThreadContext &context)
        {
            for (int i = 0; i < params_.number_of_batches(); i++)
                symmetric_polys(split, i, context);

            return symm_polys_[split];
        }

        void SenderDB::symmetric_polys(int split, int batch, SenderThreadContext &context)
        {
            int table_size = params_.table_size(), split_size = params_.split_size(), batch_size = params_.batch_size(), split_start = split * split_size,
                batch_start = batch * batch_size, batch_end = (batch_start + batch_size < table_size? (batch_start + batch_size) : table_size);

            shared_ptr<ExField> exfield = context.exfield();

            ExFieldElement one(exfield, "1");
            ExFieldElement temp1(exfield), temp2(exfield);
            for (int i = batch_start; i < batch_end; i++)
            {
                symm_polys_[split][i][split_size] = one;
                for (int j = split_size - 1; j >= 0; j--)
                {
                    exfield->negate(exfield_db_[split_start + j][i], temp1);
                    exfield->multiply(
                        symm_polys_[split][i][j + 1],
                        temp1,
                        symm_polys_[split][i][j]);

                    for (int k = j + 1; k < split_size; k++)
                    {
                        exfield->multiply(
                            symm_polys_[split][i][k + 1],
                            temp1,
                            temp2);
                        symm_polys_[split][i][k] += temp2;
                    }
                }
            }
        }

        vector<vector<ExFieldElement>>& SenderDB::randomized_symmetric_polys(int split, SenderThreadContext &context)
        {
            for (int i = 0; i < params_.number_of_batches(); i++)
                randomized_symmetric_polys(split, i, context);

            return random_symm_polys_[split];
        }

        void SenderDB::randomized_symmetric_polys(int split, int batch, SenderThreadContext &context)
        {
            symmetric_polys(split, batch, context);

            int table_size = params_.table_size(), split_size = params_.split_size(), batch_size = params_.batch_size(),
                batch_start = batch * batch_size, batch_end = (batch_start + batch_size < table_size ? (batch_start + batch_size) : table_size);

            for (int i = batch_start; i < batch_end; i++)
            {
                //ExFieldElement r = context.exfield()->random_element();
                ExFieldElement r = ExFieldElement(context.exfield(), string("1"));
                for (int j = 0; j < split_size + 1; j++)
                    context.exfield()->multiply(symm_polys_[split][i][j], r, random_symm_polys_[split][i][j]);
            }
        }

        vector<vector<Plaintext>>& SenderDB::batched_randomized_symmetric_polys(int split, SenderThreadContext &context)
        {
            for (int i = 0; i < params_.number_of_batches(); i++)
                batched_randomized_symmetric_polys(split, i, context);
            
            return batch_random_symm_polys_[split];
        }

        vector<Plaintext>& SenderDB::batched_randomized_symmetric_polys(
            int split, int batch, SenderThreadContext &context)
        {
            if (!symm_polys_stale_[split][batch])
                return batch_random_symm_polys_[split][batch];

            randomized_symmetric_polys(split, batch, context);

            int table_size = params_.table_size(), split_size = params_.split_size(), split_start = split * split_size, batch_size = params_.batch_size(),
                batch_start = batch * batch_size, batch_end = (batch_start + batch_size < table_size ? (batch_start + batch_size) : table_size);;
            Pointer batch_backing;
            vector<ExFieldElement> batch_vector = context.exfield()->allocate_elements(batch_size, batch_backing);
            vector<uint64_t> integer_batch_vector(batch_size, 0);

            
            for (int i = 0; i < split_size + 1; i++)
            {
                Plaintext temp_plain;
                if (context.builder())
                {
                    for (int k = 0; batch_start + k < batch_end; k++)
                        integer_batch_vector[k] = *random_symm_polys_[split][batch_start + k][i].pointer(0);
                    temp_plain = context.builder()->compose(integer_batch_vector);
                }
                else // This branch works even if ex_field_ is an integer field, but it is slower than normal batching.
                {
                    for (int k = 0; batch_start + k < batch_end; k++)
                        batch_vector[k] = random_symm_polys_[split][batch_start + k][i];
                    temp_plain = context.exbuilder()->compose(batch_vector);
                }

                context.evaluator()->transform_to_ntt(temp_plain);
                batch_random_symm_polys_[split][batch][i] = temp_plain;
            }

            symm_polys_stale_[split][batch] = false;
            return batch_random_symm_polys_[split][batch];
        }
    }
}