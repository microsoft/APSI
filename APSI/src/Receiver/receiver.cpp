#include "Receiver/receiver.h"
#include "util/uintcore.h"
#include "encryptionparams.h"
#include "keygenerator.h"
#include "Sender/sender.h"
#include "apsidefines.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace cuckoo;
using namespace apsi::tools;

namespace apsi
{
	namespace receiver
	{
		Receiver::Receiver(const PSIParams &params, const MemoryPoolHandle &pool)
			:params_(params), 
			pool_(pool),
			ex_ring_(ExRing::acquire_ring(params.exring_characteristic(), params.exring_exponent(), params.exring_polymod(), pool))
		{
			initialize();
		}

		void Receiver::initialize()
		{
			EncryptionParameters enc_params;
			
			enc_params.set_poly_modulus("1x^" + to_string(params_.poly_degree()) + " + 1");
			enc_params.set_coeff_modulus(params_.coeff_modulus());
			enc_params.set_plain_modulus(params_.exring_characteristic());
			enc_params.set_decomposition_bit_count(params_.decomposition_bit_count());
			
			SEALContext seal_context(enc_params);
			KeyGenerator generator(seal_context);
			generator.generate();

			public_key_ = generator.public_key();
			secret_key_ = generator.secret_key();

			encryptor_.reset(new Encryptor(seal_context, public_key_));
			decryptor_.reset(new Decryptor(seal_context, secret_key_));

			generator.generate_evaluation_keys(1);
			evaluation_keys_ = generator.evaluation_keys();

			expolycrtbuilder_.reset(new ExPolyCRTBuilder(ex_ring_, params_.log_poly_degree()));
			
			ex_ring_->init_frobe_table();
		}

		vector<bool> Receiver::query(const vector<Item> &items, apsi::sender::Sender &sender)
		{
			clear_memory_backing();

			unique_ptr<PermutationBasedCuckoo> cuckoo = cuckoo_hashing(items);

			vector<int> indices = cuckoo_indices(items, *cuckoo);

			vector<ExRingElement> exring_items = exring_encoding(*cuckoo);

			map<uint64_t, vector<ExRingElement>> powers = generate_powers(exring_items);

			map<uint64_t, vector<Ciphertext>> ciphers = encrypt(powers);

			/* Send to sender. */
			vector<vector<Ciphertext>> result_ciphers = sender.respond(ciphers);
			vector<vector<ExRingElement>> result = decrypt(result_ciphers);

			vector<bool> tmp(params_.table_size(), false);
			ExRingElement zero(ex_ring_);
			for (int i = 0; i < params_.table_size(); i++)
			{
				bool match_found = false;
				for(int j = 0; j < params_.number_of_splits(); j++)
				{
					if (result[j][i] == zero)
					{
						match_found = true;
						break;
					}
				}
				if (match_found)
					tmp[i] = true;
			}

			/* Now we need to shorten and convert this tmp vector to match the length and indice of the query "items". */
			vector<bool> intersection(items.size(), false);
			for (int i = 0; i < indices.size(); i++)
				intersection[i] = tmp[indices[i]];

			return intersection;
		}

		unique_ptr<PermutationBasedCuckoo> Receiver::cuckoo_hashing(const vector<Item> &items)
		{
			unique_ptr<PermutationBasedCuckoo> cuckoo(
				new PermutationBasedCuckoo(params_.hash_func_count(), params_.hash_func_seed(), params_.log_table_size(), params_.item_bit_length(), params_.max_probe()));
			bool insertionSuccess;
			for (int i = 0; i < items.size(); i++)
			{
				insertionSuccess = cuckoo->insert(items[i].data());
				if (!insertionSuccess)
					throw logic_error("cuck hashing failed.");
			}
			/* Lock to truncate the table items. */
			cuckoo->lock_table_final();
			
			return cuckoo;
		}

		std::vector<int> Receiver::cuckoo_indices(const std::vector<Item> &items, cuckoo::PermutationBasedCuckoo &cuckoo)
		{
			vector<int> indice(items.size(), -1);

			vector<uint64_t> locs;
			int bin_bit_length = cuckoo.bin_bit_length(), bin_uint64_count = cuckoo.bin_u64_length(),
				item_bit_length = cuckoo.item_bit_length(), log_capacity = cuckoo.log_capacity(),
				shifted_bin_uint64_count = (bin_bit_length - log_capacity + 63) / 64;
			unique_ptr<uint64_t> temp_item(new uint64_t[bin_uint64_count]);
			uint64_t top_u64_mask = (static_cast<uint64_t>(1) << ((item_bit_length - log_capacity) % 64)) - 1;
			for (int i = 0; i < items.size(); i++)
			{
				right_shift_uint(items[i].data(), temp_item.get(), log_capacity, bin_uint64_count); // Assuming item and bin have the same uint64_t count.
				zero_uint(temp_item.get() + shifted_bin_uint64_count, bin_uint64_count - shifted_bin_uint64_count);
				uint64_t *shifted_item_top_ptr = temp_item.get() + shifted_bin_uint64_count - 1;

				cuckoo.get_locations(items[i].data(), locs);
				for (int j = 0; j < locs.size(); j++)
				{
					*shifted_item_top_ptr &= top_u64_mask;
					*shifted_item_top_ptr ^= (static_cast<uint64_t>(j) << ((item_bit_length - log_capacity) % 64));

					if (are_equal_uint(cuckoo.hash_table_item(locs[j]), temp_item.get(), bin_uint64_count))
						indice[i] = locs[j];
				}
			}
			return indice;
		}

		vector<ExRingElement> Receiver::exring_encoding(const PermutationBasedCuckoo &cuckoo)
		{
			memory_backing_.emplace_back(Pointer());
			vector<ExRingElement> exring_items = ex_ring_->allocate_elements(cuckoo.capacity(), memory_backing_.back());
			int bin_u64_len = cuckoo.bin_u64_length();
			Item item;
			for (int i = 0; i < cuckoo.capacity(); i++)
			{
				const uint64_t *cuckoo_item = cuckoo.hash_table_item(i);
				item[0] = *cuckoo_item;
				if (bin_u64_len > 1)
					item[1] = *(cuckoo_item + 1);
				else
					item[1] = 0;

				item.to_exring_element(exring_items[i]);
			}
			return exring_items;
		}

		map<uint64_t, vector<ExRingElement> > Receiver::generate_powers(const vector<ExRingElement> &exring_items)
		{
			map<uint64_t, vector<ExRingElement> > result;
			int split_size = (params_.sender_bin_size() + params_.number_of_splits() - 1) / params_.number_of_splits();
			int window_size = params_.window_size();
			int radix = 1 << window_size;
			int bound = floor(log2(split_size) / window_size) + 1;

			vector<ExRingElement> current_power = exring_items;
			for (int j = 0; j < bound; j++)
			{
				result[1 << (window_size * j)] = current_power;
				for (int i = 2; i < radix; i++)
				{
					if (i * (static_cast<uint64_t>(1) << (window_size * j)) > split_size)
					{
						return result;
					}
					memory_backing_.emplace_back(Pointer());
					result[i * (1 << (window_size * j))] = ex_ring_->allocate_elements(current_power.size(), memory_backing_.back());
					ex_ring_->dyadic_multiply(result[(i - 1)*(1 << (window_size*j))], current_power, result[i * (1 << (window_size * j))]);
				}
				for (int k = 0; k < window_size; k++)
				{
					ex_ring_->dyadic_square_inplace(current_power);
				}
			}

			return result;
		}

		std::map<uint64_t, vector<Ciphertext>> Receiver::encrypt(std::map<uint64_t, std::vector<ExRingElement>> &input)
		{
			map<uint64_t, vector<Ciphertext>> result;

			for (map<uint64_t, vector<ExRingElement>>::iterator it = input.begin(); it != input.end(); it++)
			{
				result[it->first] = encrypt(it->second);
			}

			return result;
		}

		vector<Ciphertext> Receiver::encrypt(const vector<ExRingElement> &input)
		{
			int batch_size = expolycrtbuilder_->slot_count(), num_of_batches = (input.size() + batch_size - 1) / batch_size;
			Pointer tmp_backing;
			vector<ExRingElement> batch = ex_ring_->allocate_elements(batch_size, tmp_backing);
			vector<Ciphertext> result;
			for (int i = 0; i < num_of_batches; i++)
			{
				for (int j = 0; (j < batch_size) && ((i * batch_size + j) < input.size()); j++)
					batch[j] = input[i * batch_size + j];
				result.emplace_back(
					encryptor_->encrypt(
						expolycrtbuilder_->compose(batch)));
			}
			return result;
		}

		vector<vector<ExRingElement>> Receiver::decrypt(const vector<vector<Ciphertext>> &result_ciphers)
		{
			if (result_ciphers.size() != params_.number_of_splits() || result_ciphers[0].size() != params_.number_of_batches())
				throw invalid_argument("Result ciphers have unexpexted sizes.");

			vector<vector<ExRingElement>> result;
			for (int i = 0; i < result_ciphers.size(); i++)
			{
				result.emplace_back(decrypt(result_ciphers[i]));
			}
			cout << "Remaining Nosie Budget: " << decryptor_->invariant_noise_budget(result_ciphers[0][0]) << endl;
			return result;
		}

		vector<ExRingElement> Receiver::decrypt(const vector<Ciphertext> &ciphers)
		{
			int slot_count = expolycrtbuilder_->slot_count();
			memory_backing_.emplace_back(Pointer());
			vector<ExRingElement> result = ex_ring_->allocate_elements(ciphers.size() * slot_count, memory_backing_.back());
			Pointer tmp_backing;
			vector<ExRingElement> temp = ex_ring_->allocate_elements(slot_count, tmp_backing);
			for (int i = 0; i < ciphers.size(); i++)
			{
				expolycrtbuilder_->decompose(decryptor_->decrypt(ciphers[i]), temp);
				for(int j = 0; j < temp.size(); j++)
					result[i * slot_count + j] = temp[j];
			}
			return result;
		}
	}
}