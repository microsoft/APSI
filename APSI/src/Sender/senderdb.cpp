
#include "Sender/senderdb.h"
#include "apsidefines.h"
#include "util/uintcore.h"
#include <fstream>
#include <algorithm>
#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/MatrixView.h"
#include <thread>
#include <cryptoTools/Crypto/sha1.h>
#include <unordered_map>

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
	namespace sender
	{
		SenderDB::SenderDB(const PSIParams& params, shared_ptr<ExField> ex_field, bool dummy_init)
			:
			dummy_init_(dummy_init),
			params_(params),
			global_ex_field_(ex_field),
			cuckoo_(params.hash_func_count(), params.hash_func_seed(), params.log_table_size(), params.item_bit_length(), params.max_probe()),
			simple_hashing_db2_(params.sender_bin_size(), params.table_size()),
			//simple_hashing_db_empty_(params.sender_bin_size() * params.table_size(), true),
			//shuffle_index2_(params.table_size(), params_.sender_bin_size()),
			next_locs_(params.table_size(), 0),
			//cuckoo_location_lock_(new std::atomic_bool[params_.table_size()]),
			//symm_polys_stale_(params.number_of_splits(), vector<char>(params.number_of_batches(), true)),
			batch_random_symm_polys_(params.number_of_splits() * params.number_of_batches() * (params.split_size() + 1))

		{

			//for (int i = 0; i < params_.table_size(); ++i)
			//	cuckoo_location_lock_[i] = false;

			int characteristic_bit_count = util::get_significant_bit_count(params_.exfield_characteristic());

			if (dummy_init_)
			{
				std::cout << "WARNING: dummy init(...)" << std::endl;
				for (auto& v : batch_random_symm_polys_)
				{
					v.resize(params_.coeff_modulus().size() * (params_.poly_degree() + 1));
					v[0] = 1;
				}
			}
			else
			{
				for (auto &plain : batch_random_symm_polys_)
					plain.resize(params_.coeff_modulus().size() * (params_.poly_degree() + 1));
			}

			oc::block seed;
			std::random_device rd;
			*(std::array<unsigned int, 4>*)&seed = { rd(), rd(), rd(), rd() };
			prng_.SetSeed(seed, 256);


			/* Set null value for sender: 00..0011..11, with itemL's 1 */
			sender_null_item_.fill(~static_cast<uint64_t>(0));
			right_shift_uint(sender_null_item_.data(), sender_null_item_.data(),
				(sender_null_item_.bit_count() - cuckoo_.itemL_bit_length()), sender_null_item_.uint64_count());

			null_element_ = sender_null_item_.to_exfield_element(global_ex_field_);

			// hack to get an allocation
			neg_null_element_ = global_ex_field_->random_element();
			global_ex_field_->negate(null_element_, neg_null_element_);

			sender_null_item_.fill(~static_cast<uint64_t>(0));
			/* Set nature index */
			//for (int j = 0; j < params_.sender_bin_size(); j++)
			//	shuffle_index2_(0, j) = j;

			//for (int i = 1; i < params_.table_size(); i++)
			//	memcpy(&shuffle_index2_(i, 0), &shuffle_index2_(0, 0), shuffle_index2_.stride());


		}

		void SenderDB::clear_db()
		{

			auto src = simple_hashing_db2_.data();
			//memset(src, -1, simple_hashing_db2_.size() * sizeof(Item));

			auto ss = params_.sender_bin_size() * params_.table_size();
#ifdef ADD_DATA_MULTI_THREAD
			simple_hashing_db_has_item_.reset(new std::atomic_bool[ss]());
			//simple_hashing_db_has_item_2.resize(ss, false);
			//bin_size_.resize(params_.table_size(),0);
#else
			simple_hashing_db_has_item_.resize(ss, false);
#endif

			// make sure the its zero init.
			for (int i = 0; i < ss; ++i)
				if (simple_hashing_db_has_item_[i])
					throw std::runtime_error(LOCATION);

			//std::fill(simple_hashing_db_empty_.begin(), simple_hashing_db_empty_.end(), true);
		}

		void SenderDB::set_data(const vector<Item> &data)
		{
			clear_db();
			add_data(data);
			stop_watch.set_time_point("Sender add-data");
		}

		void SenderDB::add_data(const vector<Item> &data)
		{
//#define ADD_DATA_MULTI_THREAD
			auto bin_size = params_.sender_bin_size();

			using namespace oc;

#ifdef  ADD_DATA_MULTI_THREAD 
			std::vector<std::thread> thrds(params_.sender_total_thread_count());
			for (int t = 0; t < thrds.size(); ++t)
			{
				auto seed = prng_.get<oc::block>();
				thrds[t] = std::thread(
					[&, t, seed](){
					oc::PRNG prng(seed, 256);
					auto start = t * data.size() / thrds.size();
					auto end = (t+1) * data.size() / thrds.size();
#else
					auto start = 0;
					auto end = data.size();
					auto& prng = prng_;
					std::unordered_map<u64, u64> map, map2;
					map.reserve(data.size());
					map2.reserve(data.size());
#endif
					EllipticCurve curve(p256k1, prng.get<oc::block>());
					std::vector<u8> buff(curve.getGenerator().sizeBytes());
					PRNG pp(oc::CCBlock);
					oc::EccNumber key_(curve, pp);


					std::vector<uint64_t> hash_locations;

					for (int i = start; i < end; i++)
					{

						//SHA1 ss;
						//ss.Update((oc::block&)data[i]);
						//oc::block bb;
						//ss.Final(bb);
						//auto dd = *(u64*)&bb;

						//auto iter = map.find(dd);
						//if (iter != map.end())
						//{
						//	std::cout<< " *** " << i << std::endl;
						//	//throw std::runtime_error(LOCATION);
						//}
						//map.insert({ dd, i });

						if (params_.use_pk_oprf())
						{
							static_assert(sizeof(oc::block) == sizeof(Item), "");
							oc::PRNG p((oc::block&)data[i], 8);
							//std::cout << p.get<oc::block>() << std::endl;
							oc::EccPoint a(curve, p);
							//std::cout<< "a1 " << a << std::endl;

							a *= key_;
							a.toBytes(buff.data());

							//std::cout << "a2 " <<a << " "<<p.mAes.getKey()  <<" _ "<< *(u64*)buff.data() << std::endl;

							oc::SHA1 sha(sizeof(block));
							sha.Update(buff.data(), buff.size());
							sha.Final((oc::block&)data[i]);


							//auto iter2 = map2.find(data[i][0]);
							//if (iter2 != map2.end())
							//{
							//	std::cout << " ++++ " << i << std::endl;

							//}
							//map2.insert({ data[i][0], i });
						}

						cuckoo_.get_locations(data[i].data(), hash_locations);
						for (int j = 0; j < hash_locations.size(); j++)
						{
							auto cuckoo_loc = hash_locations[j];
							// claim a location in this bin that is empty

							//oc::block b = prng.get<oc::block>();
							//PRNG p0(b);
							//PRNG p0(b, 8);

							auto position = aquire_bin_location(cuckoo_loc, prng, false, data[i]);
							//auto position2 = aquire_bin_location(cuckoo_loc, p1, true, data[i]);

							//if (position != position2)
							//{ 
							//	std::cout << i << " " << j << std::endl;
							//	std::cout << position << " " << position2 << std::endl;

							//	throw std::runtime_error(LOCATION);
							//}
							simple_hashing_db2_(position, cuckoo_loc) = data[i];
							simple_hashing_db2_(position, cuckoo_loc).to_itemL(cuckoo_, j);
						}
					}
#ifdef ADD_DATA_MULTI_THREAD
				});
			}

			for (auto& t : thrds) t.join();
#endif
		}

		int SenderDB::aquire_bin_location(int cuckoo_loc, oc::PRNG & prng, bool par, const Item& i)
		{
			auto s = params_.sender_bin_size();
			auto start = cuckoo_loc   * s;
			auto end = (cuckoo_loc+1) * s;
			if (cuckoo_loc >= params_.table_size())
				throw std::runtime_error(LOCATION);


			for (int i = 0; i < 100; ++i)
			{
				auto idx = prng.get<oc::u32>() % s;

				//std::cout << idx;
				//if (par)
				//{
					bool exp = false;
					if (simple_hashing_db_has_item_[start + idx].compare_exchange_strong(exp, true))
					{
						//std::cout << " *" << std::endl << std::endl;
						return idx;
					}
				//}
				//else
				//{
				//	if (simple_hashing_db_has_item_2[start + idx] == false)
				//	{
				//		simple_hashing_db_has_item_2[start + idx] = true;
				//		++bin_size_[cuckoo_loc];
				//		//std::cout << " *" << std::endl << std::endl;
				//		return idx;
				//	}
				//}
				//std::cout << std::endl;

			}
			//std::cout << "------------------------- "<< cuckoo_loc  << " " << (oc::block&)i << std::endl;


			// do linear scan
			for (int idx = 0; idx< s; ++idx)
			{
				//if (par)
				//{
					bool exp = false;
					if (simple_hashing_db_has_item_[start + idx].compare_exchange_strong(exp, true))
						return idx;
				//}
				//else
				//{
				//	if (simple_hashing_db_has_item_2[start + idx] == false)
				//	{
				//		simple_hashing_db_has_item_2[start + idx] = true;
				//		++bin_size_[cuckoo_loc];
				//		return idx;
				//	}
				//}
			}


			//std::cout << bin_size_[cuckoo_loc] << " vs " << params_.sender_bin_size() << std::endl;;
			throw std::runtime_error("sender's bin is full. " LOCATION);
		}

		bool SenderDB::has_item(int cuckoo_loc, int position)
		{
			auto s = params_.sender_bin_size();
			auto start = cuckoo_loc   * s;
#ifdef ADD_DATA_MULTI_THREAD
			return simple_hashing_db_has_item_[start + position].load(std::memory_order_relaxed);
#else
			return simple_hashing_db_has_item_[start + position];
#endif
		}


		void SenderDB::add_data(const Item &item)
		{
			add_data(vector<Item>(1, item));
		}

		void SenderDB::delete_data(const std::vector<Item> &data)
		{
			throw std::runtime_error("Update function");

			//vector<uint64_t> hash_locations;
			//for (int i = 0; i < data.size(); i++)
			//{
			//	cuckoo_.get_locations(data[i].data(), hash_locations);
			//	for (int j = 0; j < hash_locations.size(); j++)
			//	{
			//		Item target_itemL = data[i].itemL(cuckoo_, j);
			//		for (int k = 0; k < next_shuffle_locs_[hash_locations[j]]; k++)
			//		{
			//			int index = shuffle_index_[hash_locations[j]][k];
			//			if (simple_hashing_db2_(index, hash_locations[j]) == target_itemL) /* Item is found. Delete it. */
			//			{
			//				simple_hashing_db2_(index, hash_locations[j]) = sender_null_item_;

			//				/* Set the block that contains this item to be stale. */
			//				//symm_polys_stale_[index / params_.split_size()][hash_locations[j] / params_.batch_size()] = true;
			//			}
			//		}
			//	}
			//}
		}

		void SenderDB::delete_data(const Item &item)
		{
			delete_data(vector<Item>(1, item));
		}

//		void SenderDB::shuffle()
//		{
//			std::random_device dev;
//			std::array<int, 4> ss{ dev(), dev(), dev(), dev() };
//			oc::PRNG prng(*(oc::block*)ss.data());
//
//			std::vector<std::thread> thrds(params_.sender_total_thread_count());
//			for (int t = 0; t < thrds.size(); ++t)
//			{
//				auto seed = prng.get<oc::block>();
//				thrds[t] = std::thread([&, t, seed]()
//				{
//					auto start = t * params_.table_size() / thrds.size();
//					auto end = (t + 1) * params_.table_size() / thrds.size();
//#ifdef APSI_SECURE_SHUFFLE
//					oc::PRNG prng(seed, 256);
//					for (int i = start; i < end; i++)
//						std::shuffle(shuffle_index_[i].begin(), shuffle_index_[i].end(), prng);
//#else
//					for (int i = start; i < end; i++)
//						std::random_shuffle(shuffle_index_[i].begin(), shuffle_index_[i].end());
//#endif
//				});
//			}
//
//			for (auto& thrd : thrds)
//				thrd.join();
//
//			next_shuffle_locs_.assign(params_.table_size(), 0);
//		}

		void SenderDB::symmetric_polys(int split, int batch, SenderThreadContext &context, oc::MatrixView<seal::util::ExFieldElement>symm_block)
		{
			int table_size = params_.table_size(), split_size = params_.split_size(), batch_size = params_.batch_size(), split_start = split * split_size,
				batch_start = batch * batch_size;
			shared_ptr<ExField> exfield = context.exfield();

			auto num_rows = symm_block.bounds()[0];
			auto num_cols = symm_block.bounds()[1];

			ExFieldElement one(exfield, "1");
			ExFieldElement temp11(exfield), temp2(exfield), *temp1;

			auto numSlots = params_.sender_bin_size();

			for (int i = 0; i < num_rows; i++)
			{
				symm_block(i, split_size) = one;
				for (int j = split_size - 1; j >= 0; j--)
				{
					auto position = split_start + j;
					auto cuckoo_loc = batch_start + i;

					if (has_item(cuckoo_loc, position) == false)
					{
						temp1 = &neg_null_element_;
					}
					else
					{
						simple_hashing_db2_(position , cuckoo_loc).to_exfield_element(temp11);
						temp1 = &temp11;
						exfield->negate(*temp1, *temp1);
					}
					
						exfield->multiply(
							symm_block(i, j + 1),
							*temp1,
							symm_block(i, j));

						for (int k = j + 1; k < split_size; k++)
						{
							exfield->multiply(
								symm_block(i, k + 1),
								*temp1,
								temp2);
							symm_block(i, k) += temp2;
						}
				}
			}
		}

		void SenderDB::randomized_symmetric_polys(int split, int batch, SenderThreadContext &context, oc::MatrixView<seal::util::ExFieldElement> symm_block)
		{
			int split_size = params_.split_size();
			symmetric_polys(split, batch, context, symm_block);
			auto num_rows = symm_block.bounds()[0];

			for (int i = 0; i < num_rows; i++)
			{
				ExFieldElement r = context.exfield()->random_element();
				for (int j = 0; j < split_size + 1; j++)
					context.exfield()->multiply(symm_block(i, j), r, symm_block(i, j));
			}
		}

		void SenderDB::batched_randomized_symmetric_polys(SenderThreadContext &context)
		{
			if (dummy_init_)
			{
				return;
			}


			shared_ptr<ExField>& exfield = context.exfield();
			auto symm_block = context.symm_block();

			//oc::MatrixView<ExFieldElement> ()

			Pointer batch_backing;
			vector<ExFieldElement>& batch_vector = context.batch_vector();
			vector<uint64_t>& integer_batch_vector = context.integer_batch_vector();

			int table_size = params_.table_size(),
				split_size = params_.split_size(),
				batch_size = params_.batch_size(),
				split_size_plus_one = params_.split_size() + 1;

			auto indexer = [
				splitStep = params_.number_of_batches() * split_size_plus_one,
					batchStep = split_size_plus_one](int splitIdx, int batchIdx, int i)
				{
					return splitIdx * splitStep + batchIdx * batchStep + i;
				};

				int total_blocks = params_.number_of_splits() * params_.number_of_batches();
				int start_block = context.id() * total_blocks / params_.sender_total_thread_count();
				int end_block = (context.id() + 1) * total_blocks / params_.sender_total_thread_count();

				for (int next_block = start_block; next_block < end_block; next_block++)
				{
					int split = next_block / params_.number_of_batches(), batch = next_block % params_.number_of_batches();

					//if (!symm_polys_stale_[split][batch])
					//	continue;

					int split_start = split * split_size,
						batch_start = batch * batch_size,
						batch_end = (batch_start + batch_size < table_size ? (batch_start + batch_size) : table_size);

					randomized_symmetric_polys(split, batch, context, symm_block);

					Plaintext temp_plain;
					auto idx = indexer(split, batch, 0);
					for (int i = 0; i < split_size + 1; i++, idx++)
					{
						if (context.builder())
						{
							for (int k = 0; batch_start + k < batch_end; k++)
								integer_batch_vector[k] = *symm_block(k, i).pointer(0);
							context.builder()->compose(integer_batch_vector, temp_plain);
						}
						else // This branch works even if ex_field_ is an integer field, but it is slower than normal batching.
						{
							for (int k = 0; batch_start + k < batch_end; k++)
								batch_vector[k] = symm_block(k, i);
							context.exbuilder()->compose(batch_vector, temp_plain);
						}


						context.evaluator()->transform_to_ntt(temp_plain, batch_random_symm_polys_[idx]);
						//temp_plain.resize()
					}

					//symm_polys_stale_[split][batch] = false;
				}

				//if (!symm_polys_stale_[split][batch])
				//    return batch_random_symm_polys_[split][batch];

				//int table_size = params_.table_size(), split_size = params_.split_size(), split_start = split * split_size, batch_size = params_.batch_size(),
				//    batch_start = batch * batch_size, batch_end = (batch_start + batch_size < table_size ? (batch_start + batch_size) : table_size);

				//randomized_symmetric_polys(split, batch, context, symm_block);

				//Pointer batch_backing;
				//vector<ExFieldElement> batch_vector = context.exfield()->allocate_elements(batch_size, batch_backing);
				//vector<uint64_t> integer_batch_vector(batch_size, 0);

				//for (int i = 0; i < split_size + 1; i++)
				//{
				//    Plaintext temp_plain;
				//    if (context.builder())
				//    {
				//        for (int k = 0; batch_start + k < batch_end; k++)
				//            integer_batch_vector[k] = *symm_block[k][i].pointer(0);
				//        temp_plain = context.builder()->compose(integer_batch_vector);
				//    }
				//    else // This branch works even if ex_field_ is an integer field, but it is slower than normal batching.
				//    {
				//        for (int k = 0; batch_start + k < batch_end; k++)
				//            batch_vector[k] = symm_block[k][i];
				//        temp_plain = context.exbuilder()->compose(batch_vector);
				//    }

				//    context.evaluator()->transform_to_ntt(temp_plain);
				//    batch_random_symm_polys_[split][batch][i] = temp_plain;
				//}

				//symm_polys_stale_[split][batch] = false;
		}

		void SenderDB::save(std::ostream &stream) const
		{
			/** Save the following data.
			B x m
			std::vector<std::vector<Item>> simple_hashing_db_;

			m x B
			std::vector<std::vector<int>> shuffle_index_;

			size m vector
			std::vector<int> next_shuffle_locs_;

			#splits x #batches x (split_size + 1).
			std::vector<std::vector<std::vector<seal::Plaintext>>> batch_random_symm_polys_;

			#splits x #batches.
			std::vector<std::vector<bool>> symm_polys_stale_;
			**/

			int32_t bin_size = params_.sender_bin_size(), table_size = params_.table_size(),
				num_splits = params_.number_of_splits(), num_batches = params_.number_of_batches(),
				split_size_plus_one = params_.split_size() + 1;

			stream.write(reinterpret_cast<const char*>(&bin_size), sizeof(int32_t));
			stream.write(reinterpret_cast<const char*>(&table_size), sizeof(int32_t));
			stream.write(reinterpret_cast<const char*>(&num_splits), sizeof(int32_t));
			stream.write(reinterpret_cast<const char*>(&num_batches), sizeof(int32_t));
			stream.write(reinterpret_cast<const char*>(&split_size_plus_one), sizeof(int32_t));

			for (int i = 0; i < bin_size; i++)
				for (int j = 0; j < table_size; j++)
					simple_hashing_db2_(i, j).save(stream);

			//for (int i = 0; i < table_size; i++)
			//	for (int j = 0; j < bin_size; j++)
			//		stream.write(reinterpret_cast<const char*>(&(shuffle_index_[i][j])), sizeof(int));

			//for (int i = 0; i < table_size; i++)
			//	stream.write(reinterpret_cast<const char*>(&(next_shuffle_locs_[i])), sizeof(int));

			//for (int i = 0; i < num_splits; i++)
			//    for (int j = 0; j < num_batches; j++)
			//        for (int k = 0; k < split_size_plus_one; k++)
			//            batch_random_symm_polys_[i][j][k].save(stream);
			for (auto& p : batch_random_symm_polys_)
				p.save(stream);

			//for (int i = 0; i < num_splits; i++)
			//	for (int j = 0; j < num_batches; j++)
			//	{
			//		uint8_t c = (uint8_t)symm_polys_stale_[i][j];
			//		stream.write(reinterpret_cast<const char*>(&c), 1);
			//	}
		}

		void SenderDB::load(std::istream &stream)
		{
			int32_t bin_size = 0, table_size = 0,
				num_splits = 0, num_batches = 0,
				split_size_plus_one = 0;

			stream.read(reinterpret_cast<char*>(&bin_size), sizeof(int32_t));
			stream.read(reinterpret_cast<char*>(&table_size), sizeof(int32_t));
			stream.read(reinterpret_cast<char*>(&num_splits), sizeof(int32_t));
			stream.read(reinterpret_cast<char*>(&num_batches), sizeof(int32_t));
			stream.read(reinterpret_cast<char*>(&split_size_plus_one), sizeof(int32_t));

			if (bin_size != params_.sender_bin_size() || table_size != params_.table_size() ||
				num_splits != params_.number_of_splits() || num_batches != params_.number_of_batches()
				|| split_size_plus_one != params_.split_size() + 1)
				throw runtime_error("Unexpected params.");

			for (int i = 0; i < bin_size; i++)
				for (int j = 0; j < table_size; j++)
					simple_hashing_db2_(i, j).load(stream);

			//for (int i = 0; i < table_size; i++)
			//	for (int j = 0; j < bin_size; j++)
			//		stream.read(reinterpret_cast<char*>(&(shuffle_index_[i][j])), sizeof(int));

			//for (int i = 0; i < table_size; i++)
			//	stream.read(reinterpret_cast<char*>(&(next_shuffle_locs_[i])), sizeof(int));

			//for (int i = 0; i < num_splits; i++)
			//    for (int j = 0; j < num_batches; j++)
			//        for (int k = 0; k < split_size_plus_one; k++)
			//            batch_random_symm_polys_[i][j][k].load(stream);
			for (auto& p : batch_random_symm_polys_)
				p.load(stream);

			//for (int i = 0; i < num_splits; i++)
			//	for (int j = 0; j < num_batches; j++)
			//		stream.read(reinterpret_cast<char*>(&symm_polys_stale_[i][j]), sizeof(bool));
		}

	}
}
