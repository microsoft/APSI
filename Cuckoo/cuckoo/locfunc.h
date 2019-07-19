// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#pragma once

#include <cstring>
#include "cuckoo/common.h"
#include "cuckoo/aes.h"

namespace cuckoo
{
	// Implements location functions for simple hashing
	class LocFunc
	{
	public:
		LocFunc() = default; 

		LocFunc(u64 log_capacity, u64 seed) :
			modulus_(1ULL << log_capacity)
		{
			// Set the key to given seed (only 64 bit seeds used for simplicity)
			block key;
			set_block(seed, 0, &key);
			aes_enc_.set_key(key);
		}

		LocFunc(const LocFunc &copy) = default;

		virtual inline LocFunc &operator =(const LocFunc &assign)
		{
			aes_enc_ = assign.aes_enc_;
			modulus_= assign.modulus_;
			return *this;
		}

		// Returns an integer between 0 and (capacity-1)
		virtual inline u64 location(item_type item)
		{
			return compress(item) % modulus_;
		}

	protected:
		inline u64 compress(item_type item)
		{
			aes_enc_.ecb_encrypt(item, item);

			// Need to make a copy due to strict aliasing
			u64 result;
			std::memcpy(&result, &item, bytes_per_u64);
			return result;
		}

		AESEnc aes_enc_;

		u64 modulus_ = 0;
	};
}