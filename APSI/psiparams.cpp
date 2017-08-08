#include "psiparams.h"
#include "chooser.h"
#include <stdexcept>
#include <item.h>

using namespace seal;
using namespace std;

namespace apsi
{
	static std::map<std::string, int> upperbound_on_B
	{
		{ "(4096, 8)", 10 },
		{ "(4096, 12)", 26 },
		{ "(4096, 16)", 114 },
		{ "(4096, 20)", 1004 },
		{ "(4096, 24)", 13199 },
		{ "(4096, 28)", 200221 },

		{ "(8192, 8)", 9 },
		{ "(8192, 12)", 20 },
		{ "(8192, 16)", 74 },
		{ "(8192, 20)", 556 },
		{ "(8192, 24)", 6798 },
		{ "(8192, 28)", 100890 },

		{ "(16384, 8)", 8 },
		{ "(16384, 12)", 16 },
		{ "(16384, 16)", 51 },
		{ "(16384, 20)", 318 },
		{ "(16384, 24)", 3543 },
		{ "(16384, 28)", 51002 }
	};

	BigUInt PSIParams::coeff_modulus()
	{
		
		if (coeff_mod_bit_count_ == 120)
		{
			// 120 bits (2^120 - 2^26 + 3 * 2^15 + 1)
			return "fffffffffffffffffffffffc018001";
		}
		else if (coeff_mod_bit_count_ == 125) {
			// 125 bits (2^125 - 2^25 + 3 * 2^14 + 1)
			return "1ffffffffffffffffffffffffe00c001";
		}
		else if (coeff_mod_bit_count_ == 189) {
			// 189 bits (2^189 - 2^21 + 9 * 2^15 + 1)
			return "1fffffffffffffffffffffffffffffffffffffffffe48001";
		}
		else if (coeff_mod_bit_count_ == 435) {
			// 435 bits (2^435 - 2^33 + 1), default 16384
			return ChooserEvaluator::default_parameter_options().at(16384);
		}
		else if (coeff_mod_bit_count_ == 226) {
			// 226 bits (2^226 - 2^26 + 1), default 8192
			return ChooserEvaluator::default_parameter_options().at(8192);
		}
		else if (coeff_mod_bit_count_ == 116) {
			// 116 bits (2^116 - 2^18 + 1), default 4096
			return ChooserEvaluator::default_parameter_options().at(4096);
		}
		else if (coeff_mod_bit_count_ == 60)
		{
			return ChooserEvaluator::default_parameter_options().at(2048);
		}
		else {
			throw std::runtime_error("bad coeff modulus.");
		}
	}

	void PSIParams::validate()
	{
		if (sender_bin_size_ % number_of_splits_ != 0)
			throw invalid_argument("sender bin size must be a multiple of number of splits.");

		Item::set_item_bit_length(item_bit_length_);
		Item::set_reduced_bit_length(reduced_item_bit_length_);

		if ((item_bit_length_ + 63) / 64 != (item_bit_length_ + (int)floor(log2(hash_func_count_)) + 1 + 1 + 63) / 64)
			throw invalid_argument("invalid for cuckoo: null bit and location index overflow to new uint64_t.");
	}

}