#include <stdexcept>
#include "seal/chooser.h"
#include "seal/defaultparams.h"
#include "apsi/psiparams.h"
#include "apsi/item.h"

using namespace seal;
using namespace std;
using namespace seal::util;

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

    vector<SmallModulus> PSIParams::coeff_modulus()
    {
        int num_coeff_mod;
        if (coeff_mod_bit_count_ == 120)
        {
            num_coeff_mod = 2;
        }
        else if (coeff_mod_bit_count_ == 125) {
            num_coeff_mod = 2;
        }
        else if (coeff_mod_bit_count_ == 189) {
            num_coeff_mod = 3;
        }
        else if (coeff_mod_bit_count_ == 435) {
            num_coeff_mod = 7;
        }
        else if (coeff_mod_bit_count_ == 226) {
            num_coeff_mod = 4;
        }
        else if (coeff_mod_bit_count_ == 116) {
            num_coeff_mod = 2;
        }
        else if (coeff_mod_bit_count_ == 60)
        {
            num_coeff_mod = 1;
        }
        else {
            throw std::runtime_error("bad coeff modulus.");
        }
        vector<SmallModulus> coeff_mod_array(num_coeff_mod);
        for (int i = 0; i < num_coeff_mod; i++)
        {
            coeff_mod_array[i] = small_mods_60bit(i);
        }
        return coeff_mod_array;
    }

    void PSIParams::validate()
    {
        if (sender_bin_size_ % number_of_splits_ != 0)
            throw invalid_argument("sender bin size must be a multiple of number of splits.");


        if ((item_bit_length_ + 63) / 64 != (item_bit_length_ + (int)floor(log2(hash_func_count_)) + 1 + 1 + 63) / 64)
            throw invalid_argument("invalid for cuckoo: null bit and location index overflow to new uint64_t.");

        if (sender_session_thread_count_ > sender_total_thread_count_)
            throw invalid_argument("invalid thread count for sender.");
    }

}