#include <stdexcept>
#include "seal/defaultparams.h"
#include "apsi/psiparams.h"
#include "apsi/item.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    //vector<SmallModulus> PSIParams::coeff_modulus()
    //{
    //    int num_coeff_mod;
    //    if (coeff_mod_bit_count_ == 120)
    //    {
    //        num_coeff_mod = 2;
    //    }
    //    else if (coeff_mod_bit_count_ == 125) {
    //        num_coeff_mod = 2;
    //    }
    //    else if (coeff_mod_bit_count_ == 189) {
    //        num_coeff_mod = 3;
    //    }
    //    else if (coeff_mod_bit_count_ == 435) {
    //        num_coeff_mod = 7;
    //    }
    //    else if (coeff_mod_bit_count_ == 226) {
    //        num_coeff_mod = 4;
    //    }
    //    else if (coeff_mod_bit_count_ == 116) {
    //        num_coeff_mod = 2;
    //    }
    //    else if (coeff_mod_bit_count_ == 60)
    //    {
    //        num_coeff_mod = 1;
    //    }
    //    else {
    //        throw runtime_error("bad coeff modulus.");
    //    }
    //    vector<SmallModulus> coeff_mod_array(num_coeff_mod);
    //    for (int i = 0; i < num_coeff_mod; i++)
    //    {
    //        coeff_mod_array[i] = small_mods_60bit(i);
    //    }
    //    return coeff_mod_array;
    //}

    void PSIParams::validate()
    {
        if (sender_bin_size_ % split_count_ != 0)
        {
            throw invalid_argument("sender bin size must be a multiple of number of splits.");
        }
        if ((item_bit_count_ + 63) / 64 != (item_bit_count_ + (int)floor(log2(hash_func_count_)) + 1 + 1 + 63) / 64)
        {
            throw invalid_argument("invalid for cuckoo: null bit and location index overflow to new uint64_t.");
        }
    }
}