#include <stdexcept>
#include "seal/defaultparams.h"
#include "apsi/psiparams.h"
#include "apsi/item.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
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