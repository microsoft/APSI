// STD
#include <stdexcept>
#include <iostream>

// SEAL
#include "seal/defaultparams.h"

// APSI
#include "apsi/psiparams.h"
#include "apsi/item.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    void PSIParams::validate() const
    {
        if (sender_bin_size_ % split_count_ != 0)
        {
            throw invalid_argument("Sender bin size must be a multiple of number of splits.");
        }

        if ((item_bit_count_ + 63) / 64 != (item_bit_count_ + static_cast<int>(floor(log2(hash_func_count_))) + 1 + 1 + 63) / 64)
        {
            throw invalid_argument("Invalid for cuckoo: null bit and location index overflow to new uint64_t.");
        }

        if (item_bit_count_ > max_item_bit_count)
        {
            throw invalid_argument("Item bit count cannot exceed max.");
        }

        if (item_bit_count_ > (max_item_bit_count - 8))
        {
            // Not an error, but a warning.
            cout << endl << "Item bit count is close to its upper limit. Several bits should be reserved for appropriate Cuckoo hashing." << endl;
        }
    }
}
