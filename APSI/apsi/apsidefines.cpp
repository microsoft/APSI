#include "apsidefines.h"
#include "seal/context.h"
#include <sstream>
#include <random>
#include <wmmintrin.h>

using namespace std;

namespace apsi
{
    apsi::tools::Stopwatch stop_watch, recv_stop_watch;

    const block ZeroBlock   = _mm_set_epi64x(0, 0);
    const block OneBlock    = _mm_set_epi64x(0, 1);
    const block AllOneBlock = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
    const block CCBlock     = _mm_set_epi64x(0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC);

    uint64_t optimal_split(uint64_t x, int base)
    {
        vector<uint64_t> digits = conversion_to_digits(x, base);
        int ndigits = digits.size();
        int hammingweight = 0;
        for (int i = 0; i < ndigits; i++)
        {
            hammingweight += static_cast<int>(digits[i] != 0);
        }
        int target = hammingweight / 2;
        int now = 0;
        uint64_t result = 0;
        for (int i = 0; i < ndigits; i++)
        {
            if (digits[i] != 0)
            {
                now++;
                result += pow(base, i)*digits[i];
            }
            if (now >= target)
            {
                break;
            }
        }
        return result;
    }

    vector<uint64_t> conversion_to_digits(uint64_t input, int base)
    {
        vector<uint64_t> result;
        while (input > 0)
        {
            result.push_back(input % base);
            input /= base;
        }
        return result;
    }

    void split(const std::string &s, char delim, std::vector<std::string> &elems) {
        std::stringstream ss(s);
        std::string item;
        while (std::getline(ss, item, delim)) {
            elems.push_back(item);
        }
    }

    std::vector<std::string> split(const std::string &s, char delim) {
        std::vector<std::string> elems;
        split(s, delim, elems);
        return elems;
    }

    seal::Plaintext random_plaintext(const seal::SEALContext &context)
    {
        std::uint64_t plain_mod = context.context_data()->parms().plain_modulus().value();
        int coeff_count = context.context_data()->parms().poly_modulus_degree();
        seal::Plaintext random(coeff_count);
        uint64_t* random_ptr = random.data();

        random_device rd;
        for (int i = 0; i < coeff_count - 1; i++)
        {
            random_ptr[i] = static_cast<std::uint64_t>(rd());
            random_ptr[i] <<= 32;
            random_ptr[i] = random_ptr[i] | static_cast<std::uint64_t>(rd());
            random_ptr[i] %= plain_mod;
        }
        random_ptr[coeff_count - 1] = 0;
        return random;
    }
}
