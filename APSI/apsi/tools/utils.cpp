#include "utils.h" 

#include <random>
#include <array>
#include <vector>

using namespace std;
using namespace apsi;
using namespace apsi::tools;

Stopwatch apsi::tools::stop_watch;
Stopwatch apsi::tools::recv_stop_watch;

block apsi::tools::sys_random_seed()
{
    std::random_device rd;
    auto ret = std::array<unsigned int, 4> { rd(), rd(), rd(), rd() };
    return *(block*)&ret;
}

bool apsi::tools::not_equal(const block& lhs, const block& rhs)
{
    block neq = _mm_xor_si128(lhs, rhs);
    return _mm_test_all_zeros(neq, neq) == 0;
}

uint64_t apsi::tools::optimal_split(uint64_t x, int base)
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

vector<uint64_t> apsi::tools::conversion_to_digits(uint64_t input, int base)
{
    vector<uint64_t> result;
    while (input > 0)
    {
        result.push_back(input % base);
        input /= base;
    }
    return result;
}

void apsi::tools::split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
}

std::vector<std::string> apsi::tools::split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
}

seal::Plaintext apsi::tools::random_plaintext(const seal::SEALContext &context)
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
