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
    return *(reinterpret_cast<block*>(&ret));
}

bool apsi::tools::not_equal(const block& lhs, const block& rhs)
{
    block neq = _mm_xor_si128(lhs, rhs);
    return _mm_test_all_zeros(neq, neq) == 0;
}

u64 apsi::tools::optimal_split(const u64 x, const int base)
{
    vector<u64> digits = conversion_to_digits(x, base);
    int ndigits = static_cast<int>(digits.size());
    int hammingweight = 0;
    for (int i = 0; i < ndigits; i++)
    {
        hammingweight += static_cast<int>(digits[i] != 0);
    }
    int target = hammingweight / 2;
    int now = 0;
    u64 result = 0;
    for (int i = 0; i < ndigits; i++)
    {
        if (digits[i] != 0)
        {
            now++;
            result += static_cast<u64>(pow(base, i) * digits[i]);
        }
        if (now >= target)
        {
            break;
        }
    }
    return result;
}

vector<u64> apsi::tools::conversion_to_digits(const u64 input, const int base)
{
    vector<uint64_t> result;
    u64 number = input;

    while (number > 0)
    {
        result.push_back(number % base);
        number /= base;
    }

    return result;
}

void apsi::tools::split(const std::string &s, const char delim, std::vector<std::string> &elems)
{
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim))
    {
        elems.push_back(item);
    }
}

std::vector<std::string> apsi::tools::split(const std::string &s, const char delim)
{
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
}

seal::Plaintext apsi::tools::random_plaintext(const seal::SEALContext &context)
{
    u64 plain_mod = context.context_data()->parms().plain_modulus().value();
    int coeff_count = context.context_data()->parms().poly_modulus_degree();
    seal::Plaintext random(coeff_count);
    u64* random_ptr = random.data();

    random_device rd;
    for (int i = 0; i < coeff_count - 1; i++)
    {
        random_ptr[i] = static_cast<u64>(rd());
        random_ptr[i] <<= 32;
        random_ptr[i] = random_ptr[i] | static_cast<u64>(rd());
        random_ptr[i] %= plain_mod;
    }
    random_ptr[coeff_count - 1] = 0;
    return random;
}
