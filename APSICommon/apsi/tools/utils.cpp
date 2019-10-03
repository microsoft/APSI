#include "utils.h" 

// STD
#include <random>
#include <array>
#include <vector>


using namespace std;
using namespace apsi;
using namespace apsi::tools;

Stopwatch apsi::tools::sender_stop_watch;
Stopwatch apsi::tools::recv_stop_watch;

namespace
{
    double get_bin_overflow_prob(u64 num_bins, u64 num_balls, u64 bin_size, double epsilon = 0.0001)
    {
        if (num_balls <= bin_size)
        {
            return numeric_limits<double>::max();
        }

        if (num_balls > numeric_limits<int>::max())
        {
            auto msg = ("Number of balls exceeds numeric limit of int");
            throw runtime_error(msg);
        }

        typedef long double ldouble;
        ldouble sum = 0.0;
        ldouble sec = 0.0;
        u64 i = 0;
        ldouble back = pow((1 - ldouble(1.0) / num_bins), num_balls); 

        while (i <= bin_size)
        {
            // a(i) = a(i-1) * stuff. 
            sum += back;
            back *= ldouble(num_balls - i) / (ldouble(i + 1) * ldouble(num_bins - 1)); 
            ldouble sec2 = log2(ldouble(num_bins)* (1 - sum)); 
            sec = sec2;
            i++;
        }

        return max<double>(0, (double)-sec);
    }

    u64 get_bin_size(u64 num_bins, u64 num_balls, u64 stat_sec_param)
    {
        auto B = max<u64>(1, num_balls / num_bins);
        double currentProb = get_bin_overflow_prob(num_bins, num_balls, B);
        u64 step = 1;
        bool doubling = true;

        while (currentProb < static_cast<double>(stat_sec_param) || step > 1)
        {
            if (stat_sec_param > currentProb)
            {
                if (doubling)
                {
                    step = max<u64>(1, step * 2);
                }
                else
                {
                    step = max<u64>(1, step / 2);
                }
                B += step;
            }
            else
            {
                doubling = false;
                step = max<u64>(1, step / 2);
                B -= step;
            }
            currentProb = get_bin_overflow_prob(num_bins, num_balls, B);
        }

        return B;
    }
}

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

// compute F(d,k)
apsi::u64 apsi::tools::maximal_power(const apsi::u64 degree, const apsi::u64 bound, const u64 base)
{
    // base must be positive
    if (base < 0) throw invalid_argument("base must be a positive integer");

    // if d >= k-1, use the first formula.
    if (bound <= degree + 1)
    {
        double result = pow(base, bound) - base + (degree - bound + 1) * pow(base, bound - 1) * (base - 1);
        return static_cast<u64>(result);
    }
    else
    { // when d < k -1 i.e. k > d+1. 
        return maximal_power(degree, degree + 1, base);
    }
    return apsi::u64();
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
    u64 plain_mod = context.first_context_data()->parms().plain_modulus().value();
    size_t coeff_count = context.first_context_data()->parms().poly_modulus_degree();
    seal::Plaintext random(coeff_count);
    u64* random_ptr = random.data();

    random_device rd;
    for (size_t i = 0; i < coeff_count - 1; i++)
    {
        random_ptr[i] = static_cast<u64>(rd());
        random_ptr[i] <<= 32;
        random_ptr[i] = random_ptr[i] | static_cast<u64>(rd());
        random_ptr[i] %= plain_mod;
    }
    random_ptr[coeff_count - 1] = 0;
    return random;
}

u64 apsi::tools::compute_sender_bin_size(unsigned log_table_size, u64 sender_set_size, unsigned hash_func_count, unsigned binning_sec_level, unsigned split_count)
{
    return round_up_to(
        get_bin_size(
            1ull << log_table_size,
            sender_set_size * hash_func_count,
            binning_sec_level),
        static_cast<u64>(split_count));
}
