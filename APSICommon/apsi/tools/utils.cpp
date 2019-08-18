#include "utils.h" 

// STD
#include <random>
#include <array>
#include <vector>

// Boost
//#include <boost/math/special_functions/binomial.hpp>
//#include <boost/multiprecision/cpp_bin_float.hpp>


using namespace std;
using namespace apsi;
using namespace apsi::tools;

Stopwatch apsi::tools::sender_stop_watch;
Stopwatch apsi::tools::recv_stop_watch;

namespace
{
    double get_bin_overflow_prob(u64 num_bins, u64 num_balls, u64 bin_size, double epsilon = 0.0001)
    {
		cout << "bin size = " << bin_size;
        if (num_balls <= bin_size)
        {
            return numeric_limits<double>::max();
        }
        if (num_balls > numeric_limits<int>::max())
        {
            auto msg = ("boost::math::binomial_coefficient(...) only supports "
                + to_string(sizeof(unsigned) * 8) + " bit inputs which was exceeded.");
            throw runtime_error(msg);
        }

		typedef long double T; // typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_bin_float<16> > T;
        T sum = 0.0;
        T sec = 0.0;
        T diff = 1;
        // u64 i = bin_size + 1;
		u64 i = 0;
		T back = pow((1 - T(1.0) / num_bins), num_balls); 

        while (/* diff > T(epsilon) && /*num_balls >= i */  i <= bin_size)
        {
			// a(i) = a(i-1) * stuff. 
			sum += back;
			back *= T(num_balls - i) / (T(i + 1) * T(num_bins - 1)); 
			//sum += num_bins * boost::math::binomial_coefficient<T>(static_cast<int>(num_balls), static_cast<int>(i))
            //    * boost::multiprecision::pow(T(1.0) / num_bins, i) * boost::multiprecision::pow(1 - T(1.0) / num_bins, num_balls - i);
			// cout << "i = " << i << "sum = " << sum << endl;
			T sec2 = log2(T(num_bins)* (1 - sum)); 
            //T sec2 = boost::multiprecision::logb(sum);
			// diff = abs(sec - sec2); 
			//diff = boost::multiprecision::abs(sec - sec2);
            sec = sec2;
			i++;
        }
		cout << "sec = " << sec << endl;

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
    size_t coeff_count = context.context_data()->parms().poly_modulus_degree();
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
