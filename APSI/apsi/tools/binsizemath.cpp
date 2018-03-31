#include <limits>
#include "apsi/tools/binsizemath.h"

// Boost
#include <boost/math/special_functions/binomial.hpp>
#include <boost/multiprecision/cpp_bin_float.hpp>

using namespace std;

namespace apsi
{
    double get_bin_overflow_prob(std::uint64_t num_bins, std::uint64_t num_balls, std::uint64_t bin_size, double epsilon)
    {
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

        typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_bin_float<16> > T;
        T sum = 0.0;
        T sec = 0.0;
        T diff = 1;
        std::uint64_t i = bin_size + 1;

        while (diff > T(epsilon) && num_balls >= i)
        {
            sum += num_bins * boost::math::binomial_coefficient<T>(static_cast<int>(num_balls), static_cast<int>(i))
                * boost::multiprecision::pow(T(1.0) / num_bins, i) * boost::multiprecision::pow(1 - T(1.0) / num_bins, num_balls - i);

            T sec2 = boost::multiprecision::logb(sum);
            diff = boost::multiprecision::abs(sec - sec2);
            sec = sec2;

            i++;
        }

        return max<double>(0, (double)-sec);
    }

    std::uint64_t get_bin_size(std::uint64_t num_bins, std::uint64_t num_balls, std::uint64_t stat_sec_param)
    {
        auto B = max<std::uint64_t>(1, num_balls / num_bins);
        double currentProb = get_bin_overflow_prob(num_bins, num_balls, B);
        std::uint64_t step = 1;
        bool doubling = true;

        while (currentProb < stat_sec_param || step > 1)
        {
            if (stat_sec_param > currentProb)
            {
                if (doubling)
                {
                    step = max<std::uint64_t>(1, step * 2);
                }
                else
                {
                    step = max<std::uint64_t>(1, step / 2);
                }
                B += step;
            }
            else
            {
                doubling = false;
                step = max<std::uint64_t>(1, step / 2);
                B -= step;
            }
            currentProb = get_bin_overflow_prob(num_bins, num_balls, B);
        }

        return B;
    }

}
