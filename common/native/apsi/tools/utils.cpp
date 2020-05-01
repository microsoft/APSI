// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <array>
#include <vector>
#include <numeric>
#include "apsi/tools/utils.h"

using namespace std;

namespace apsi
{
    namespace tools
    {
        Stopwatch sender_stop_watch;
        Stopwatch recv_stop_watch;

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

                using ldouble = long double;
                ldouble sum = 0.0;
                ldouble sec = 0.0;
                u64 i = 0;
                ldouble back = pow((1 - static_cast<ldouble>(1.0) / num_bins), num_balls); 

                while (i <= bin_size)
                {
                    // a(i) = a(i-1) * stuff. 
                    sum += back;
                    back *= static_cast<ldouble>(num_balls - i) / (static_cast<ldouble>(i + 1) * static_cast<ldouble>(num_bins - 1));
                    ldouble sec2 = log2(static_cast<ldouble>(num_bins)* (1 - sum)); 
                    sec = sec2;
                    i++;
                }

                return max<double>(0, static_cast<double>(-sec));
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

        u64 optimal_split(const u64 x, const int base)
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
        u64 maximal_power(const u64 degree, const u64 bound, const u64 base)
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
            return u64();
        }

        vector<u64> conversion_to_digits(const u64 input, const int base)
        {
            vector<u64> result;
            u64 number = input;

            while (number > 0)
            {
                result.push_back(number % base);
                number /= base;
            }

            return result;
        }

        void split(const string &s, const char delim, vector<string> &elems)
        {
            stringstream ss(s);
            string item;
            while (getline(ss, item, delim))
            {
                elems.push_back(item);
            }
        }

        vector<string> split(const string &s, const char delim)
        {
            vector<string> elems;
            split(s, delim, elems);
            return elems;
        }

        u64 compute_sender_bin_size(
            u32 log_table_size, u64 sender_set_size,
            u32 hash_func_count, u32 binning_sec_level, u32 split_count)
        {
            return round_up_to(
                get_bin_size(
                    1ull << log_table_size,
                    sender_set_size * hash_func_count,
                    binning_sec_level),
                static_cast<u64>(split_count));
        }
    } // namespace tools
} // namespace apsi
