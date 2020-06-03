// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "apsi/util/utils.h"
#include <array>
#include <numeric>
#include <vector>

using namespace std;

namespace apsi
{
    namespace util
    {
        Stopwatch sender_stop_watch;
        Stopwatch recv_stop_watch;

        namespace
        {
            double get_bin_overflow_prob(size_t num_bins, size_t num_balls, size_t bin_size, double epsilon = 0.0001)
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
                uint64_t i = 0;
                ldouble back = pow((1 - static_cast<ldouble>(1.0) / num_bins), num_balls);

                while (i <= bin_size)
                {
                    // a(i) = a(i-1) * stuff.
                    sum += back;
                    back *= static_cast<ldouble>(num_balls - i) /
                            (static_cast<ldouble>(i + 1) * static_cast<ldouble>(num_bins - 1));
                    ldouble sec2 = log2(static_cast<ldouble>(num_bins) * (1 - sum));
                    sec = sec2;
                    i++;
                }

                return max<double>(0, static_cast<double>(-sec));
            }

            size_t get_bin_size(size_t num_bins, size_t num_balls, uint32_t stat_sec_param)
            {
                size_t B = max<size_t>(size_t(1), num_balls / num_bins);
                double currentProb = get_bin_overflow_prob(num_bins, num_balls, B);
                uint64_t step = 1;
                bool doubling = true;

                while (currentProb < static_cast<double>(stat_sec_param) || step > 1)
                {
                    if (static_cast<double>(stat_sec_param) > currentProb)
                    {
                        if (doubling)
                        {
                            step = max<uint64_t>(1, step * 2);
                        }
                        else
                        {
                            step = max<uint64_t>(1, step / 2);
                        }
                        B += step;
                    }
                    else
                    {
                        doubling = false;
                        step = max<uint64_t>(1, step / 2);
                        B -= step;
                    }
                    currentProb = get_bin_overflow_prob(num_bins, num_balls, B);
                }

                return B;
            }
        } // namespace

        uint64_t optimal_split(const uint64_t x, const uint64_t base)
        {
            vector<uint64_t> digits = conversion_to_digits(x, base);
            size_t ndigits = digits.size();
            int hammingweight = 0;
            for (size_t i = 0; i < ndigits; i++)
            {
                hammingweight += static_cast<int>(digits[i] != uint64_t(0));
            }
            int target = hammingweight / 2;
            int now = 0;
            uint64_t result = 0;
            for (size_t i = 0; i < ndigits; i++)
            {
                if (digits[i] != uint64_t(0))
                {
                    now++;
                    result += static_cast<uint64_t>(pow(base, i) * digits[i]);
                }
                if (now >= target)
                {
                    break;
                }
            }
            return result;
        }

        // compute F(d,k)
        uint64_t maximal_power(const uint64_t degree, const uint64_t bound, const uint64_t base)
        {
            // base must be positive
            if (base < 0)
                throw invalid_argument("base must be a positive integer");

            // if d >= k-1, use the first formula.
            if (bound <= degree + 1)
            {
                double result = pow(base, bound) - base + (degree - bound + 1) * pow(base, bound - 1) * (base - 1);
                return static_cast<uint64_t>(result);
            }
            else
            { // when d < k -1 i.e. k > d+1.
                return maximal_power(degree, degree + 1, base);
            }
            return uint64_t();
        }

        vector<uint64_t> conversion_to_digits(const uint64_t input, const uint64_t base)
        {
            vector<uint64_t> result;
            uint64_t number = input;

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

        uint64_t compute_sender_bin_size(
            uint32_t log_table_size, size_t sender_set_size, size_t hash_func_count, uint32_t binning_sec_level,
            size_t split_count)
        {
            return round_up_to(
                get_bin_size(1ull << log_table_size, sender_set_size * hash_func_count, binning_sec_level),
                static_cast<uint64_t>(split_count));
        }
    } // namespace util
} // namespace apsi
