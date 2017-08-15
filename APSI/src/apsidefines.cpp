#include "apsidefines.h"
#include <sstream>

using namespace std;

namespace apsi
{
    apsi::tools::Stopwatch stop_watch;

    void right_shift_uint(const u64 *source, u64 *destination, u64 shift_amount, u64 u64_count)
    {
        if (source == destination && shift_amount == 0)
        {
            // Fast path to handle inplace no shifting.
            return;
        }

        u64 uint64_shift_amount = shift_amount / 64;
        u64 bit_shift_amount = shift_amount - uint64_shift_amount * 64;
        u64 neg_bit_shift_amount = (64 - bit_shift_amount) & (static_cast<uint64_t>(bit_shift_amount == 0) - 1);

        for (u64 i = 0; i < u64_count - uint64_shift_amount - 1; i++)
        {
            *destination = *(source + uint64_shift_amount);

            *destination >>= bit_shift_amount;
            *destination++ |= (*(++source + uint64_shift_amount) << neg_bit_shift_amount) & static_cast<uint64_t>(-(neg_bit_shift_amount != 0));
        }
        if (uint64_shift_amount < u64_count)
        {
            *destination = *(source + uint64_shift_amount);
            *destination++ >>= bit_shift_amount;
        }
        for (u64 i = u64_count - uint64_shift_amount; i < u64_count; i++)
        {
            *destination++ = 0;
        }
    }

    void left_shift_uint(const u64 *source, u64 *destination, u64 shift_amount, u64 u64_count)
    {
        if (source == destination && shift_amount == 0)
        {
            // Fast path to handle inplace no shifting.
            return;
        }

        u64 uint64_shift_amount = shift_amount / 64;
        u64 bit_shift_amount = shift_amount - uint64_shift_amount * 64;
        u64 neg_bit_shift_amount = (64 - bit_shift_amount) & (static_cast<uint64_t>(bit_shift_amount == 0) - 1);

        destination += (u64_count - 1);
        source += (u64_count - 1);

        for (u64 i = 0; i < u64_count - uint64_shift_amount - 1; ++i)
        {
            *destination = *(source - uint64_shift_amount);
            *destination <<= bit_shift_amount;
            *destination-- |= (*(--source - uint64_shift_amount) >> neg_bit_shift_amount) & static_cast<uint64_t>(-(neg_bit_shift_amount != 0));
        }
        if (uint64_shift_amount < u64_count)
        {
            *destination = *(source - uint64_shift_amount);
            *destination-- <<= bit_shift_amount;
        }
        for (u64 i = u64_count - uint64_shift_amount; i < u64_count; ++i)
        {
            *destination-- = 0;
        }
    }

    uint64_t optimal_split(uint64_t x, int base)
    {
        vector<uint64_t> digits = conversion_to_digits(x, base);
        int ndigits = digits.size();
        int hammingweight = 0;
        for (int i = 0; i < ndigits; i++)
        {
            if (digits[i] != 0) {
                hammingweight++;
            }
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
            if (now >= target) { break; }
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
}