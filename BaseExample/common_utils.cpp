#include "common_utils.h"

// STD
#include <iostream>
#include <unordered_map>

#ifdef _MSC_VER
#include "windows.h"
#endif

// APSI
#include "base_clp.h"
#include "apsi/apsidefines.h"
#include "apsi/psiparams.h"
#include "apsi/tools/utils.h"

// SEAL
#include "seal/smallmodulus.h"
#include "seal/defaultparams.h"

// Boost
#include <boost/math/special_functions/binomial.hpp>
#include <boost/multiprecision/cpp_bin_float.hpp>


using namespace std;
using namespace apsi;
using namespace seal;

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
            auto msg = ("boost::math::binomial_coefficient(...) only supports "
                + to_string(sizeof(unsigned) * 8) + " bit inputs which was exceeded.");
            throw runtime_error(msg);
        }

        typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_bin_float<16> > T;
        T sum = 0.0;
        T sec = 0.0;
        T diff = 1;
        u64 i = bin_size + 1;

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

    u64 get_bin_size(u64 num_bins, u64 num_balls, u64 stat_sec_param)
    {
        auto B = max<u64>(1, num_balls / num_bins);
        double currentProb = get_bin_overflow_prob(num_bins, num_balls, B);
        u64 step = 1;
        bool doubling = true;

        while (currentProb < stat_sec_param || step > 1)
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

void apsi::tools::print_example_banner(string title)
{
    if (!title.empty())
    {
        size_t title_length = title.length();
        size_t banner_length = title_length + 2 + 2 * 10;
        string banner_top(banner_length, '*');
        string banner_middle = string(10, '*') + " " + title + " " + string(10, '*');

        cout << endl
            << banner_top << endl
            << banner_middle << endl
            << banner_top << endl
            << endl;
    }
}

/**
 * This only turns on showing colors for Windows.
 */
void apsi::tools::prepare_console()
{
#ifndef _MSC_VER
    return; // Nothing to do on Linux.
#else

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE)
        return;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hConsole, &dwMode))
        return;

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hConsole, dwMode);

#endif
}

const apsi::PSIParams apsi::tools::build_psi_params(const BaseCLP& cmd)
{
    // Larger set size 
    unsigned sender_set_size = 1 << cmd.sender_size();

    // Negative log failure probability for simple hashing
    unsigned binning_sec_level = cmd.sec_level();

    // Length of items
    unsigned item_bit_length = cmd.item_bit_length();

    bool useLabels = cmd.use_labels();
    unsigned label_bit_length = useLabels ? item_bit_length : 0;

    // Cuckoo hash parameters
    CuckooParams cuckoo_params;
    {
        // Cuckoo hash function count
        cuckoo_params.hash_func_count = 3;

        // Set the hash function seed
        cuckoo_params.hash_func_seed = 0;

        // Set max_probe count for Cuckoo hashing
        cuckoo_params.max_probe = 100;
    }

    // Create TableParams and populate.
    TableParams table_params;
    {
        // Log of size of full hash table
        table_params.log_table_size = cmd.log_table_size();

        // Number of splits to use
        // Larger means lower depth but bigger S-->R communication
        table_params.split_count = cmd.split_count();

        // Get secure bin size
        table_params.sender_bin_size = round_up_to(
            static_cast<unsigned>(get_bin_size(
                1ull << table_params.log_table_size,
                sender_set_size * cuckoo_params.hash_func_count,
                binning_sec_level)),
            table_params.split_count);

        // Window size parameter
        // Larger means lower depth but bigger R-->S communication
        table_params.window_size = cmd.window_size();
    }

    SEALParams seal_params;
    {
        seal_params.encryption_params.set_poly_modulus_degree(cmd.poly_modulus());

        vector<SmallModulus> coeff_modulus;
        auto coeff_mod_bit_vector = cmd.coeff_modulus();

        if (coeff_mod_bit_vector.size() == 0)
        {
            coeff_modulus = coeff_modulus_128(seal_params.encryption_params.poly_modulus_degree());
        }
        else
        {
            unordered_map<u64, size_t> mods_added;
            for (auto bit_size : coeff_mod_bit_vector)
            {
                switch (bit_size)
                {
                case 30:
                    coeff_modulus.emplace_back(small_mods_30bit(static_cast<int>(mods_added[bit_size])));
                    mods_added[bit_size]++;
                    break;

                case 40:
                    coeff_modulus.emplace_back(small_mods_40bit(static_cast<int>(mods_added[bit_size])));
                    mods_added[bit_size]++;
                    break;

                case 50:
                    coeff_modulus.emplace_back(small_mods_50bit(static_cast<int>(mods_added[bit_size])));
                    mods_added[bit_size]++;
                    break;

                case 60:
                    coeff_modulus.emplace_back(small_mods_60bit(static_cast<int>(mods_added[bit_size])));
                    mods_added[bit_size]++;
                    break;

                default:
                    throw invalid_argument("invalid coeff modulus bit count");
                }
            }
        }
        seal_params.encryption_params.set_coeff_modulus(coeff_modulus);
        seal_params.encryption_params.set_plain_modulus(cmd.plain_modulus());

        // This must be equal to plain_modulus
        seal_params.exfield_params.exfield_characteristic = seal_params.encryption_params.plain_modulus().value();
        seal_params.exfield_params.exfield_degree = cmd.exfield_degree();
        seal_params.decomposition_bit_count = cmd.dbc();
    }

    // Use OPRF to eliminate need for noise flooding for sender's security
    auto use_OPRF = cmd.oprf();

    /*
    Creating the PSIParams class.
    */
    PSIParams params(item_bit_length, use_OPRF, table_params, cuckoo_params, seal_params);
    params.set_value_bit_count(label_bit_length);
    params.validate();

    return params;
}
