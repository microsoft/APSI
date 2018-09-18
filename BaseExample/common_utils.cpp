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


using namespace std;
using namespace apsi;
using namespace apsi::tools;
using namespace seal;


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
    u64 sender_set_size = 1ull << cmd.sender_size();

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

        // Negative log failure probability for simple hashing
        table_params.binning_sec_level = cmd.sec_level();

        // Window size parameter
        // Larger means lower depth but bigger R-->S communication
        table_params.window_size = cmd.window_size();

        // Get secure bin size
        table_params.sender_bin_size = static_cast<int>(compute_sender_bin_size(
            table_params.log_table_size,
            sender_set_size,
            cuckoo_params.hash_func_count,
            table_params.binning_sec_level,
            table_params.split_count));
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

void apsi::tools::generate_timespan_report(vector<string>& report, const vector<Stopwatch::TimespanSummary>& timespans, int max_name_length)
{
    report.clear();

    int name_col_width = max_name_length + 3;

    for (const auto& timespan : timespans)
    {
        stringstream ss;
        ss << setw(max_name_length) << left << timespan.event_name << ": " << setw(5) << right << timespan.event_count << " instances. ";
        if (timespan.event_count == 1)
        {
            ss << "Duration: " << setw(6) << right << timespan.sum << "ms";
        }
        else
        {
            ss << "Average:  " << setw(6) << right << static_cast<int>(timespan.avg) << "ms Minimum: " << setw(6) << right << timespan.min << "ms Maximum: " << setw(6) << right << timespan.max << "ms";
        }

        report.push_back(ss.str());
    }
}

void apsi::tools::generate_event_report(vector<string>& report, const vector<Stopwatch::Timepoint>& timepoints, int max_name_length)
{
    report.clear();

    Stopwatch::time_unit last = Stopwatch::start_time;
    int name_col_width = max_name_length + 3;

    for (const auto& timepoint : timepoints)
    {
        stringstream ss;

        i64 since_start = chrono::duration_cast<chrono::milliseconds>(timepoint.time_point - Stopwatch::start_time).count();
        i64 since_last = chrono::duration_cast<chrono::milliseconds>(timepoint.time_point - last).count();

        ss << setw(max_name_length) << left << timepoint.event_name << ": " << setw(6) << right << since_start << "ms since start, " << setw(6) << right << since_last << "ms since last single event.";
        last = timepoint.time_point;
        report.push_back(ss.str());
    }
}
