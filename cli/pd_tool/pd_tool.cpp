// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <fstream>
#include <iostream>
#include <filesystem>
#include <random>

// APSI
#include "pd_tool/clp.h"
#include "apsi/powers.h"
#include "apsi/version.h"

using namespace std;
namespace fs = std::filesystem;
using namespace apsi;

void write_dot(const PowersDag &pd, string dot_file)
{
    if (fs::exists(dot_file) && !fs::is_regular_file(dot_file))
    {
        cout << "Cannot write to file." << endl;
        return;
    }

    try
    {
        ofstream fs(dot_file);
        fs.exceptions(ios_base::badbit | ios_base::failbit);
        fs << pd.to_dot();
    }
    catch (const ios_base::failure &ex)
    {
        cout << "Failed to write to file: " << ex.what() << endl;
    }
    catch (...)
    {
        cout << "Unknown error writing to file" << endl;
        throw;
    }

    cout << "DOT was written to file: " << dot_file << endl;
}

PowersDag do_seed_given(const CLP &clp)
{
    cout << "Using seed: " << clp.seed() << endl;

    cout << "Configuring PowersDag ... ";
    cout.flush();
    PowersDag pd;
    pd.configure(clp.seed(), clp.up_to_power(), clp.source_count());
    cout << "done" << endl;

    if (pd.is_configured())
    {
        cout << "Found a valid configuration; depth: " << pd.depth() << "." << endl;
    }
    else
    {
        cout << "Failed to find a valid configuration. Try a different seed." << endl;
    }

    return pd;
}

PowersDag do_depth_bound_given(const CLP &clp)
{
    cout << "Using depth bound: " << clp.depth_bound() << endl;

    cout << "Trying to find PowersDag ... ";
    cout.flush();
    random_device rd;
    PowersDag pd;
    uint32_t seed;
    uint32_t attempts = 0;
    uint32_t attempts_max = 1000000;
    uint32_t lowest_depth = clp.source_count();
    uint32_t lowest_depth_seed;
    while ((!pd.is_configured() || pd.depth() > clp.depth_bound()) && attempts < attempts_max)
    {
        seed = rd();
        pd.configure(seed, clp.up_to_power(), clp.source_count());
        if (pd.is_configured() && (pd.depth() < lowest_depth))
        {
            lowest_depth = pd.depth();
            lowest_depth_seed = seed;
        }
        attempts++;
    }
    cout << "done (" << attempts << " attempts)" << endl;

    if (pd.is_configured() && pd.depth() <= clp.depth_bound())
    {
        cout << "Found a valid configuration; depth: " << pd.depth() << endl;
        cout << "PowersDag seed: " << seed << endl;
    }
    else if (pd.is_configured() && pd.depth() > clp.depth_bound())
    {
        cout << "Failed to find a valid configuration; lowest depth found: " << lowest_depth << endl;
        cout << "PowersDag seed: " << lowest_depth_seed << endl;
    }
    else
    {
        cout << "Failed to find a valid configuration. Try increasing the depth bound." << endl;
    }

    return pd;
}

int main(int argc, char **argv)
{
    CLP clp("pd_tool is a simple command-line tool for discovering and printing "
            "PowersDag configurations for APSI.", to_string(apsi_version));
    clp.parse_args(argc, argv);

    if (clp.source_count() > clp.up_to_power())
    {
        cout << "source-count (" << clp.source_count()
            << ") cannot be larger than up-to-power (" << clp.up_to_power() << ")" << endl;

        return 0;
    }

    PowersDag pd;
    if (clp.seed_given())
    {
        pd = do_seed_given(clp);
    }
    else
    {
        pd = do_depth_bound_given(clp);
    }

    if (pd.is_configured() && !clp.dot_file().empty())
    {
        write_dot(pd, clp.dot_file());
    }

    return 0;
}