// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>

// APSI
#include "apsi/powers.h"
#include "apsi/version.h"
#include "apsi/util/utils.h"
#include "pd_tool/clp.h"

using namespace std;
using namespace apsi;

void write_dot(const PowersDag &pd, const string &dot_file)
{
    try {
        ofstream fs(dot_file);
        fs.exceptions(ios_base::badbit | ios_base::failbit);
        fs << pd.to_dot();
    } catch (const ios_base::failure &ex) {
        cout << "Failed to write to file: " << ex.what() << '\n';
    } catch (...) {
        cout << "Unknown error writing to file" << '\n';
        throw;
    }

    cout << "DOT was written to file: " << dot_file << '\n';
}

int main(int argc, char **argv)
{
    try {
        CLP clp(
            "pd_tool is a command-line tool for computing the depths of source power "
            "configurations.",
            to_string(apsi_version));
        clp.parse_args(argc, argv);

        PowersDag pd;
        set<uint32_t> sources_set(clp.sources().begin(), clp.sources().end());
        set<uint32_t> targets_set = util::create_powers_set(clp.ps_low_degree(), clp.bound());
        pd.configure(sources_set, targets_set);
        if (pd.is_configured()) {
            cout << "Found configuration with depth " << pd.depth() << '\n';
        } else {
            cout << "Failed to configure PowersDag" << '\n';
        }
        if (pd.is_configured() && !clp.dot_file().empty()) {
            write_dot(pd, clp.dot_file());
        }

        return 0;
    } catch (const exception &ex) {
        cerr << "pd_tool terminated with an unhandled exception: " << ex.what() << '\n';
        return -1;
    } catch (...) {
        cerr << "pd_tool terminated with an unknown exception" << '\n';
        return -1;
    }
}
