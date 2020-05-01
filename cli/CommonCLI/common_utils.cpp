// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "common_utils.h"

// STD
#include <iostream>
#include <unordered_map>

#ifdef _MSC_VER
#include "windows.h"
#endif

// APSI
#include "base_clp.h"
#include "apsi/psiparams.h"
#include "apsi/tools/utils.h"


using namespace std;
using namespace seal;

namespace apsi
{
    namespace tools
    {
        void print_example_banner(string title)
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
        void prepare_console()
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

        void generate_timespan_report(vector<string>& report, const vector<Stopwatch::TimespanSummary>& timespans, int max_name_length)
        {
            report.clear();

            int name_col_width = max_name_length + 3;

            for (const auto& timespan : timespans)
            {
                stringstream ss;
                ss << setw(max_name_length) << left << timespan.event_name << ": " << setw(5) << right << timespan.event_count << " instances. ";
                if (timespan.event_count == 1)
                {
                    ss << "Duration: " << setw(6) << right << static_cast<int>(timespan.avg) << "ms";
                }
                else
                {
                    ss << "Average:  " << setw(6) << right << static_cast<int>(timespan.avg) << "ms Minimum: " << setw(6) << right << timespan.min << "ms Maximum: " << setw(6) << right << timespan.max << "ms";
                }

                report.push_back(ss.str());
            }
        }

        void generate_event_report(vector<string>& report, const vector<Stopwatch::Timepoint>& timepoints, int max_name_length)
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
    } // namespace tools
} // namespace apsi
