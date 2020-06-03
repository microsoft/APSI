// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <string>
#include <vector>

// APSI
#include "apsi/util/stopwatch.h"


namespace apsi
{
    namespace util
    {
        /**
        Print a banner with asterisks on top and bottom
        */
        void print_example_banner(const std::string title);

        /**
        Prepare console for color output.
        */
        void prepare_console();

        /**
        Generate timing report for timespans
        */
        void generate_timespan_report(std::vector<std::string>& report, const std::vector<Stopwatch::TimespanSummary>& timespans, int max_name_length);

        /**
        Generate timing report for single events
        */
        void generate_event_report(std::vector<std::string>& report, const std::vector<Stopwatch::Timepoint>& timepoints, int max_name_length);
    } // namespace util
} // namespace apsi
