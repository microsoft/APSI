// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <string>
#include <vector>

// APSI
#include "apsi/util/stopwatch.h"

/**
Print a banner with asterisks on top and bottom.
*/
void print_example_banner(const std::string &title);

/**
Prepare console for color output.
*/
void prepare_console();

/**
Generate timing report for timespans.
*/
std::vector<std::string> generate_timespan_report(
    const std::vector<apsi::util::Stopwatch::TimespanSummary> &timespans,
    int max_name_length);

/**
Generate timing report for single events.
*/
std::vector<std::string> generate_event_report(
    const std::vector<apsi::util::Stopwatch::Timepoint> &timepoints,
    int max_name_length);
