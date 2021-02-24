// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <iostream>
#include <fstream>
#include <string>
#include <csignal>
#include <functional>

// APSI
#include "apsi/logging/log.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/version.h"
#include "apsi/zmq/sender_dispatcher.h"
#include "common/common_utils.h"
#include "common/csv_reader.h"
#include "sender/sender_utils.h"
#include "sender/clp.h"

using namespace std;
namespace fs = std::filesystem;
using namespace apsi;
using namespace apsi::util;
using namespace apsi::sender;
using namespace apsi::network;
using namespace apsi::logging;
using namespace apsi::oprf;

int run_sender_dispatcher(const CLP &cmd);

unique_ptr<CSVReader::DBData> load_db(const string &db_file);

pair<shared_ptr<OPRFKey>, shared_ptr<SenderDB>> create_sender_db(
    const CSVReader::DBData &db_data,
    const PSIParams &psi_params,
    size_t thread_count);

int main(int argc, char *argv[])
{
    prepare_console();

    // Enable full logging to console until desired values are read from command line arguments
    Log::set_console_disabled(true);
    Log::set_log_level(Log::Level::all);

    CLP cmd("Example of a Sender implementation", APSI_VERSION);
    if (!cmd.parse_args(argc, argv))
    {
        APSI_LOG_ERROR("Failed parsing command line arguments");
        return -1;
    }

    Log::set_log_file(cmd.log_file());
    Log::set_console_disabled(!cmd.enable_console());
    Log::set_log_level(cmd.log_level());

    return run_sender_dispatcher(cmd);
}

void sigint_handler(int param)
{
    APSI_LOG_WARNING("Sender interrupted");

    vector<string> timing_report;
    vector<Stopwatch::TimespanSummary> timings;
    sender_stopwatch.get_timespans(timings);

    if (timings.size() > 0)
    {
        timing_report = generate_timespan_report(timings, sender_stopwatch.get_max_timespan_event_name_length());

        APSI_LOG_INFO("Timespan event information");
        for (const auto &timing : timing_report)
        {
            APSI_LOG_INFO(timing.c_str());
        }
    }

    vector<Stopwatch::Timepoint> timepoints;
    sender_stopwatch.get_events(timepoints);

    if (timepoints.size() > 0)
    {
        timing_report = generate_event_report(timepoints, sender_stopwatch.get_max_event_name_length());

        APSI_LOG_INFO("Single event information");
        for (const auto &timing : timing_report)
        {
            APSI_LOG_INFO(timing.c_str());
        }
    }

    exit(0);
}

int run_sender_dispatcher(const CLP &cmd)
{
    print_example_banner("Starting APSI Example Sender");

    // Set up parameters according to command line input
    unique_ptr<PSIParams> params = build_psi_params(cmd);
    if (!params)
    {
        // Failed to set parameters
        APSI_LOG_ERROR("Failed to set PSI parameters: terminating");
        return -1;
    }

    unique_ptr<CSVReader::DBData> db_data = load_db(cmd.db_file());
    if (!db_data)
    {
        // Failed to read db file
        APSI_LOG_ERROR("Failed to read database: terminating");
        return -1;
    }

    auto [oprf_key, sender_db] = create_sender_db(*db_data, *params, cmd.threads());
    db_data = nullptr;

    signal(SIGINT, sigint_handler);

    // Run the dispatcher
    atomic<bool> stop = false;
    ZMQSenderDispatcher dispatcher(sender_db, cmd.threads());

    // The dispatcher will run until stopped.
    dispatcher.run(stop, cmd.net_port(), oprf_key);

    return 0;
}

unique_ptr<CSVReader::DBData> load_db(const string &db_file)
{
    CSVReader::DBData db_data;
    try
    {
        CSVReader reader(db_file);
        db_data = reader.read();
    }
    catch (const exception &ex)
    {
        APSI_LOG_WARNING("Could not open or read file `" << db_file << "`: " << ex.what());
        return nullptr;
    }

    return make_unique<CSVReader::DBData>(move(db_data));
}

pair<shared_ptr<OPRFKey>, shared_ptr<SenderDB>> create_sender_db(
    const CSVReader::DBData &db_data,
    const PSIParams &psi_params,
    size_t thread_count)
{
    auto oprf_key = make_shared<OPRFKey>();
    APSI_LOG_INFO("Created new OPRF key");

    shared_ptr<SenderDB> sender_db;
    if (holds_alternative<CSVReader::UnlabeledData>(db_data))
    {
        vector<HashedItem> hashed_db_data;
        {
            STOPWATCH(sender_stopwatch, "OPRF");
            hashed_db_data = OPRFSender::ComputeHashes(get<CSVReader::UnlabeledData>(db_data), *oprf_key, thread_count);
        }
        APSI_LOG_INFO("Computed OPRF hash for " << hashed_db_data.size() << " items");

        try
        {
            sender_db = make_shared<UnlabeledSenderDB>(psi_params);
            sender_db->set_data(hashed_db_data, thread_count);
            APSI_LOG_INFO("Created unlabeled SenderDB with " << sender_db->get_items().size() << " items");
        }
        catch (const exception &ex)
        {
            APSI_LOG_ERROR("Failed to create SenderDB: " << ex.what());
            return { nullptr, nullptr };
        }
    }
    else if (holds_alternative<CSVReader::LabeledData>(db_data))
    {
        vector<pair<HashedItem, FullWidthLabel>> hashed_db_data;
        {
            STOPWATCH(sender_stopwatch, "OPRF");
            hashed_db_data = OPRFSender::ComputeHashes(get<CSVReader::LabeledData>(db_data), *oprf_key, thread_count);
        }
        APSI_LOG_INFO("Computed OPRF hash for " << hashed_db_data.size() << " items");

        try
        {
            sender_db = make_shared<LabeledSenderDB>(psi_params);
            sender_db->set_data(hashed_db_data, thread_count);
            APSI_LOG_INFO("Created labeled SenderDB with " << sender_db->get_items().size() << " items");
        }
        catch (const exception &ex)
        {
            APSI_LOG_ERROR("Failed to create SenderDB: " << ex.what());
            return { nullptr, nullptr };
        }
    }
    else
    {
        // Should never reach this point
        APSI_LOG_ERROR("Loaded database is in an invalid state");
        return { nullptr, nullptr };
    }

    return { oprf_key, sender_db };
}
