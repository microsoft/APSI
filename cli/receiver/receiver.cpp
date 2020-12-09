// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

// APSI
#include "apsi/receiver.h"
#include "apsi/network/zmq/zmq_channel.h"
#include "apsi/logging/log.h"
#include "apsi/version.h"
#include "common/common_utils.h"
#include "common/csv_reader.h"
#include "receiver/clp.h"

using namespace std;
namespace fs = std::filesystem;
using namespace apsi;
using namespace apsi::util;
using namespace apsi::receiver;
using namespace apsi::network;
using namespace apsi::logging;

namespace {
    struct Colors {
        static const string Red;
        static const string Green;
        static const string RedBold;
        static const string GreenBold;
        static const string Reset;
    };

    const string Colors::Red = "\033[31m";
    const string Colors::Green = "\033[32m";
    const string Colors::RedBold = "\033[1;31m";
    const string Colors::GreenBold = "\033[1;32m";
    const string Colors::Reset = "\033[0m";
}

int remote_query(const CLP &cmd);

string get_conn_addr(const CLP &cmd);

unique_ptr<CSVReader::DBData> load_db(const string &db_file);

void print_intersection_results(const vector<Item> &items, const vector<MatchRecord> &intersection);

void print_timing_info();

void print_transmitted_data(Channel &channel);

int main(int argc, char *argv[])
{
    // Enable full logging to console until desired values are read from command line arguments
    Log::set_console_disabled(true);
    Log::set_log_level(Log::Level::all);

    CLP cmd("Example of a Receiver implementation", APSI_VERSION);
    if (!cmd.parse_args(argc, argv))
    {
        APSI_LOG_ERROR("Failed parsing command line arguments");
        return -1;
    }

    Log::set_log_file(cmd.log_file());
    Log::set_console_disabled(!cmd.enable_console());
    Log::set_log_level(cmd.log_level());

    return remote_query(cmd);
}

int remote_query(const CLP& cmd)
{
    print_example_banner("Starting APSI Example Receiver");

    // Connect to the network
    ZMQReceiverChannel channel;

    string conn_addr = get_conn_addr(cmd);
    APSI_LOG_INFO("Connecting to " << conn_addr);
    channel.connect(conn_addr);
    if (channel.is_connected())
    {
        APSI_LOG_INFO("Successfully connected to " << conn_addr);
    }
    else
    {
        APSI_LOG_WARNING("Failed to connect to " << conn_addr);
        return -1;
    }

    unique_ptr<PSIParams> params;
    try
    {
        APSI_LOG_INFO("Sending parameter request");
        params = make_unique<PSIParams>(Receiver::RequestParams(channel));
        APSI_LOG_INFO("Received valid parameters");
    }
    catch (const exception &ex)
    {
        APSI_LOG_WARNING("Failed to receive valid parameters: " << ex.what());
        return -1;
    }

    Receiver receiver(*params, cmd.threads());

    unique_ptr<CSVReader::DBData> query_data = load_db(cmd.query_file());
    if (!query_data || !holds_alternative<CSVReader::UnlabeledData>(*query_data))
    {
        // Failed to read query file
        APSI_LOG_ERROR("Failed to read query file: terminating");
        return -1;
    }

    auto &items = get<CSVReader::UnlabeledData>(*query_data);
    vector<Item> items_vec(items.begin(), items.end());
    vector<HashedItem> oprf_items;
    try
    {
        APSI_LOG_INFO("Sending OPRF request for " << items_vec.size() << " items");
        oprf_items = receiver.request_oprf(items_vec, channel);
        APSI_LOG_INFO("Received OPRF request for " << items_vec.size() << " items");
    }
    catch (const exception &ex)
    {
        APSI_LOG_WARNING("OPRF request failed: " << ex.what());
        return -1;
    }

    unique_ptr<Query> query;
    try
    {
        APSI_LOG_INFO("Creating query");
        query = make_unique<Query>(receiver.create_query(oprf_items));
        APSI_LOG_INFO("Finished creating query");
    }
    catch (const exception &ex)
    {
        APSI_LOG_WARNING("Failed to create query: " << ex.what());
        return -1;
    }

    vector<MatchRecord> query_result;
    try
    {
        APSI_LOG_INFO("Sending APSI query");
        query_result = receiver.request_query(move(*query), channel);
        query = nullptr;
        APSI_LOG_INFO("Received APSI query response");
    }
    catch (const exception &ex)
    {
        APSI_LOG_WARNING("Failed sending APSI query: " << ex.what());
        return -1;
    }

    print_intersection_results(items_vec, query_result);
    print_timing_info();
    print_transmitted_data(channel);

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

string print_hex(gsl::span<unsigned char> s)
{
    stringstream ss;
    ss << "{ ";
    for (int i = static_cast<int>(s.size()) - 1; i >= 0; i--)
    {
        ss << setw(2) << setfill('0') << hex << int(s[i]) << (i ? ", " : " }");
    }

    return ss.str();
}

void print_intersection_results(const vector<Item> &items, const vector<MatchRecord> &intersection)
{
    for (size_t i = 0; i < intersection.size(); i++)
    {
        stringstream msg;
        msg << items[i].to_string() << ": ";
        if (intersection[i].found)
        {
            msg << Colors::GreenBold << "found" << Colors::Reset;
            msg << "; label: ";
            if (intersection[i].label)
            {
                msg << Colors::GreenBold << intersection[i].label.to_string() << Colors::Reset;
            }
            else
            {
                msg << Colors::GreenBold << "<empty>" << Colors::Reset;
            }
        }
        else
        {
            msg << Colors::Red << "not found" << Colors::Reset;
        }

        APSI_LOG_INFO(msg.str());
    }
}

void print_timing_info(Stopwatch &stopwatch, const string &caption)
{
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
}

void print_timing_info()
{
    print_timing_info(recv_stopwatch, "Timing events for Receiver");
}

void print_transmitted_data(Channel &channel)
{
    APSI_LOG_INFO("Communication R->S: " << channel.bytes_sent() / 1024.0f << " KB");
    APSI_LOG_INFO("Communication S->R: " << channel.bytes_received() / 1024.0f << " KB");
    APSI_LOG_INFO("Communication total: "
        << (channel.bytes_sent() + channel.bytes_received()) / 1024.0f << " KB");
}

string get_conn_addr(const CLP &cmd)
{
    stringstream ss;
    ss << "tcp://" << cmd.net_addr() << ":" << cmd.net_port();

    return ss.str();
}
