// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#if defined(__GNUC__) && (__GNUC__ < 8) && !defined(__clang__)
#include <experimental/filesystem>
#else
#include <filesystem>
#endif

// APSI
#include "apsi/log.h"
#include "apsi/network/zmq/zmq_channel.h"
#include "apsi/receiver.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/version.h"
#include "common/common_utils.h"
#include "common/csv_reader.h"
#include "receiver/clp.h"

using namespace std;
#if defined(__GNUC__) && (__GNUC__ < 8) && !defined(__clang__)
namespace fs = std::experimental::filesystem;
#else
namespace fs = std::filesystem;
#endif
using namespace apsi;
using namespace apsi::util;
using namespace apsi::receiver;
using namespace apsi::network;

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
} // namespace

int remote_query(const CLP &cmd);

string get_conn_addr(const CLP &cmd);

pair<unique_ptr<CSVReader::DBData>, vector<string>> load_db(const string &db_file);

void print_intersection_results(
    const vector<string> &orig_items,
    const vector<Item> &items,
    const vector<MatchRecord> &intersection,
    const string &out_file);

void print_transmitted_data(Channel &channel);

int main(int argc, char *argv[])
{
    CLP cmd("Example of a Receiver implementation", APSI_VERSION);
    if (!cmd.parse_args(argc, argv)) {
        APSI_LOG_ERROR("Failed parsing command line arguments");
        return -1;
    }

    return remote_query(cmd);
}

int remote_query(const CLP &cmd)
{
    // Connect to the network
    ZMQReceiverChannel channel;

    string conn_addr = get_conn_addr(cmd);
    APSI_LOG_INFO("Connecting to " << conn_addr);
    channel.connect(conn_addr);
    if (channel.is_connected()) {
        APSI_LOG_INFO("Successfully connected to " << conn_addr);
    } else {
        APSI_LOG_WARNING("Failed to connect to " << conn_addr);
        return -1;
    }

    unique_ptr<PSIParams> params;
    try {
        APSI_LOG_INFO("Sending parameter request");
        params = make_unique<PSIParams>(Receiver::RequestParams(channel));
        APSI_LOG_INFO("Received valid parameters");
    } catch (const exception &ex) {
        APSI_LOG_WARNING("Failed to receive valid parameters: " << ex.what());
        return -1;
    }

    ThreadPoolMgr::SetThreadCount(cmd.threads());
    APSI_LOG_INFO("Setting thread count to " << ThreadPoolMgr::GetThreadCount());

    Receiver receiver(*params);

    auto [query_data, orig_items] = load_db(cmd.query_file());
    if (!query_data || !holds_alternative<CSVReader::UnlabeledData>(*query_data)) {
        // Failed to read query file
        APSI_LOG_ERROR("Failed to read query file: terminating");
        return -1;
    }

    auto &items = get<CSVReader::UnlabeledData>(*query_data);
    vector<Item> items_vec(items.begin(), items.end());
    vector<HashedItem> oprf_items;
    vector<LabelKey> label_keys;
    try {
        APSI_LOG_INFO("Sending OPRF request for " << items_vec.size() << " items");
        tie(oprf_items, label_keys) = Receiver::RequestOPRF(items_vec, channel);
        APSI_LOG_INFO("Received OPRF response for " << items_vec.size() << " items");
    } catch (const exception &ex) {
        APSI_LOG_WARNING("OPRF request failed: " << ex.what());
        return -1;
    }

    vector<MatchRecord> query_result;
    try {
        APSI_LOG_INFO("Sending APSI query");
        query_result = receiver.request_query(oprf_items, label_keys, channel);
        APSI_LOG_INFO("Received APSI query response");
    } catch (const exception &ex) {
        APSI_LOG_WARNING("Failed sending APSI query: " << ex.what());
        return -1;
    }

    print_intersection_results(orig_items, items_vec, query_result, cmd.output_file());
    print_transmitted_data(channel);
    print_timing_report(recv_stopwatch);

    return 0;
}

pair<unique_ptr<CSVReader::DBData>, vector<string>> load_db(const string &db_file)
{
    CSVReader::DBData db_data;
    vector<string> orig_items;
    try {
        CSVReader reader(db_file);
        tie(db_data, orig_items) = reader.read();
    } catch (const exception &ex) {
        APSI_LOG_WARNING("Could not open or read file `" << db_file << "`: " << ex.what());
        return { nullptr, orig_items };
    }

    return { make_unique<CSVReader::DBData>(move(db_data)), move(orig_items) };
}

void print_intersection_results(
    const vector<string> &orig_items,
    const vector<Item> &items,
    const vector<MatchRecord> &intersection,
    const string &out_file)
{
    if (orig_items.size() != items.size()) {
        throw invalid_argument("orig_items must have same size as items");
    }

    stringstream csv_output;
    for (size_t i = 0; i < orig_items.size(); i++) {
        stringstream msg;
        if (intersection[i].found) {
            msg << Colors::GreenBold << orig_items[i] << Colors::Reset << " (FOUND)";
            csv_output << orig_items[i];
            if (intersection[i].label) {
                msg << ": ";
                msg << Colors::GreenBold << intersection[i].label.to_string() << Colors::Reset;
                csv_output << "," << intersection[i].label.to_string();
            }
            csv_output << endl;
            APSI_LOG_INFO(msg.str());
        } else {
            // msg << Colors::RedBold << orig_items[i] << Colors::Reset << " (NOT FOUND)";
            // APSI_LOG_INFO(msg.str());
        }
    }

    if (!out_file.empty()) {
        ofstream ofs(out_file);
        ofs << csv_output.str();
        APSI_LOG_INFO("Wrote output to " << out_file);
    }
}

void print_transmitted_data(Channel &channel)
{
    auto nice_byte_count = [](uint64_t bytes) -> string {
        stringstream ss;
        if (bytes >= 10 * 1024) {
            ss << bytes / 1024 << " KB";
        } else {
            ss << bytes << " B";
        }
        return ss.str();
    };

    APSI_LOG_INFO("Communication R->S: " << nice_byte_count(channel.bytes_sent()));
    APSI_LOG_INFO("Communication S->R: " << nice_byte_count(channel.bytes_received()));
    APSI_LOG_INFO(
        "Communication total: " << nice_byte_count(
            channel.bytes_sent() + channel.bytes_received()));
}

string get_conn_addr(const CLP &cmd)
{
    stringstream ss;
    ss << "tcp://" << cmd.net_addr() << ":" << cmd.net_port();

    return ss.str();
}
