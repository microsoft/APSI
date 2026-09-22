// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>
#include <cstddef>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

// APSI
#include "apsi/log.h"
#include "apsi/network/zmq/zmq_channel.h"
#include "apsi/receiver.h"
#include "apsi/thread_pool_mgr.h"
#include "common/common_utils.h"
#include "common/csv_reader.h"
#include "receiver/clp.h"

using namespace std;
using namespace apsi;
using namespace apsi::util;
using namespace apsi::receiver;
using namespace apsi::network;

namespace {
    struct Colors {
        [[maybe_unused]] static constexpr const char *Red = "\033[31m";
        [[maybe_unused]] static constexpr const char *Green = "\033[32m";
        [[maybe_unused]] static constexpr const char *RedBold = "\033[1;31m";
        static constexpr const char *GreenBold = "\033[1;32m";
        static constexpr const char *Reset = "\033[0m";
    };

    /**
    Rewrites the C0 control characters as escapes. A label is whatever the sender chose to store,
    and it is printed to a terminal here: an ESC it contains would otherwise move the cursor or
    recolor what is already on the screen, and a CR would let it overwrite the line just written.
    Bytes above 0x7E are left as they are, so that a label holding UTF-8 text still reads as text.
    */
    string escape_control_bytes(const string &in)
    {
        static constexpr array<char, 17> hex_digits{ "0123456789abcdef" };

        string out;
        out.reserve(in.size());
        for (char c : in) {
            auto byte = static_cast<unsigned char>(c);
            if (byte < 0x20 || byte == 0x7F) {
                out += "\\x";
                out += hex_digits[byte >> 4];
                out += hex_digits[byte & 0x0F];
            } else {
                out += c;
            }
        }
        return out;
    }

    /**
    Escapes a field for the CSV output. Control characters are rewritten as above, and a field
    holding a comma or a quote is quoted with its internal quotes doubled, as RFC 4180 describes.
    A label could otherwise add columns to the file.
    */
    string escape_csv_field(const string &in)
    {
        string escaped = escape_control_bytes(in);
        if (escaped.find_first_of(",\"") == string::npos) {
            return escaped;
        }

        string out = "\"";
        for (char c : escaped) {
            if (c == '"') {
                out += "\"\"";
            } else {
                out += c;
            }
        }
        out += '"';
        return out;
    }
} // namespace

int remote_query(const CLP &cmd);

string get_conn_addr(const CLP &cmd);

pair<unique_ptr<CSVReader::DBData>, vector<string>> load_db(const string &db_file);

void print_intersection_results(
    const vector<string> &orig_items,
    const vector<Item> &items,
    const vector<MatchRecord> &intersection,
    const string &out_file,
    bool use_color);

void print_transmitted_data(Channel &channel);

int main(int argc, char *argv[])
{
    try {
        CLP cmd("Example of a Receiver implementation", APSI_VERSION);
        if (!cmd.parse_args(argc, argv)) {
            APSI_LOG_ERROR("Failed parsing command line arguments");
            return -1;
        }

        return remote_query(cmd);
    } catch (const exception &ex) {
        APSI_LOG_ERROR("Receiver terminated with an unhandled exception: " << ex.what());
        return -1;
    } catch (...) {
        APSI_LOG_ERROR("Receiver terminated with an unknown exception");
        return -1;
    }
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
        params = make_unique<PSIParams>(Receiver::RequestParams(channel, cmd.timeout()));
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
    LabelKeyVector label_keys;
    try {
        APSI_LOG_INFO("Sending OPRF request for " << items_vec.size() << " items");
        tie(oprf_items, label_keys) = Receiver::RequestOPRF(items_vec, channel, cmd.timeout());
        APSI_LOG_INFO("Received OPRF response for " << items_vec.size() << " items");
    } catch (const exception &ex) {
        APSI_LOG_WARNING("OPRF request failed: " << ex.what());
        return -1;
    }

    vector<MatchRecord> query_result;
    try {
        APSI_LOG_INFO("Sending APSI query");
        query_result = receiver.request_query(oprf_items, label_keys, channel, cmd.timeout());
        APSI_LOG_INFO("Received APSI query response");
    } catch (const exception &ex) {
        APSI_LOG_WARNING("Failed sending APSI query: " << ex.what());
        return -1;
    }

    // Color only when the output is a terminal that will render it. A log file, a pipe or a
    // redirect receives the escape sequences as literal bytes instead.
    bool use_color = stdout_is_terminal() && cmd.log_file().empty();

    print_intersection_results(orig_items, items_vec, query_result, cmd.output_file(), use_color);
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

    return { make_unique<CSVReader::DBData>(std::move(db_data)), std::move(orig_items) };
}

void print_intersection_results(
    const vector<string> &orig_items,
    const vector<Item> &items,
    const vector<MatchRecord> &intersection,
    const string &out_file,
    bool use_color)
{
    if (orig_items.size() != items.size()) {
        throw invalid_argument("orig_items must have same size as items");
    }
    if (intersection.size() != items.size()) {
        throw invalid_argument("intersection must have same size as items");
    }

    const char *highlight = use_color ? Colors::GreenBold : "";
    const char *reset = use_color ? Colors::Reset : "";

    stringstream csv_output;
    for (size_t i = 0; i < orig_items.size(); i++) {
        stringstream msg;
        if (intersection[i].found) {
            msg << highlight << escape_control_bytes(orig_items[i]) << reset << " (FOUND)";
            csv_output << escape_csv_field(orig_items[i]);
            if (intersection[i].label) {
                string label = intersection[i].label.to_string();
                msg << ": ";
                msg << highlight << escape_control_bytes(label) << reset;
                csv_output << "," << escape_csv_field(label);
            }
            csv_output << '\n';
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
        if (bytes >= static_cast<uint64_t>(10 * 1024)) {
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
