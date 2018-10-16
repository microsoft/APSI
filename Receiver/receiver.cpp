// STD
#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>
#include <vector>
#include <set>
#include <stack>

// APSI
#include "apsi/apsi.h"
#include "apsi/network/receiverchannel.h"
#include "apsi/tools/utils.h"
#include "apsi/tools/csvreader.h"
#include "apsi/logging/log.h"
#include "common_utils.h"

// SEAL
#include "seal/seal.h"

// Command Line Processor
#include "clp.h"


// For now version is a constant.
#define RECEIVER_VERSION "0.1"


using namespace std;
using namespace apsi;
using namespace apsi::tools;
using namespace apsi::receiver;
using namespace apsi::sender;
using namespace apsi::network;
using namespace apsi::logging;
using namespace seal::util;
using namespace seal;


void remote_query(const CLP& cmd);
void print_intersection_results(pair<vector<bool>, Matrix<u8>>& intersection);
void print_timing_info();
void print_transmitted_data(Channel& channel);
string get_conn_addr(const CLP& cmd);
int initialize_query(const CLP& cmd, vector<Item>& items);

namespace {
    struct Colors {
        static const std::string Red;
        static const std::string Green;
        static const std::string RedBold;
        static const std::string GreenBold;
        static const std::string Reset;
    };

    const std::string Colors::Red = "\033[31m";
    const std::string Colors::Green = "\033[32m";
    const std::string Colors::RedBold = "\033[1;31m";
    const std::string Colors::GreenBold = "\033[1;32m";
    const std::string Colors::Reset = "\033[0m";
}


int main(int argc, char *argv[])
{
    apsi::CLP cmd("Example Implementation of APSI Receiver", RECEIVER_VERSION);

    if (!cmd.parse_args(argc, argv))
        return -1;

    Log::set_log_level(cmd.log_level());

    prepare_console();

    remote_query(cmd);

//#ifdef _MSC_VER
//    if (IsDebuggerPresent())
//    {
//        // Wait for ENTER before closing screen.
//        cout << endl << "Press ENTER to exit" << endl;
//        char ignore;
//        cin.get(ignore);
//    }
//#endif
    return 0;
}

void remote_query(const CLP& cmd)
{
    print_example_banner("Query a remote Sender");

    // Connect to the network
    ReceiverChannel channel;

    string conn_addr = get_conn_addr(cmd);
    Log::info("Receiver connecting to address: %s", conn_addr.c_str());
    channel.connect(conn_addr);

    Receiver receiver(cmd.threads());

    vector<Item> items;
    Matrix<u8> labels;
    int intersection_size = initialize_query(cmd, items);

    receiver.handshake(channel);
    auto result = receiver.query(items, channel);

    print_intersection_results(result);
    print_timing_info();
    print_transmitted_data(channel);
}

string print_hex(gsl::span<u8> s)
{
    stringstream ss;
    ss << "{ ";
    for (int i = static_cast<int>(s.size()) - 1; i >= 0; i--)
    {
        ss << std::setw(2) << std::setfill('0') << std::hex << int(s[i]) << (i ? ", " : " }");
    }

    return ss.str();
}

void print_intersection_results(pair<vector<bool>, Matrix<u8>>& intersection)
{
    for (int i = 0; i < intersection.first.size(); i++)
    {
        stringstream msg;
        msg << "Item at index " << i << " is ";
        if (intersection.first[i])
        {
            msg << Colors::GreenBold << "present" << Colors::Reset;
        }
        else
        {
            msg << Colors::Red << "missing" << Colors::Reset;
        }
        msg << " in Sender.";

        if (intersection.first[i] && intersection.second.columns() > 0)
        {
            msg << " Label: " << print_hex(intersection.second[i]);
        }

        Log::info("%s", msg.str().c_str());
    }
}

void print_timing_info(Stopwatch& stopwatch, const string& caption)
{
    vector<string> timing_report;
    vector<Stopwatch::TimespanSummary> timings;
    vector<Stopwatch::Timepoint> timepoints;

    stopwatch.get_events(timepoints);
    stopwatch.get_timespans(timings);

    if (timepoints.size() == 0 && timings.size() == 0)
        return;

    Log::info(caption.c_str());

    if (timings.size() > 0)
    {
        generate_timespan_report(timing_report, timings, stopwatch.get_max_timespan_event_name_length());

        Log::info("Timespan event information");
        for (const auto& timing : timing_report)
        {
            Log::info(timing.c_str());
        }
    }


    if (timepoints.size() > 0)
    {
        generate_event_report(timing_report, timepoints, stopwatch.get_max_event_name_length());

        Log::info("Single event information");
        for (const auto& timing : timing_report)
        {
            Log::info(timing.c_str());
        }
    }
}

void print_timing_info()
{
    print_timing_info(recv_stop_watch, "Timing events for Receiver");
}

void print_transmitted_data(Channel& channel)
{
    Log::info("Communication R->S: %0.3f KB", channel.get_total_data_sent() / 1024.0f);
    Log::info("Communication S->R: %0.3f KB", channel.get_total_data_received() / 1024.0f);
    Log::info("Communication total: %0.3f KB", (channel.get_total_data_received() + channel.get_total_data_sent()) / 1024.0f);
}

string get_conn_addr(const CLP& cmd)
{
    stringstream ss;
    ss << "tcp://" << cmd.net_addr() << ":" << cmd.net_port();

    return ss.str();
}

int initialize_query(const CLP& cmd, vector<Item>& items)
{
    // Read items that should exist from file
    Matrix<u8> unused;
    CSVReader reader(cmd.query_file());
    reader.read(items, unused, /* label_byte_count */ 0);

    return static_cast<int>(items.size());
}
