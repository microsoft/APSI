#include "sender.h"

// STD
#include <iostream>
#include <fstream>
#include <string>
#include <csignal>

// APSI
#include "clp.h"
#include "apsi/sender/sender.h"
#include "apsi/network/channel.h"
#include "apsi/logging/log.h"
#include "apsi/tools/csvreader.h"
#include "apsi/tools/utils.h"
#include "common_utils.h"



using namespace std;
using namespace apsi;
using namespace apsi::tools;
using namespace apsi::sender;
using namespace apsi::network;
using namespace apsi::logging;


void example_remote(const CLP& cmd);
string get_bind_address(const CLP& cmd);
void initialize_db(const CLP& cmd, vector<Item>& items, Matrix<u8>& labels);


int main(int argc, char *argv[])
{
    prepare_console();

    CLP cmd("Example of a Sender implementation");
    if (!cmd.parse_args(argc, argv))
        return -1;

    Log::set_log_level(cmd.log_level());

    // Example: Remote
    example_remote(cmd);
}

void sigint_handler(int param)
{
    Log::warning("Sender interrupted.");

    vector<string> timing_report;
    vector<Stopwatch::TimespanSummary> timings;
    sender_stop_watch.get_timespans(timings);

    if (timings.size() > 0)
    {
        generate_timespan_report(timing_report, timings, sender_stop_watch.get_max_timespan_event_name_length());

        Log::info("Timespan event information");
        for (const auto& timing : timing_report)
        {
            Log::info(timing.c_str());
        }
    }

    vector<Stopwatch::Timepoint> timepoints;
    sender_stop_watch.get_events(timepoints);

    if (timepoints.size() > 0)
    {
        generate_event_report(timing_report, timepoints, sender_stop_watch.get_max_event_name_length());

        Log::info("Single event information");
        for (const auto& timing : timing_report)
        {
            Log::info(timing.c_str());
        }
    }

    exit(0);
}

void example_remote(const CLP& cmd)
{
    print_example_banner("Remote Sender");

    PSIParams params = build_psi_params(cmd);

    Log::info("Preparing sender DB");

    vector<Item> items;
    Matrix<u8> labels;

    initialize_db(cmd, items, labels);
    u64 sender_bin_size = compute_sender_bin_size(
        params.log_table_size(),
        items.size(),
        params.hash_func_count(),
        params.binning_sec_level(),
        params.split_count());
    params.set_sender_bin_size(static_cast<int>(sender_bin_size));

    Log::info("Building sender");
    Sender sender(params, cmd.threads(), cmd.threads());

    Log::info("Sender loading DB with %i items", items.size());
    sender.load_db(items, labels);

    zmqpp::context_t context;
    Channel channel(context);

    string bind_addr = get_bind_address(cmd);
    Log::info("Binding to address: %s", bind_addr.c_str());
    channel.bind(bind_addr);

    // Sender will run until interrupted.
    signal(SIGINT, sigint_handler);

    while (true)
    {
        Log::info("Waiting for request.");
        sender.query_session(channel);
    }
}

string get_bind_address(const CLP& cmd)
{
    stringstream ss;
    ss << "tcp://*:" << cmd.net_port();

    return ss.str();
}

void initialize_db(const CLP& cmd, vector<Item>& items, Matrix<u8>& labels)
{
    auto label_bit_length  = cmd.use_labels() ? cmd.item_bit_length() : 0;
    auto label_byte_length = (label_bit_length + 7) / 8;

    CSVReader reader(cmd.db_file());
    reader.read(items, labels, label_byte_length);
}
