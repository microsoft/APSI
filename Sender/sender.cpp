#include "sender.h"

// STD
#include <iostream>
#include <fstream>
#include <string>
#include <csignal>

// APSI
#include "clp.h"
#include "senderutils.h"
#include "common_utils.h"
#include "apsi/sender/sender.h"
#include "apsi/sender/senderdispatcher.h"
#include "apsi/network/channel.h"
#include "apsi/logging/log.h"
#include "apsi/tools/csvreader.h"
#include "apsi/tools/utils.h"


// For now version is a constant
#define SENDER_VERSION "0.1"


using namespace std;
using namespace apsi;
using namespace apsi::tools;
using namespace apsi::sender;
using namespace apsi::network;
using namespace apsi::logging;


void run_sender_dispatcher(const CLP& cmd);
void initialize_db(const CLP& cmd, vector<Item>& items, Matrix<u8>& labels);


int main(int argc, char *argv[])
{
    prepare_console();

    CLP cmd("Example of a Sender implementation", SENDER_VERSION);
    if (!cmd.parse_args(argc, argv))
        return -1;

    Log::set_log_level(cmd.log_level());

    run_sender_dispatcher(cmd);
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

void run_sender_dispatcher(const CLP& cmd)
{
    print_example_banner("Remote Sender");

    Log::info("Preparing sender DB");

    vector<Item> items;
    Matrix<u8> labels;

    initialize_db(cmd, items, labels);

    PSIParams params = build_psi_params(cmd, items.size());

    Log::info("Building sender");
    shared_ptr<Sender> sender = make_shared<Sender>(params, cmd.threads(), cmd.threads());

    Log::info("Sender loading DB with %i items", items.size());
    sender->load_db(items, labels);

    signal(SIGINT, sigint_handler);

    // Run the dispatcher
    atomic<bool> stop = false;
    SenderDispatcher dispatcher(sender);

    // The dispatcher will run until stopped.
    dispatcher.run(stop, cmd.net_port());
}

void initialize_db(const CLP& cmd, vector<Item>& items, Matrix<u8>& labels)
{
    auto label_bit_length  = cmd.use_labels() ? cmd.item_bit_length() : 0;
    auto label_byte_length = (label_bit_length + 7) / 8;

    CSVReader reader(cmd.db_file());
    reader.read(items, labels, label_byte_length);
}