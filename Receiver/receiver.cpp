// STD
#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>
#include <vector>
#include <set>

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
void print_intersection_results(vector<Item>& client_items, int intersection_size, pair<vector<bool>, Matrix<u8>>& intersection, bool compare_labels, vector<int>& label_idx, Matrix<u8>& labels);
void print_timing_info();
void print_transmitted_data(Channel& channel);
string get_conn_addr(const CLP& cmd);
int initialize_query(const CLP& cmd, vector<Item>& items, Matrix<u8>& labels, int label_byte_count);

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

#ifdef _MSC_VER
    if (IsDebuggerPresent())
    {
        // Wait for ENTER before closing screen.
        cout << endl << "Press ENTER to exit" << endl;
        char ignore;
        cin.get(ignore);
    }
#endif
    return 0;
}

void remote_query(const CLP& cmd)
{
    print_example_banner("Query a remote Sender");

    // Connect to the network
    zmqpp::context_t context;
    ReceiverChannel channel(context);

    string conn_addr = get_conn_addr(cmd);
    Log::info("Receiver connecting to address: %s", conn_addr.c_str());
    channel.connect(conn_addr);

    PSIParams params = build_psi_params(cmd);
    Receiver receiver(params, cmd.threads());

    // Check that number of blocks is not smaller than thread count
    auto block_count = params.split_count() * params.batch_count();
    if (cmd.threads() > block_count)
    {
        Log::warning("Using too many threads for block count! Block count: %i", block_count);
    }

    vector<Item> items;
    Matrix<u8> labels;
    int intersection_size = initialize_query(cmd, items, labels, params.get_label_byte_count());

    auto result = receiver.query(items, channel);

    vector<int> label_idx;
    bool compare_labels = false;
    if (!cmd.query_file().empty() && receiver.get_params().get_label_bit_count() > 0)
    {
        // We can compare labels.
        compare_labels = true;
        for (int i = 0; i < intersection_size; i++)
        {
            label_idx.emplace_back(i);
        }
    }

    print_intersection_results(items, intersection_size, result, compare_labels, label_idx, labels);
    print_timing_info();
    print_transmitted_data(channel);
}

void print_intersection_results(vector<Item>& client_items, int intersection_size, pair<vector<bool>, Matrix<u8>>& intersection, bool compare_labels, vector<int>& label_idx, Matrix<u8>& labels)
{
    bool correct = true;
    for (int i = 0; i < client_items.size(); i++)
    {

        if (i < intersection_size)
        {
            if (intersection.first[i] == false)
            {
                Log::info("Miss result for receiver's item at index: %i", i);
                correct = false;
            }
            else if (compare_labels)
            {
                auto idx = label_idx[i];
                if (memcmp(intersection.second[i].data(), labels[idx].data(), labels[idx].size()))
                {
                    Log::error("%sincorrect label at index: %i%s", Colors::Red.c_str(), i, Colors::Reset.c_str());
                    correct = false;
                }
            }
        }
        else
        {
            if (intersection.first[i])
            {
                Log::info("%sIncorrect result for receiver's item at index: %i%s", Colors::Red.c_str(), i, Colors::Reset.c_str());
                correct = false;
            }
        }
    }

    Log::info("Intersection results: %s%s%s",
        correct ? Colors::Green.c_str() : Colors::Red.c_str(),
        correct ? "Correct" : "Incorrect",
        Colors::Reset.c_str());
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
    print_timing_info(sender_stop_watch, "Timing events for Sender");
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

int initialize_query(const CLP& cmd, vector<Item>& items, Matrix<u8>& labels, int label_byte_count)
{
    // Read items that should exist from file
    CSVReader reader(cmd.query_file());
    reader.read(items, labels, label_byte_count);

    u64 read_items = items.size();

    // Now add some items that should _not_ be in the Sender.
    PRNG prng(sys_random_seed());
    labels.resize(read_items + 20, label_byte_count);

    for (int i = 0; i < 20; i++)
    {
        u64 low_part = 0;
        Item item = zero_block;

        prng.get(reinterpret_cast<u8*>(&low_part), 7);
        item[0] = low_part;

        items.push_back(item);
    }

    return static_cast<int>(read_items);
}
