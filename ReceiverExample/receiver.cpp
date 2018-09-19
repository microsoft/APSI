// STD
#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>
#include <vector>
#include <set>

// APSI
#include "apsi/apsi.h"
#include "apsi/network/channel.h"
#include "apsi/tools/utils.h"
#include "apsi/tools/csvreader.h"
#include "apsi/logging/log.h"
#include "common_utils.h"

// SEAL
#include "seal/seal.h"

// Command Line Processor
#include "clp.h"


using namespace std;
using namespace apsi;
using namespace apsi::tools;
using namespace apsi::receiver;
using namespace apsi::sender;
using namespace apsi::network;
using namespace apsi::logging;
using namespace seal::util;
using namespace seal;


void example_slow_batching(const CLP& cmd);
void example_remote(const CLP& cmd);
void print_intersection_results(vector<Item>& client_items, int intersection_size, pair<vector<bool>, Matrix<u8>>& intersection, bool compare_labels, vector<int>& label_idx, Matrix<u8>& labels);
void print_timing_info();
void print_transmitted_data(Channel& channel);
string get_bind_addr(const CLP& cmd);
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

std::pair<vector<Item>, vector<int>> rand_subset(const vector<Item>& items, int size)
{
    PRNG prn(zero_block);

    set<int> ss;
    while (ss.size() != size)
    {
        ss.emplace(static_cast<int>(prn.get<unsigned int>() % items.size()));
    }
    auto ssIter = ss.begin();

    vector<Item> ret(size);
    for (int i = 0; i < size; i++)
    {
        ret[i] = items[*ssIter++];
    }
    auto iter = ss.begin();
    vector<int> s(size);
    for (u64 i = 0; i < size; ++i)
    {
        s[i] = *iter++;
    }
    return { ret, s };
}


int main(int argc, char *argv[])
{
    apsi::CLP cmd("Example Implementation of APSI library");

    if (!cmd.parse_args(argc, argv))
        return -1;

    Log::set_log_level(cmd.log_level());

    prepare_console();

    if (cmd.mode() == "local")
    {
        // Example: Slow batching
        example_slow_batching(cmd);
    }
    else
    {
        example_remote(cmd);
    }

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

std::string print(gsl::span<u8> s)
{
    std::stringstream ss;
    for (int i = 0; i < s.size(); ++i)
    {
        ss << (i ? ", " : "{ ") << std::setw(2) << std::setfill('0') << std::hex << int(s[i]);
    }

    ss << " }";
    return ss.str();
}

void example_slow_batching(const CLP& cmd)
{
    print_example_banner("Example: Slow batching");

    // Connect the network
    zmqpp::context_t context;
    Channel recvChl(context);
    Channel sendChl(context);

    string bind_addr = get_bind_addr(cmd);
    string conn_addr = get_conn_addr(cmd);

    Log::info("Binding Sender to address: %s", bind_addr.c_str());
    sendChl.bind(bind_addr);

    Log::info("Connecting receiver to address: %s", conn_addr.c_str());
    recvChl.connect(conn_addr);

    // Thread count
    unsigned numThreads = cmd.threads();

    PSIParams params = build_psi_params(cmd);

    std::unique_ptr<Receiver> receiver_ptr;

    int recThreads = cmd.rec_threads();

    // Check that number of blocks is not smaller than thread count
    if(max<int>(numThreads, recThreads) > params.split_count() * params.batch_count())
    {
        cout << "WARNING: Using too many threads for block count!" << endl;
    }

    auto f = std::async([&]()
    {
        receiver_ptr = make_unique<Receiver>(params, recThreads, MemoryPoolHandle::New());
    });
    Sender sender(params, numThreads, numThreads, MemoryPoolHandle::New());
    f.get();
    Receiver& receiver = *receiver_ptr;

    auto label_bit_length = cmd.use_labels() ? cmd.item_bit_length() : 0;
    auto sendersActualSize = 1 << cmd.sender_size();
    auto recversActualSize = 50;
    auto intersectionSize = 25;

    auto s1 = vector<Item>(sendersActualSize);
    Matrix<u8> labels(sendersActualSize, params.get_label_byte_count());
    for (int i = 0; i < s1.size(); i++)
    {
        s1[i] = i;

        if (label_bit_length) {
            memset(labels[i].data(), 0, labels[i].size());

            labels[i][0] = i;
            labels[i][1] = (i >> 8);
        }
    }

    auto cc1 = rand_subset(s1, intersectionSize);
    auto& c1 = cc1.first;

    c1.reserve(recversActualSize);
    for (int i = 0; i < (recversActualSize - intersectionSize); ++i)
        c1.emplace_back(i + s1.size());

    sender.load_db(s1, labels);

    auto thrd = thread([&]() {
        sender.query_session(sendChl); 
    });
    recv_stop_watch.add_event("receiver start");
    auto intersection = receiver.query(c1, recvChl);
    recv_stop_watch.add_event("receiver done");
    thrd.join();

    // Done with everything. Print the results!
    print_intersection_results(c1, intersectionSize, intersection, label_bit_length > 0, cc1.second, labels);
    print_timing_info();
    print_transmitted_data(recvChl);
}

void example_remote(const CLP& cmd)
{
    print_example_banner("Example: Remote connection");

    Log::warning("Only parameter 'recThreads' is used in this mode. All other thread count parameters are ignored.");

    // Connect to the network
    zmqpp::context_t context;
    Channel channel(context);

    string conn_addr = get_conn_addr(cmd);
    Log::info("Receiver connecting to address: %s", conn_addr.c_str());
    channel.connect(conn_addr);

    PSIParams params = build_psi_params(cmd);
    Receiver receiver(params, cmd.rec_threads());

    vector<Item> items;
    Matrix<u8> labels;
    int intersection_size = initialize_query(cmd, items, labels, params.get_label_byte_count());

    auto result = receiver.query(items, channel);

    vector<int> label_idx;
    bool compare_labels = false;
    if (!cmd.query_file().empty() && cmd.use_labels())
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

string get_bind_addr(const CLP& cmd)
{
    stringstream ss;
    ss << "tcp://*:" << cmd.net_port();

    return ss.str();
}

string get_conn_addr(const CLP& cmd)
{
    stringstream ss;
    ss << "tcp://" << cmd.net_addr() << ":" << cmd.net_port();

    return ss.str();
}

int initialize_query(const CLP& cmd, vector<Item>& items, Matrix<u8>& labels, int label_byte_count)
{
    if (cmd.query_file().empty())
    {
        items.resize(20);
        auto sender_size = 1 << cmd.sender_size();

        int i;
        for (i = 0; i < items.size() / 2; i++)
        {
            // Items within sender
            items[i] = i;
        }

        for (; i < items.size(); i++)
        {
            // Items that should not be within sender
            items[i] = sender_size + i;
        }

        return static_cast<int>(items.size() / 2);
    }
    else
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
}
