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
void print_transmitted_data(Channel& channel);
string get_bind_addr(const CLP& cmd);
string get_conn_addr(const CLP& cmd);


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
    stop_watch.time_points.clear();

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

    stop_watch.set_time_point("Application preparation done");
    sender.load_db(s1, labels);

    auto thrd = thread([&]() {
        sender.query_session(sendChl); 
    });
    recv_stop_watch.set_time_point("receiver start");
    auto intersection = receiver.query(c1, recvChl);
    thrd.join();

    // Done with everything. Print the results!
    print_intersection_results(c1, intersectionSize, intersection, label_bit_length > 0, cc1.second, labels);

    cout << stop_watch << endl;
    cout << recv_stop_watch << endl;

    print_transmitted_data(recvChl);
}

void example_remote(const CLP& cmd)
{
    print_example_banner("Example: Remote connection");

    Log::warning("Only parameter 'recThreads' is used in this mode. All other thread count parameters are ignored.");

    // Connect the network
    zmqpp::context_t context;
    Channel channel(context);

    string conn_addr = get_conn_addr(cmd);
    Log::info("Receiver connecting to address: %s", conn_addr.c_str());
    channel.connect(conn_addr);

    PSIParams params = build_psi_params(cmd);

    Receiver receiver(params, cmd.rec_threads());
    vector<Item> items(20);
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

    auto result = receiver.query(items, channel);

    vector<int> label_idx;
    Matrix<u8> labels;
    print_intersection_results(items, static_cast<int>(items.size() / 2), result, /* compare_labels */ false, label_idx, labels);
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
                cout << "Miss result for receiver's item at index: " << i << endl;
                correct = false;
            }
            else if (compare_labels)
            {
                auto idx = label_idx[i];
                if (memcmp(intersection.second[i].data(), labels[idx].data(), labels[idx].size()))
                {
                    std::cout << Colors::Red << "incorrect label at index: " << i
                        << ". actual: " << print(intersection.second[i])
                        << ", expected: " << print(labels[i]) << std::endl << Colors::Reset;
                    correct = false;
                }
            }
        }
        else
        {
            if (intersection.first[i])
            {
                cout << Colors::Red << "Incorrect result for receiver's item at index: " << i << endl << Colors::Reset;
                correct = false;
            }
        }
    }

    cout << "Intersection results: ";

    if (correct)
        cout << Colors::Green << "Correct";

    else
        cout << Colors::Red << "Incorrect";

    cout << Colors::Reset << endl;
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

