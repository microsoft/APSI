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
using namespace seal::util;
using namespace seal;

void example_slow_batching(CLP& cmd, Channel& recvChl, Channel& sendChl);

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

std::pair<vector<Item>, vector<int>> randSubset(const vector<Item>& items, int size)
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

    zmqpp::context_t context;

    Channel clientChl(context);
    Channel serverChl(context);

    serverChl.bind("tcp://*:1212");
    clientChl.connect("tcp://localhost:1212");

    prepare_console();

    // Example: Slow batching
    example_slow_batching(cmd, clientChl, serverChl);

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

void example_slow_batching(CLP& cmd, Channel& recvChl, Channel& sendChl)
{
    print_example_banner("Example: Slow batching");
    stop_watch.time_points.clear();

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

    auto s1 = vector<Item>(sendersActualSize);// { string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h") };
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

    auto cc1 = randSubset(s1, intersectionSize);
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
    bool correct = true;
    for (int i = 0; i < c1.size(); i++)
    {

        if (i < intersectionSize)
        {
            if (intersection.first[i] == false)
            {
                cout << "Miss result for receiver's item at index: " << i << endl;
                correct = false;
            }
            else if(label_bit_length)
            {
                auto idx = cc1.second[i];
                if(memcmp(intersection.second[i].data(), labels[idx].data(), labels[idx].size()))
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

    cout << stop_watch << endl;
    cout << recv_stop_watch << endl;

    cout << "Communication R->S: " << recvChl.get_total_data_sent() / 1024.0 << " KB" << endl;
    cout << "Communication S->R: " << recvChl.get_total_data_received() / 1024.0 << " KB" << endl;
    cout << "Communication total: " << (recvChl.get_total_data_sent() + recvChl.get_total_data_received()) / 1024.0 << " KB" << endl;
}
