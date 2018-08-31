// STD
#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>
#include <vector>
#include <set>

// APSI
#include "apsi/apsi.h"

// SEAL
#include "seal/seal.h"

// Networking
#include "zmqpp/zmqpp.hpp"
#include "apsi/network/channel.h"

// Command Line Processor
#include "clp.h"

#ifdef _MSC_VER
#include "windows.h"
#endif

using namespace std;
using namespace apsi;
using namespace apsi::tools;
using namespace apsi::receiver;
using namespace apsi::sender;
using namespace apsi::network;
using namespace seal::util;
using namespace seal;

namespace apsi { class CLP;  }

void print_example_banner(string title);
void print_parameters(const PSIParams &psi_params);
void example_basics();
void example_update();
void example_save_db();
void example_load_db();
void example_slow_batching(CLP& cmd, Channel& recvChl, Channel& sendChl);
void example_slow_vs_fast();
void example_remote();
void example_remote_multiple();

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

int round_up_to(int v, int s)
{
    return (v + s - 1) / s * s;
}

/**
 * This only turns on showing colors for Windows.
 */
void prepare_console()
{
#ifndef _MSC_VER
    return; // Nothing to do on Linux.
#else

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE)
        return;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hConsole, &dwMode))
        return;

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hConsole, dwMode);

#endif
}

void print_example_banner(string title)
{
    if (!title.empty())
    {
        size_t title_length = title.length();
        size_t banner_length = title_length + 2 + 2 * 10;
        string banner_top(banner_length, '*');
        string banner_middle = string(10, '*') + " " + title + " " + string(10, '*');

        std::cout << endl
            << banner_top << endl
            << banner_middle << endl
            << banner_top << endl
            << endl;
    }
}
 
std::pair<vector<Item>, vector<int>> randSubset(const vector<Item>& items, int size)
{
    PRNG prn(ZeroBlock);

    set<int> ss;
    while (ss.size() != size)
    {
        ss.emplace(prn.get<unsigned int>() % items.size());
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
    //// Example: Basics
    //example_basics();

    //// Example: Update
    //example_update();

    //// Example: Save and Load
    //example_save_db();
    //example_load_db();

    // Example: Slow batching
    example_slow_batching(cmd, clientChl, serverChl);

    // Example: Slow batching vs. Fast batching
    //example_slow_vs_fast();

    // Example: Remote connection
    //example_remote();

    // Example: Remote connection from multiple receivers
    //example_remote_multiple();

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

// void example_fast_batching(oc::CLP &cmd, Channel &recvChl, Channel &sendChl)
// {
//     print_example_banner("Example: Fast batching");
//     stop_watch.time_points.clear();
//
//     #<{(|
//     Use generalized batching in integer mode. This requires using an ExField with f(x) = x,
//     which makes ExField become an integer field. Then generalized batching is essentially
//     equivalent to SEAL's BatchEncoder, which is slightly faster due to David Harvey's
//     optimization of NTT butterfly operation on integers.
//
//     However, in this case, we can only use short PSI items such that the reduced item length
//     is smaller than bit length of 'p' in ExField (also the plain modulus in SEAL).
//     "Reduced item" refers to the permutation-based cuckoo hashing items.
//     |)}>#
//
//     // Thread count
//     unsigned numThreads = cmd.get<int>("t");
//
//     // Larger set size
//     unsigned sender_set_size = 1 << 20;
//
//     // Negative log failure probability for simple hashing
//     unsigned binning_sec_level = 10;
//
//     // Length of items
//     unsigned item_bit_length = 20;
//
//     // Cuckoo hash parameters
//     CuckooParams cuckoo_params;
//     {
//         // Use standard Cuckoo or PermutationBasedCuckoo
//         cuckoo_params.cuckoo_mode = cuckoo::CuckooMode::Normal;
//
//         // Cuckoo hash function count
//         cuckoo_params.hash_func_count = 3;
//
//         // Set the hash function seed
//         cuckoo_params.hash_func_seed = 0;
//
//         // Set max_probe count for Cuckoo hashing
//         cuckoo_params.max_probe = 100;
//     }
//
//     // Create TableParams and populate.    
//     TableParams table_params;
//     {
//         // Log of size of full hash table
//         table_params.log_table_size = 14;
//
//         // Number of splits to use
//         // Larger means lower depth but bigger S-->R communication
//         table_params.split_count = 256;
//
//         // Get secure bin size
//         table_params.sender_bin_size = round_up_to(get_bin_size(
//             1 << table_params.log_table_size,
//             sender_set_size * cuckoo_params.hash_func_count,
//             binning_sec_level),
//             table_params.split_count);
//
//         // Window size parameter
//         // Larger means lower depth but bigger R-->S communication
//         table_params.window_size = 1;
//     }
//
//     SEALParams seal_params;
//     {
//         seal_params.encryption_params.set_poly_modulus("1x^16384 + 1");
//         seal_params.encryption_params.set_coeff_modulus(
//             coeff_modulus_128(seal_params.encryption_params.poly_modulus_degree());
//         seal_params.encryption_params.set_plain_modulus(0x820001);
//
//         // This must be equal to plain_modulus
//         seal_params.exfield_params.exfield_characteristic = seal_params.encryption_params.plain_modulus().value();
//         seal_params.exfield_params.exfield_degree = 1;
//
//         seal_params.decomposition_bit_count = 60;
//     }
//
//     // Use OPRF to eliminate need for noise flooding for sender's security
//     auto oprf_type = OprfType::None;
//
//     #<{(|
//     Creating the PSIParams class.
//     |)}>#
//     PSIParams params(item_bit_length, table_params, cuckoo_params, seal_params, oprf_type);
//     {
//         params.set_value_bit_count(20);
//     }
//
//     // Check that the parameters are OK
//     params.validate();
//
//     // Set up receiver
//     Receiver receiver(params, 1, MemoryPoolHandle::New());
//     stop_watch.set_time_point("Receiver constructor");
//
//     // Set up sender
//     Sender sender(params, numThreads, numThreads, MemoryPoolHandle::New());
//     stop_watch.set_time_point("Sender constructor");
//
//     // For testing only insert a couple of elements in the sender's dataset
//     int sendersActualSize = 40;
//
//     // Sender's dataset
//     vector<Item> s1(sendersActualSize);
//     oc::Matrix<u8> labels(sendersActualSize, params.get_label_byte_count());
//     for (int i = 0; i < s1.size(); i++)
//     {
//         s1[i] = i;
//         memcpy(labels[i].data(), &s1[i], labels[i].size());
//         labels[i][4] ^= 0xcc;
//         //// Insert random string
//         //s1[i] = oc::mAesFixedKey.ecbEncBlock(oc::toBlock(i));
//     }
//
//     // Receiver's dataset
//     int receiversActualSize = 40;
//     int intersectionSize = 20;
//     int rem = receiversActualSize - intersectionSize;
//
//     #<{(|
//     Set receiver's dataset to be a random subset of sender's actual data
//     (this is where we get the intersection) and some data that won't match.
//     |)}>#
//
//     auto cc1 = randSubset(s1, intersectionSize);
//     auto& c1 = cc1.first;
//
//     c1.reserve(c1.size() + rem);
//     for (u64 i = 0; i < rem; i++)
//     {
//         c1.emplace_back(i + s1.size());
//         //// Insert random string
//         //c1.emplace_back(oc::mAesFixedKey.ecbEncBlock(oc::toBlock(i + s1.size()) & toBlock(0, -1)));
//     }
//
//     // We are done with constructing the datasets but no preprocessing done yet.
//     stop_watch.set_time_point("Application preparation");
//
//     // Now construct the sender's database
//     sender.load_db(s1, labels);
//     stop_watch.set_time_point("Sender pre-processing");
//
//     // Start the sender's query session in a separate thread
//     auto senderQuerySessionTh = thread([&]() {
//         sender.query_session(sendChl);
//     });
//
//     std::this_thread::sleep_for(std::chrono::seconds(1));
//
//     // Receiver's query
//     recv_stop_watch.set_time_point("recevier start");
//     auto intersection = receiver.query(c1, recvChl);
//     senderQuerySessionTh.join();
//
//
//     // Done with everything. Print the results!
//     bool correct = true;
//     for (int i = 0; i < c1.size(); i++)
//     {
//
//         if (i < intersectionSize)
//         {
//             if (intersection.first[i] == false)
//             {
//                 cout << "Miss result for receiver's item at index: " << i << endl;
//                 correct = false;
//             }
//             else
//             {
//                 u64 l = 0, exp = *(u64*)&c1[i];
//                 auto label = intersection.second[i];
//                 memcpy(&l, label.data(), label.size());
//
//
//                 if (l != exp)
//                 {
//                     std::cout << "incorrect label at index: " << i << ". actual: " << print(label) << " " << l << ", expected: " << exp << std::endl;
//                 }
//             }
//         }
//         else
//         {
//             if (intersection.first[i])
//             {
//                 cout << "Incorrect result for receiver's item at index: " << i << endl;
//                 correct = false;
//             }
//         }
//     }
//     cout << "Intersection results: " << (correct ? "Correct" : "Incorrect") << endl;
//
//     //cout << '[';
//     //for (int i = 0; i < intersection.size(); i++)
//     //    cout << intersection[i] << ", ";
//     //cout << ']' << endl;
//
//
//     #<{(| Test different update performance. |)}>#
//     #<{(|vector<int> updates{1, 10, 30, 50, 70, 100};
//     random_device rd;
//     for (int i = 0; i < updates.size(); i++)
//     {
//         vector<Item> items;
//         for (int j = 0; j < updates[i]; j++)
//             items.emplace_back(to_string(rd()));
//         sender.add_data(items);
//         sender.offline_compute();
//
//         stop_watch.set_time_point(string("Add ") + to_string(updates[i]) + " records done");
//     }|)}>#
//
//     cout << stop_watch << endl;
//     cout << recv_stop_watch << endl;
// }


void example_slow_batching(CLP& cmd, Channel& recvChl, Channel& sendChl)
{
    print_example_banner("Example: Slow batching");
    stop_watch.time_points.clear();

    // Thread count
    unsigned numThreads = cmd.threads();

    // Larger set size 
    unsigned sender_set_size = 1 << cmd.sender_size();

    // Negative log failure probability for simple hashing
    unsigned binning_sec_level = cmd.sec_level();

    // Length of items
    unsigned item_bit_length = cmd.item_bit_length();

    bool useLabels = cmd.use_labels();
    unsigned label_bit_length = useLabels ? item_bit_length : 0;

    // Cuckoo hash parameters
    CuckooParams cuckoo_params;
    {
        // Cuckoo hash function count
        cuckoo_params.hash_func_count = 3;

        // Set the hash function seed
        cuckoo_params.hash_func_seed = 0;

        // Set max_probe count for Cuckoo hashing
        cuckoo_params.max_probe = 100;

    }

    // Create TableParams and populate.    
    TableParams table_params;
    {
        // Log of size of full hash table
        table_params.log_table_size = cmd.log_table_size();

        // Number of splits to use
        // Larger means lower depth but bigger S-->R communication
        table_params.split_count = cmd.split_count();

        // Get secure bin size
        table_params.sender_bin_size = round_up_to(get_bin_size(
            1 << table_params.log_table_size,
            sender_set_size * cuckoo_params.hash_func_count,
            binning_sec_level),
            table_params.split_count);

        // Window size parameter
        // Larger means lower depth but bigger R-->S communication
        table_params.window_size = cmd.window_size();
    }

    SEALParams seal_params;
    {
        seal_params.encryption_params.set_poly_modulus_degree(cmd.poly_modulus());
        
        vector<SmallModulus> coeff_modulus;
        auto coeff_mod_bit_vector = cmd.coeff_modulus();

        if (coeff_mod_bit_vector.size() == 0)
        {
            coeff_modulus = coeff_modulus_128(seal_params.encryption_params.poly_modulus_degree());
        }
        else
        {
            unordered_map<int, size_t> mods_added;
            for(auto bit_size : coeff_mod_bit_vector)
            {
                switch(bit_size)
                {
                    case 30:
                        coeff_modulus.emplace_back(small_mods_30bit(mods_added[bit_size]));
                        mods_added[bit_size]++;
                        break;
                
                    case 40:
                        coeff_modulus.emplace_back(small_mods_40bit(mods_added[bit_size]));
                        mods_added[bit_size]++;
                        break;
                
                    case 50:
                        coeff_modulus.emplace_back(small_mods_50bit(mods_added[bit_size]));
                        mods_added[bit_size]++;
                        break;
                
                    case 60:
                        coeff_modulus.emplace_back(small_mods_60bit(mods_added[bit_size]));
                        mods_added[bit_size]++;
                        break;

                    default:
                        throw invalid_argument("invalid coeff modulus bit count");
                }
            }
        }
        seal_params.encryption_params.set_coeff_modulus(coeff_modulus);
        seal_params.encryption_params.set_plain_modulus(cmd.plain_modulus());

        // This must be equal to plain_modulus
        seal_params.exfield_params.exfield_characteristic = seal_params.encryption_params.plain_modulus().value();
        seal_params.exfield_params.exfield_degree = cmd.exfield_degree();
        seal_params.decomposition_bit_count = cmd.dbc();
    }

    // Use OPRF to eliminate need for noise flooding for sender's security
    auto oprf_type = OprfType::None;
    auto useOPRF = cmd.oprf();

    if (useOPRF)
    {
        oprf_type = OprfType::PK;
    }

    /*
    Creating the PSIParams class.
    */
    PSIParams params(item_bit_length, table_params, cuckoo_params, seal_params, oprf_type);
    params.set_value_bit_count(label_bit_length);
    // params.enable_debug();
    params.validate();

    std::unique_ptr<Receiver> receiver_ptr;

    int recThreads = cmd.rec_threads();

    // Check that number of blocks is not smaller than thread count
    if(max<int>(numThreads, recThreads) > params.split_count() * params.batch_count())
    {
        cout << "WARNING: Using too many threads for block count!" << endl;
    }

    auto f = std::async([&]() {receiver_ptr.reset(new Receiver(params, recThreads, MemoryPoolHandle::New())); });
    Sender sender(params, numThreads, numThreads, MemoryPoolHandle::New());
    f.get();
    Receiver& receiver = *receiver_ptr;

    //sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
    //sender.set_secret_key(receiver.secret_key());  // This should not be used in real application. Here we use it for outputing noise budget.

    auto sendersActualSize = sender_set_size;// 10000;// sender_set_size;
    auto recversActualSize = 50;
    auto intersectionSize = 25;

    auto s1 = vector<Item>(sendersActualSize);// { string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h") };
    Matrix<u8> labels(sendersActualSize, params.get_label_byte_count());
    for (int i = 0; i < s1.size(); i++)
    {
        s1[i] = i;

        if (label_bit_length) {
            //memcpy(labels[i].data(), &s1[i], labels[i].size());
            memset(labels[i].data(), 0, labels[i].size());

            labels[i][0] = i;
            labels[i][1] = (i >> 8);
            //labels[i][i% labels.cols()] = i;
            //labels[i][(i + 1) % labels.cols()] = (i>> 8);
            //labels[i][(i + 2) % labels.cols()] = 0xcc;

            //for (int j = 0; j < labels[i].size(); ++j)
            //{
            //    labels[i][j] ^= 0xcc ^ i;
            //}
        }
        //// Insert random string
        //s1[i] = oc::mAesFixedKey.ecbEncBlock(oc::toBlock(i));
    }

    auto cc1 = randSubset(s1, intersectionSize);
    auto& c1 = cc1.first;
    // for (int i = 0; i < c1.size(); ++i)
    //     if(label_bit_length)
    //         std::cout << "exp intersection[" << i << "] = s[" << cc1.second[i] << "] = " << s1[cc1.second[i]] << ", label = " << print(labels[cc1.second[i]]) << std::endl;
    //     else
    //         std::cout << "exp intersection[" << i << "] = s[" << cc1.second[i] << "] = " << s1[cc1.second[i]] << std::endl;

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
                //u64 l = 0, exp = *(u64*)&c1[i];
                //auto label = intersection.second[i];
                //memcpy(&l, label.data(), label.size());

                auto idx = cc1.second[i];
                //if (l != exp)
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
/*
    std::cout << "interp count: " << interp_count << std::endl;
    std::cout << "summ count:    " << sym_count << std::endl;*/
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



//void example_basics()
//{
//    print_example_banner("Example: Basics");
//    stop_watch.time_points.clear();
//
//    /* sender total threads (8), sender session threads (8), receiver threads (1),
//    table size (2^8=256), sender bin size (32), window size (2), splits (4). */
//    PSIParams params(8, 8, 1, 8, 32, 2, 4);
//
//    /* 
//    Item's bit length. In this example, we will only consider 32 bits of input items. 
//    If we use Item's string or pointer constructor, it means we only consider the first 32 bits of its hash;
//    If we use Item's integer constructor, it means we only consider the first 32 bits of the integer.
//    */
//    params.set_item_bit_length(32);  
//
//    params.set_decomposition_bit_count(2);
//
//    /* n = 2^11 = 2048, in SEAL's poly modulus "x^n + 1". */
//    params.set_log_poly_degree(11);
//
//    /* The prime p in ExField. It is also the plain modulus in SEAL. */
//    params.set_exfield_characteristic(0x101);
//
//    /* f(x) in ExField. It determines the generalized batching slots. */
//    params.set_exfield_polymod(string("1x^16 + 3"));
//
//    /* SEAL's coefficient modulus q: when n = 2048, q has 60 bits. */
//    params.set_coeff_mod_bit_count(60);
//
//    params.validate();
//
//    Receiver receiver(params, MemoryPoolHandle::New());
//
//    Sender sender(params, MemoryPoolHandle::New());
//    sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
//    sender.set_secret_key(receiver.secret_key());  // This should not be used in real application. Here we use it for outputing noise budget.
//    sender.load_db(vector<Item>{string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h")});
//    stop_watch.set_time_point("Precomputation done");
//
//    vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);
//    stop_watch.set_time_point("Query done");
//    cout << "Intersection result: ";
//    cout << '[';
//    for (int i = 0; i < intersection.size(); i++)
//        cout << intersection[i] << ", ";
//    cout << ']' << endl;
//
//	auto s1 = vector<Item>{ 10, 12, 89, 33, 123, 352, 4, 236 };
//	auto c1 = vector<Item>{ 78, 12, 84, 784, 3, 352 };
//
//    /* We can also use integers to construct the items.
//    In this example, because params set item bit length to be 32, it will only use the first 32 bits of the input integers. */
//    sender.load_db(s1);
//    stop_watch.set_time_point("Precomputation done");
//
//
//	auto thrd = thread([&]() {sender.query_session(sendChl); });
//    intersection = receiver.query(c1);
//    stop_watch.set_time_point("Query done");
//    cout << "Intersection result: ";
//    cout << '[';
//    for (int i = 0; i < intersection.size(); i++)
//        cout << intersection[i] << ", ";
//    cout << ']' << endl;
//
//    cout << stop_watch << endl;
//}

//void example_update()
//{
//    print_example_banner("Example: Update");
//    stop_watch.time_points.clear();
//
//    PSIParams params(8, 8, 1, 8, 32, 2, 4);
//    params.set_item_bit_length(32);
//    params.set_decomposition_bit_count(2);
//    params.set_log_poly_degree(11);
//    params.set_exfield_characteristic(0x101);
//    params.set_exfield_polymod(string("1x^16 + 3"));
//    params.set_coeff_mod_bit_count(60);  // SEAL param: when n = 2048, q has 60 bits.
//    params.validate();
//    Receiver receiver(params, MemoryPoolHandle::New());
//
//    Sender sender(params, MemoryPoolHandle::New());
//    sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
//    sender.set_secret_key(receiver.secret_key());
//    sender.load_db(vector<Item>{string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h")});
//    stop_watch.set_time_point("Precomputation done");
//
//    vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);
//    stop_watch.set_time_point("Query done");
//    cout << '[';
//    for (int i = 0; i < intersection.size(); i++)
//        cout << intersection[i] << ", ";
//    cout << ']' << endl;
//
//    /* Now we update the database, and precompute again. It should be faster because we only update a few stale blocks. */
//    sender.add_data(string("i"));
//    sender.add_data(string("h")); // duplicated item
//    sender.add_data(string("x"));
//    //sender.offline_compute();
//    stop_watch.set_time_point("Update done");
//
//    intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);
//    stop_watch.set_time_point("Query done");
//    cout << "Intersection result: ";
//    cout << '[';
//    for (int i = 0; i < intersection.size(); i++)
//        cout << intersection[i] << ", ";
//    cout << ']' << endl;
//
//    /* We can also delete items in the database. */
//    sender.delete_data(string("1")); // Item will be ignored if it doesn't exist in the database.
//    sender.delete_data(string("f"));
//    //sender.offline_compute();
//    stop_watch.set_time_point("Delete done");
//
//    intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);
//    stop_watch.set_time_point("Query done");
//    cout << "Intersection result: ";
//    cout << '[';
//    for (int i = 0; i < intersection.size(); i++)
//        cout << intersection[i] << ", ";
//    cout << ']' << endl;
//
//    cout << stop_watch << endl;
//}
//
//void example_save_db()
//{
//    print_example_banner("Example: Save DB");
//    stop_watch.time_points.clear();
//
//    PSIParams params(4, 4, 1, 14, 3584, 1, 256);
//    params.set_item_bit_length(32); // The effective item bit length will be limited by ExField's p.
//    params.set_exfield_polymod(string("1x^1")); // f(x) = x
//    params.set_exfield_characteristic(0x820001); // p = 8519681. NOTE: p=1 (mod 2n)
//    params.set_log_poly_degree(14); /* n = 2^14 = 16384, in SEAL's poly modulus "x^n + 1". */
//    params.set_coeff_mod_bit_count(226);  // SEAL param: when n = 16384, q has 189 or 226 bits.
//    params.set_decomposition_bit_count(46);
//    params.validate();
//
//    cout << "Reduced item bit length: " << params.reduced_item_bit_length() << endl;
//    cout << "Bit length of p: " << get_significant_bit_count(params.exfield_characteristic()) << endl;
//
//    if (params.reduced_item_bit_length() >= get_significant_bit_count(params.exfield_characteristic()))
//    {
//        cout << "Reduced items too long. We will only use the first " << get_significant_bit_count(params.exfield_characteristic()) - 1 << " bits." << endl;
//    }
//    else
//    {
//        cout << "All bits of reduced items are used." << endl;
//    }
//
//    Receiver receiver(params, MemoryPoolHandle::New());
//    Sender sender(params, MemoryPoolHandle::New());
//    sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
//    sender.set_secret_key(receiver.secret_key());  // This should not be used in real application. Here we use it for outputing noise budget.
//
//    stop_watch.set_time_point("Application preparation");
//    sender.load_db(vector<Item>{string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h")});
//    stop_watch.set_time_point("Sender pre-processing");
//
//    ofstream ofs("apsi.sender.db", ofstream::out | ofstream::binary); // Must use binary mode
//    sender.save_db(ofs);
//    ofs.close();
//    stop_watch.set_time_point("Sender DB saved");
//
//    cout << stop_watch << endl;
//}
//
//void example_load_db()
//{
//    print_example_banner("Example: Load DB");
//    stop_watch.time_points.clear();
//
//    PSIParams params(4, 4, 1, 14, 3584, 1, 256);
//    params.set_item_bit_length(32); // The effective item bit length will be limited by ExField's p.
//    params.set_exfield_polymod(string("1x^1")); // f(x) = x
//    params.set_exfield_characteristic(0x820001); // p = 8519681. NOTE: p=1 (mod 2n)
//    params.set_log_poly_degree(14); /* n = 2^14 = 16384, in SEAL's poly modulus "x^n + 1". */
//    params.set_coeff_mod_bit_count(226);  // SEAL param: when n = 16384, q has 189 or 226 bits.
//    params.set_decomposition_bit_count(46);
//    params.validate();
//
//    cout << "Reduced item bit length: " << params.reduced_item_bit_length() << endl;
//    cout << "Bit length of p: " << get_significant_bit_count(params.exfield_characteristic()) << endl;
//
//    if (params.reduced_item_bit_length() >= get_significant_bit_count(params.exfield_characteristic()))
//    {
//        cout << "Reduced items too long. We will only use the first " << get_significant_bit_count(params.exfield_characteristic()) - 1 << " bits." << endl;
//    }
//    else
//    {
//        cout << "All bits of reduced items are used." << endl;
//    }
//
//    Receiver receiver(params, MemoryPoolHandle::New());
//    Sender sender(params, MemoryPoolHandle::New());
//    sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
//    sender.set_secret_key(receiver.secret_key());  // This should not be used in real application. Here we use it for outputing noise budget.
//
//    stop_watch.set_time_point("Application preparation");
//
//    ifstream ifs("apsi.sender.db", ifstream::in | ifstream::binary); // Must use binary mode
//    sender.load_db(ifs);
//    ifs.close();
//    stop_watch.set_time_point("Sender DB loaded");
//
//    vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);
//
//    cout << "Intersection result: ";
//    cout << '[';
//    for (int i = 0; i < intersection.size(); i++)
//        cout << intersection[i] << ", ";
//    cout << ']' << endl;
//
//    /* Try update database. */
//    sender.delete_data(string("1")); // Item will be ignored if it doesn't exist in the database.
//    sender.delete_data(string("f"));
//    stop_watch.set_time_point("Delete done");
//
//    intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);
//    stop_watch.set_time_point("Query done");
//    cout << "Intersection result: ";
//    cout << '[';
//    for (int i = 0; i < intersection.size(); i++)
//        cout << intersection[i] << ", ";
//    cout << ']' << endl;
//
//    cout << stop_watch << endl;
//}


//
//void example_slow_vs_fast()
//{
//    print_example_banner("Example: Slow batching vs. Fast batching");
//    stop_watch.time_points.clear();
//
//    /* The slow batching case. We are using an ExField with f(x) of degree higher than 1, which results in fewer batching slots and thus 
//    potentially more batches to be processed. The following table size is 4096, number of batching slots is 512, hence we have 8 batches. 
//    In exchange, we could handle very long items. */
//    PSIParams params(8, 8, 1, 12, 128, 2, 8);
//    params.set_item_bit_length(90); // We can handle very long items in the following ExField.
//    params.set_exfield_polymod(string("1x^8 + 7"));  // f(x) = x^8 + 7
//    params.set_exfield_characteristic(0x3401); // p = 13313
//    params.set_log_poly_degree(12);
//    params.set_coeff_mod_bit_count(116);  // SEAL param: when n = 4096, q has 116 bits.
//    params.validate();
//
//    cout << "Reduced item bit length: " << params.reduced_item_bit_length() << endl;
//    cout << "Bit length of p: " << get_significant_bit_count(params.exfield_characteristic()) << endl;
//
//    if (params.reduced_item_bit_length() > 
//        (get_significant_bit_count(params.exfield_characteristic()) - 1) * (params.exfield_polymod().coeff_count() - 1))
//    {
//        cout << "Reduced items too long. We will only use the first " 
//            << (get_significant_bit_count(params.exfield_characteristic()) - 1) * (params.exfield_polymod().coeff_count() - 1) << " bits." << endl;
//    }
//    else
//    {
//        cout << "All bits of reduced items are used." << endl;
//    }
//
//    Receiver receiver(params, MemoryPoolHandle::New());
//    Sender sender(params, MemoryPoolHandle::New());
//    sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
//    sender.load_db(vector<Item>{string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h")});
//
//    vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);
//
//    cout << "First Intersection result: ";
//    cout << '[';
//    for (int i = 0; i < intersection.size(); i++)
//        cout << intersection[i] << ", ";
//    cout << ']' << endl;
//    stop_watch.set_time_point("PSI with slow batching done.");
//    
//    /* The fast batching case. The table size is 4096, and the batching slots are also 4096, hence we only have one batch. */
//    PSIParams params2(8, 8, 1, 12, 128, 2, 8);
//    params2.set_item_bit_length(90); // The effective item bit length will be limited by ExField's p.
//    params2.set_exfield_polymod(string("1x^1")); // f(x) = x
//    params2.set_exfield_characteristic(0xA001); // p = 40961. NOTE: p=1 (mod 2n)
//    params2.set_log_poly_degree(12);
//    params2.set_coeff_mod_bit_count(116);  // SEAL param: when n = 4096, q has 116 bits.
//    params2.validate();
//
//    cout << "Reduced item bit length: " << params2.reduced_item_bit_length() << endl;
//    cout << "Bit length of p: " << get_significant_bit_count(params2.exfield_characteristic()) << endl;
//
//    if (params2.reduced_item_bit_length() >= get_significant_bit_count(params2.exfield_characteristic()))
//    {
//        cout << "Reduced items too long. We will only use the first " << get_significant_bit_count(params2.exfield_characteristic()) - 1 << " bits." << endl;
//    }
//    else
//    {
//        cout << "All bits of reduced items are used." << endl;
//    }
//
//    Receiver receiver2(params2, MemoryPoolHandle::New());
//    Sender sender2(params2, MemoryPoolHandle::New());
//    sender2.set_keys(receiver2.public_key(), receiver2.evaluation_keys());
//    sender2.load_db(vector<Item>{string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h")});
//
//    vector<bool> intersection2 = receiver2.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender2);
//
//    cout << "Second Intersection result: ";
//    cout << '[';
//    for (int i = 0; i < intersection2.size(); i++)
//        cout << intersection2[i] << ", ";
//    cout << ']' << endl;
//    stop_watch.set_time_point("PSI with fast batching done.");
//
//    cout << stop_watch << endl;
//}
//
//void example_remote()
//{
//    print_example_banner("Example: Remote");
//    stop_watch.time_points.clear();
//
//    /* sender total threads (8), sender session threads (4), receiver threads (1)
//    table size (2^8=256), sender bin size (32), window size (2), splits (4). */
//    PSIParams params(8, 4, 1, 8, 32, 2, 4);
//
//    /*
//    Item's bit length. In this example, we will only consider 32 bits of input items.
//    If we use Item's string or pointer constructor, it means we only consider the first 32 bits of its hash;
//    If we use Item's integer constructor, it means we only consider the first 32 bits of the integer.
//    */
//    params.set_item_bit_length(32);
//
//    params.set_decomposition_bit_count(2);
//
//    /* n = 2^11 = 2048, in SEAL's poly modulus "x^n + 1". */
//    params.set_log_poly_degree(11);
//
//    /* The prime p in ExField. It is also the plain modulus in SEAL. */
//    params.set_exfield_characteristic(0x101);
//
//    /* f(x) in ExField. It determines the generalized batching slots. */
//    params.set_exfield_polymod(string("1x^16 + 3"));
//
//    /* SEAL's coefficient modulus q: when n = 2048, q has 60 bits. */
//    params.set_coeff_mod_bit_count(60);
//
//    params.validate();
//
//    Receiver receiver(params, MemoryPoolHandle::New());
//
//    vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, "127.0.0.1", params.apsi_port());
//    stop_watch.set_time_point("Query done");
//    cout << "Intersection result: ";
//    cout << '[';
//    for (int i = 0; i < intersection.size(); i++)
//        cout << intersection[i] << ", ";
//    cout << ']' << endl;
//
//    cout << stop_watch << endl;
//}
//
//void example_remote_multiple()
//{
//    print_example_banner("Example: Remote multiple");
//    stop_watch.time_points.clear();
//
//    /* sender total threads (8), sender session threads (4), receiver threads (1)
//    table size (2^8=256), sender bin size (32), window size (2), splits (4). */
//    PSIParams params(8, 4, 1, 8, 32, 2, 4);
//
//    /*
//    Item's bit length. In this example, we will only consider 32 bits of input items.
//    If we use Item's string or pointer constructor, it means we only consider the first 32 bits of its hash;
//    If we use Item's integer constructor, it means we only consider the first 32 bits of the integer.
//    */
//    params.set_item_bit_length(32);
//
//    params.set_decomposition_bit_count(2);
//
//    /* n = 2^11 = 2048, in SEAL's poly modulus "x^n + 1". */
//    params.set_log_poly_degree(11);
//
//    /* The prime p in ExField. It is also the plain modulus in SEAL. */
//    params.set_exfield_characteristic(0x101);
//
//    /* f(x) in ExField. It determines the generalized batching slots. */
//    params.set_exfield_polymod(string("1x^16 + 3"));
//
//    /* SEAL's coefficient modulus q: when n = 2048, q has 60 bits. */
//    params.set_coeff_mod_bit_count(60);
//
//    params.validate();
//
//    mutex mtx;
//
//    auto receiver_connection = [&](int id)
//    {
//        Receiver receiver(params, MemoryPoolHandle::New());
//        stop_watch.set_time_point("[Receiver " + to_string(id) + "] Initialization done");
//
//        vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, "127.0.0.1", params.apsi_port());
//        stop_watch.set_time_point("[Receiver " + to_string(id) + "] Query done");
//        mtx.lock();
//        cout << "[Receiver " << id << "] Intersection result: ";
//        cout << '[';
//        for (int i = 0; i < intersection.size(); i++)
//            cout << intersection[i] << ", ";
//        cout << ']' << endl;
//        mtx.unlock();
//    };
//
//    int receiver_count = 3;
//    vector<thread> receiver_pool;
//    for (int i = 0; i < receiver_count; i++)
//    {
//        receiver_pool.emplace_back(receiver_connection, i);
//    }
//
//    for (int i = 0; i < receiver_count; i++)
//        receiver_pool[i].join();
//
//    cout << stop_watch << endl;
//}
 
