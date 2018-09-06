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

namespace apsi { class CLP;  }

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
        table_params.sender_bin_size = round_up_to(
            static_cast<unsigned>(get_bin_size(
            1ull << table_params.log_table_size,
            sender_set_size * cuckoo_params.hash_func_count,
            binning_sec_level)),
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
            unordered_map<u64, size_t> mods_added;
            for(auto bit_size : coeff_mod_bit_vector)
            {
                switch(bit_size)
                {
                    case 30:
                        coeff_modulus.emplace_back(small_mods_30bit(static_cast<int>(mods_added[bit_size])));
                        mods_added[bit_size]++;
                        break;
                
                    case 40:
                        coeff_modulus.emplace_back(small_mods_40bit(static_cast<int>(mods_added[bit_size])));
                        mods_added[bit_size]++;
                        break;
                
                    case 50:
                        coeff_modulus.emplace_back(small_mods_50bit(static_cast<int>(mods_added[bit_size])));
                        mods_added[bit_size]++;
                        break;
                
                    case 60:
                        coeff_modulus.emplace_back(small_mods_60bit(static_cast<int>(mods_added[bit_size])));
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

    auto f = std::async([&]()
    {
        receiver_ptr = make_unique<Receiver>(params, recThreads, MemoryPoolHandle::New());
    });
    Sender sender(params, numThreads, numThreads, MemoryPoolHandle::New());
    f.get();
    Receiver& receiver = *receiver_ptr;

    auto sendersActualSize = sender_set_size;
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
