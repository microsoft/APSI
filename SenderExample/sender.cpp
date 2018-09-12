#include "sender.h"

// STD
#include <iostream>
#include <fstream>
#include <string>

// APSI
#include "clp.h"
#include "apsi/sender/sender.h"
#include "apsi/network/channel.h"
#include "apsi/logging/log.h"
#include "apsi/tools/csvreader.h"
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

    // Example: Remote
    example_remote(cmd);
}

void example_remote(const CLP& cmd)
{
    print_example_banner("Remote Sender");

    PSIParams params = build_psi_params(cmd);

    Log::info("Preparing sender DB");

    vector<Item> items;
    Matrix<u8> labels;

    initialize_db(cmd, items, labels);
    params.set_sender_set_size(items.size());

    Log::info("Building sender");
    Sender sender(params, cmd.threads(), cmd.threads());

    Log::info("Sender loading DB");
    sender.load_db(items, labels);

    zmqpp::context_t context;
    Channel channel(context);

    string bind_addr = get_bind_address(cmd);
    Log::info("Binding to address: %s", bind_addr.c_str());
    channel.bind(bind_addr);

    // Sender will run forever.
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
    auto sender_size = 1 << cmd.sender_size();
    auto label_bit_length  = cmd.use_labels() ? cmd.item_bit_length() : 0;
    auto label_byte_length = (label_bit_length + 7) / 8;

    if (cmd.db_file().empty())
    {
        items.resize(sender_size);
        labels.resize(sender_size, label_byte_length);

        for (int i = 0; i < items.size(); i++)
        {
            items[i] = i;

            if (label_bit_length) {
                memset(labels[i].data(), 0, labels[i].size());

                labels[i][0] = i;
                labels[i][1] = (i >> 8);
            }
        }
    }
    else
    {
        CsvReader reader(cmd.db_file());
        reader.read(items, labels, label_byte_length);
    }
}
