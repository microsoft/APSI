#include "sender.h"

// STD
#include <iostream>
#include <string>

// APSI
#include "clp.h"
#include "apsi/sender/sender.h"
#include "apsi/network/channel.h"
#include "apsi/logging/log.h"
#include "common_utils.h"



using namespace std;
using namespace apsi;
using namespace apsi::tools;
using namespace apsi::sender;
using namespace apsi::network;
using namespace apsi::logging;


void example_remote(const CLP& cmd);
string get_bind_address(const CLP& cmd);


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

    Log::info("Building sender");

    PSIParams params = build_psi_params(cmd);
    Sender sender(params, cmd.threads(), cmd.threads());

    Log::info("Preparing sender DB");

    auto sender_size = 1 << cmd.sender_size();
    auto label_bit_length = cmd.use_labels() ? cmd.item_bit_length() : 0;

    vector<Item> items(sender_size);
    Matrix<u8> labels(sender_size, params.get_label_byte_count());

    for (int i = 0; i < items.size(); i++)
    {
        items[i] = i;

        if (label_bit_length) {
            memset(labels[i].data(), 0, labels[i].size());

            labels[i][0] = i;
            labels[i][1] = (i >> 8);
        }
    }

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
