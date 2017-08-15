#include "sender.h"
#include "apsi.h"
#include <iostream>
#include <string>
#include "Sender/sender.h"
#include "util/exring.h"
#include "apsidefines.h"
#include "Network/channel.h"
#include "Network/network_utils.h"

using namespace std;
using namespace apsi;
using namespace apsi::tools;
using namespace apsi::receiver;
using namespace apsi::sender;
using namespace seal::util;
using namespace seal;
using namespace apsi::network;

void print_example_banner(string title);
void example_remote();

int main(int argc, char *argv[])
{
    // Example: Basics
    example_remote();

    // Wait for ENTER before closing screen.
    cout << endl << "Press ENTER to exit" << endl;
    char ignore;
    cin.get(ignore);
    return 0;
}

void example_remote()
{
    print_example_banner("Example: Remote");
    stop_watch.time_points.clear();

    /* sender threads (8), table size (2^8=256), sender bin size (32), window size (2), splits (4). */
    PSIParams params(8, 8, 32, 2, 4);

    /*
    Item's bit length. In this example, we will only consider 32 bits of input items.
    If we use Item's string or pointer constructor, it means we only consider the first 32 bits of its hash;
    If we use Item's integer constructor, it means we only consider the first 32 bits of the integer.
    */
    params.set_item_bit_length(32);

    params.set_decomposition_bit_count(2);

    /* n = 2^11 = 2048, in SEAL's poly modulus "x^n + 1". */
    params.set_log_poly_degree(11);

    /* The prime p in ExRing. It is also the plain modulus in SEAL. */
    params.set_exring_characteristic(string("101"));

    /* f(x) in ExRing. It determines the generalized batching slots. */
    params.set_exring_polymod(string("1x^16 + 3"));

    /* SEAL's coefficient modulus q: when n = 2048, q has 60 bits. */
    params.set_coeff_mod_bit_count(60);

    params.validate();

    Sender sender(params, MemoryPoolHandle::acquire_new(true));
    Channel& server_channel = sender.connect();

    sender.load_db(vector<Item>{string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h")});
    stop_watch.set_time_point("Precomputation done");

    sender.query_engine(server_channel);
    stop_watch.set_time_point("Query done");

    server_channel.close();

    cout << stop_watch << endl;
}

void print_example_banner(string title)
{
    if (!title.empty())
    {
        size_t title_length = title.length();
        size_t banner_length = title_length + 2 + 2 * 10;
        string banner_top(banner_length, '*');
        string banner_middle = string(10, '*') + " " + title + " " + string(10, '*');

        cout << endl
            << banner_top << endl
            << banner_middle << endl
            << banner_top << endl
            << endl;
    }
}