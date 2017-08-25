// iDASH2017.cpp : Defines the entry point for the console application.
//

#include "center.h"
#include "psiparams.h"
#include "idashdefines.h"
#include "Network/boost_endpoint.h"
#include "Network/channel.h"

using namespace std;
using namespace idash;
using namespace apsi;
using namespace apsi::network;

PSIParams get_params();

int main()
{
    PSIParams params = get_params();

    auto center_thread = [&](int id)
    {
        Center center(id);
        center.load(string("C:/Users/t-zhh/Desktop/Task1/random-batch-sex-5per/file") + to_string(id));
        center.start();
    };

    auto server_thread = [&](int id, PSIParams local_params)
    {
        local_params.set_apsi_port(SERVER_APSI_PORTS[id]);
        Server server(id, local_params);
        server.start();

        if (id == NUM_SERVER - 1) /* Give token to server 0 to initiate the protocol. */
            server.pass_token();

        while(true)
            this_thread::sleep_for(chrono::seconds(5));
    };

    vector<thread> servers;
    for (int i = 0; i < NUM_SERVER; i++)
        servers.emplace_back(server_thread, i, params);

    vector<thread> centers;
    centers.emplace_back(thread(center_thread, 870));
    centers.emplace_back(thread(center_thread, 694));
    centers.emplace_back(thread(center_thread, 875));

    for (int i = 0; i < centers.size(); i++)
        centers[i].join();

    cin.get();
    return 0;
}

PSIParams get_params()
{
    PSIParams params(4, 4, 10, 40, 2, 8);

    /*
    Item's bit length. In this example, we will only consider 32 bits of input items.
    If we use Item's string or pointer constructor, it means we only consider the first 32 bits of its hash;
    If we use Item's integer constructor, it means we only consider the first 32 bits of the integer.
    */
    params.set_item_bit_length(80);

    params.set_decomposition_bit_count(2);

    /* n = 2^11 = 2048, in SEAL's poly modulus "x^n + 1". */
    params.set_log_poly_degree(11);

    /* The prime p in ExField. It is also the plain modulus in SEAL. */
    params.set_exfield_characteristic(0x101);

    /* f(x) in ExField. It determines the generalized batching slots. */
    params.set_exfield_polymod(string("1x^16 + 3"));

    /* SEAL's coefficient modulus q: when n = 2048, q has 60 bits. */
    params.set_coeff_mod_bit_count(60);

    params.validate();

    return params;
}

