// APSI
#include "apsi/network/receiverchannel.h"

// ZeroMQ
#pragma warning(push, 0)
#include "zmqpp/zmqpp.hpp"
#pragma warning(pop)


using namespace apsi;
using namespace apsi::network;


zmqpp::socket_type ReceiverChannel::get_socket_type()
{
    return zmqpp::socket_type::dealer;
}

void ReceiverChannel::set_socket_options(zmqpp::socket_t* socket)
{
	// Ensure messages are not dropped
	socket->set(zmqpp::socket_option::receive_high_water_mark, 32768);
}
