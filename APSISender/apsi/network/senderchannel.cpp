// APSI
#include "apsi/network/senderchannel.h"

// ZeroMQ
#pragma warning(push, 0)
#include "zmqpp/zmqpp.hpp"
#pragma warning(pop)


using namespace apsi;
using namespace apsi::network;


zmqpp::socket_type SenderChannel::get_socket_type()
{
	return zmqpp::socket_type::router;
}
