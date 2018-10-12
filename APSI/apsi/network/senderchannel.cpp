// APSI
#include "apsi/network/senderchannel.h"

// ZeroMQ
#pragma warning(push, 0)
#include "zmqpp/zmqpp.hpp"
#pragma warning(pop)


using namespace apsi;
using namespace apsi::network;


SenderChannel::SenderChannel(const zmqpp::context_t& context)
    : Channel(context)
{
}

zmqpp::socket_type SenderChannel::get_socket_type()
{
    return zmqpp::socket_type::router;
}
