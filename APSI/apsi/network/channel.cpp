#include "channel.h"
#include "zmqpp/zmqpp.hpp"

using namespace std;
using namespace apsi;
using namespace apsi::network;
using namespace zmqpp;

Channel::Channel(const context_t& context)
    : bytes_sent_(0),
      bytes_received_(0),
      socket_(nullptr)
{
}
