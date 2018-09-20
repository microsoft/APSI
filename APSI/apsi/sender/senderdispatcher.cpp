
// STD
#include <sstream>
#include <memory>

// APSI
#include "apsi/sender/senderdispatcher.h"
#include "apsi/network/channel.h"
#include "apsi/logging/log.h"

// ZeroMQ
#pragma warning(push, 0)
#include "zmqpp/zmqpp.hpp"
#pragma warning(pop)


using namespace std;
using namespace apsi;
using namespace apsi::sender;
using namespace apsi::network;
using namespace apsi::logging;


void SenderDispatcher::run(const atomic<bool>& stop, int port)
{
    zmqpp::context_t zmqcontext;
    Channel channel(zmqcontext);

    stringstream ss;
    ss << "tcp://*:" << port;

    Log::info("Sender binding to address: %s", ss.str().c_str());
    channel.bind(ss.str());

    // Run until stopped
    while (!stop)
    {
        shared_ptr<SenderOperation> sender_op;
        channel.receive(sender_op);

        if (sender_op == nullptr)
        {
            // Receive timed out.
            continue;
        }

        switch (sender_op->type)
        {
        case SOP_get_parameters:
            DispatchGetParameters(sender_op);
            break;

        case SOP_preprocess:
            DispatchPreprocess(sender_op);
            break;

        case SOP_query:
            DispatchQuery(sender_op);
            break;

        default:
            Log::error("Invalid Sender Operation: %i", sender_op->type);
        }
    }
}
