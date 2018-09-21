
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
        if (!channel.receive(sender_op))
        {
            this_thread::sleep_for(100ms);
            continue;
        }

        if (sender_op == nullptr)
        {
            // Receive timed out.
            continue;
        }

        switch (sender_op->type)
        {
        case SOP_get_parameters:
            dispatch_get_parameters(sender_op, channel);
            break;

        case SOP_preprocess:
            dispatch_preprocess(sender_op, channel);
            break;

        case SOP_query:
            dispatch_query(sender_op, channel);
            break;

        default:
            Log::error("Invalid Sender Operation: %i", sender_op->type);
        }
    }
}

void SenderDispatcher::dispatch_get_parameters(shared_ptr<SenderOperation> sender_op, Channel& channel)
{
    channel.send_get_parameters_response(sender_->get_params());
}

void SenderDispatcher::dispatch_preprocess(shared_ptr<SenderOperation> sender_op, Channel& channel)
{
    auto preprocess_op = reinterpret_cast<SenderOperationPreprocess*>(&sender_op);
    
    sender_->preprocess(preprocess_op->buffer);
    channel.send_preprocess_response(preprocess_op->buffer);
}

void SenderDispatcher::dispatch_query(shared_ptr<SenderOperation> sender_op, Channel& channel)
{
    auto query_op = reinterpret_cast<SenderOperationQuery*>(&sender_op);

    //sender_->query(
    //    query_op->public_key,
    //    query_op->relin_keys,
    //    query_op->query);
}