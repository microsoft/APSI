
// STD
#include <sstream>
#include <memory>

// APSI
#include "apsi/sender/senderdispatcher.h"
#include "apsi/network/senderchannel.h"
#include "apsi/network/network_utils.h"
#include "apsi/logging/log.h"

// SEAL
#include "seal/publickey.h"
#include "seal/relinkeys.h"


using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::sender;
using namespace apsi::network;
using namespace apsi::logging;


void SenderDispatcher::run(const atomic<bool>& stop, const int port)
{
    SenderChannel channel;

    stringstream ss;
    ss << "tcp://*:" << port;

    Log::info("Sender binding to address: %s", ss.str().c_str());
    channel.bind(ss.str());

    bool logged_waiting = false;

    // Run until stopped
    while (!stop)
    {
        shared_ptr<SenderOperation> sender_op;

        if (!channel.receive(sender_op))
        {
            if (!logged_waiting)
            {
                // We want to log 'Waiting' only once, even if we have to wait
                // for several sleeps. And only once after processing a request as well.
                logged_waiting = true;
                Log::info("Waiting for request.");
            }

            this_thread::sleep_for(50ms);
            continue;
        }

        switch (sender_op->type)
        {
        case SOP_get_parameters:
            Log::info("Received Get Parameters request");
            dispatch_get_parameters(sender_op, channel);
            break;

        case SOP_preprocess:
            Log::info("Received Preprocess request");
            dispatch_preprocess(sender_op, channel);
            break;

        case SOP_query:
            Log::info("Received Query request");
            dispatch_query(sender_op, channel);
            break;

        default:
            Log::error("Invalid Sender Operation: %i", sender_op->type);
        }

        logged_waiting = false;
    }
}

void SenderDispatcher::dispatch_get_parameters(shared_ptr<SenderOperation> sender_op, Channel& channel)
{
    // No need to cast to SenderOperationGetParameters, we just need the client_id.
    channel.send_get_parameters_response(sender_op->client_id, sender_->get_params());
}

void SenderDispatcher::dispatch_preprocess(shared_ptr<SenderOperation> sender_op, Channel& channel)
{
    auto preprocess_op = dynamic_pointer_cast<SenderOperationPreprocess>(sender_op);
    
    sender_->preprocess(preprocess_op->buffer);
    channel.send_preprocess_response(sender_op->client_id, preprocess_op->buffer);
}

void SenderDispatcher::dispatch_query(shared_ptr<SenderOperation> sender_op, Channel& channel)
{
    auto query_op = dynamic_pointer_cast<SenderOperationQuery>(sender_op);
    PublicKey pub_key;
    RelinKeys relin_keys;

    get_public_key(pub_key, query_op->public_key);
    get_relin_keys(relin_keys, query_op->relin_keys);

    // The query response will tell the Receiver how many ResultPackages to expect
    size_t package_count = sender_->get_params().batch_count() * sender_->get_params().split_count();
    channel.send_query_response(sender_op->client_id, package_count);

    // Query will send result to client in a stream of ResultPackages
    sender_->query(
        pub_key,
        relin_keys,
        query_op->query,
        sender_op->client_id,
        channel);
}
