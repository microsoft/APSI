// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <memory>
#include <cstddef>
#include <atomic>
#include <thread>
#include <utility>

// APSI
#include "apsi/receiver.h"
#include "apsi/network/network_channel.h"

#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::network;
using namespace apsi::receiver;
using namespace seal;

namespace APSITests
{
    namespace
    {
        SenderChannel server_;
        ReceiverChannel client_;

        shared_ptr<PSIParams> get_params()
        {
            static shared_ptr<PSIParams> params = nullptr;
            if (!params)
            {
                PSIParams::ItemParams item_params;
                item_params.felts_per_item = 8;

                PSIParams::TableParams table_params;
                table_params.hash_func_count = 3;
                table_params.max_items_per_bin = 16;
                table_params.table_size = 512;
                table_params.window_size = 1;

                size_t pmd = 4096;
                PSIParams::SEALParams seal_params(scheme_type::BFV);
                seal_params.set_poly_modulus_degree(pmd);
                seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
                seal_params.set_plain_modulus(65537);

                params = make_shared<PSIParams>(item_params, table_params, seal_params);
            }

            return params;
        }

        shared_ptr<CryptoContext> get_context()
        {
            static shared_ptr<CryptoContext> context = nullptr;
            if (!context)
            {
                context = make_shared<CryptoContext>(SEALContext::Create(get_params()->seal_params()));
                KeyGenerator keygen(context->seal_context());
                context->set_secret(keygen.secret_key());
                context->set_evaluator(keygen.relin_keys_local());
            }

            return context;
        }
    } // namespace

    class ReceiverTests : public ::testing::Test
    {
    protected:
        ReceiverTests()
        {
            if (!server_.is_connected())
            {
                server_.bind("tcp://*:5555");
            }

            if (!client_.is_connected())
            {
                client_.connect("tcp://localhost:5555");
            }
        }

        void start_listen()
        {
            th_ = thread([this]() {
                // Run until stopped
                while (!stop_token_)
                {
                    unique_ptr<NetworkSenderOperation> sop;
                    if (!(sop = server_.receive_network_operation(get_context()->seal_context())))
                    {
                        this_thread::sleep_for(50ms);
                        continue;
                    }

                    switch (sop->sop->type())
                    {
                    case SenderOperationType::SOP_PARMS:
                        dispatch_parms(move(sop));
                        break;

                    case SenderOperationType::SOP_OPRF:
                        dispatch_oprf(move(sop));
                        break;

                    case SenderOperationType::SOP_QUERY:
                        dispatch_query(move(sop));
                        break;

                    default:
                        // We should never reach this point
                        throw runtime_error("invalid operation");
                    }
                }
            });
        }

        void dispatch_parms(unique_ptr<NetworkSenderOperation> sop)
        {
            // Handle parms request by responding with the default parameters
            auto response_parms = make_unique<SenderOperationResponseParms>();
            response_parms->params = make_unique<PSIParams>(*get_params());
            auto response = make_unique<NetworkSenderOperationResponse>();
            response->sop_response = move(response_parms);
            response->client_id = move(sop->client_id);

            server_.send(move(response));
        }

        void dispatch_oprf(unique_ptr<NetworkSenderOperation> sop)
        {
            auto sop_oprf = dynamic_cast<SenderOperationOPRF*>(sop->sop.get());

            // Respond with exactly the same data we received 
            auto response_oprf = make_unique<SenderOperationResponseOPRF>();
            response_oprf->data = sop_oprf->data;
            auto response = make_unique<NetworkSenderOperationResponse>();
            response->sop_response = move(response_oprf);
            response->client_id = move(sop->client_id);

            server_.send(move(response));
        }

        void dispatch_query(unique_ptr<NetworkSenderOperation> sop)
        {
            auto sop_query = dynamic_cast<SenderOperationQuery*>(sop->sop.get());

            // We'll return 3 packages for no particular reason
            uint32_t package_count = 3; 

            auto response_query = make_unique<SenderOperationResponseQuery>();
            response_query->package_count = package_count;
            auto response = make_unique<NetworkSenderOperationResponse>();
            response->sop_response = move(response_query);
            response->client_id = sop->client_id;

            server_.send(move(response));

            // Query will send result to client in a stream of ResultPackages
            auto send_nrp = [&](uint32_t bundle_idx) {
                auto rp = make_unique<ResultPackage>();
                rp->bundle_idx = 0;
                rp->psi_result = get_context()->encryptor()->encrypt_zero_symmetric();
                auto nrp = make_unique<NetworkResultPackage>();
                nrp->rp = move(rp);
                nrp->client_id = sop->client_id;
                server_.send(move(nrp));
            };

            // Send the first one with bundle_idx 0, second with 1, and third again with 0
            send_nrp(0);
            send_nrp(1);
            send_nrp(0);
        }

        void stop_listen()
        {
            stop_token_ = true;
            if (th_.joinable())
            {
                th_.join();
            }
        }

        ~ReceiverTests()
        {
            stop_listen();

            // Do not disconnect, as the Constructor / Destructor is called for every test.
            // if (client_.is_connected())
            //	client_.disconnect();

            // if (server_.is_connected())
            //	server_.disconnect();
        }

    private:
        thread th_;

        atomic<bool> stop_token_ = false;
    };

    TEST(ReceiverTests, Constructor)
    {
        // Parameterless constructors
        ASSERT_NO_THROW(auto recv = Receiver(1));
        ASSERT_NO_THROW(auto recv = Receiver(2));

        // Cannot specify zero threads
        ASSERT_THROW(auto recv = Receiver(0), invalid_argument);

        // Parametered constructors
        ASSERT_NO_THROW(auto recv = Receiver(*get_params(), 1));
        ASSERT_NO_THROW(auto recv = Receiver(*get_params(), 2));
    }

    TEST_F(ReceiverTests, SingleThread)
    {
        start_listen();

        Receiver recv(*get_params(), 1);
        ASSERT_TRUE(recv.is_initialized());

        vector<Item> items;
        recv.query(items, client_);

        stop_listen();
    }
}
