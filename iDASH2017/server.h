#pragma once

#include <deque>
#include "Network/channel.h"
#include "item.h"
#include "Sender/sender.h"
#include "Receiver/receiver.h"
#include "psiparams.h"
#include <set>

namespace idash
{
    class Server
    {
    public:
        Server(int id, const apsi::PSIParams &params);

        ~Server();

        void start();

        void stop();

        void data_engine();

        void collect(apsi::network::Channel &channel);

        void token_ring_engine();

        void pass_token();

        void psi_sender_engine();

        void psi_receiver_engine();

        void sharing_engine();


    private:
        int id_;

        std::set<std::string> record_ids_;

        std::deque<std::tuple<apsi::network::Channel*, std::vector<std::string>, std::vector<apsi::Item>>> req_queue_;

        apsi::network::BoostIOService ios_;

        apsi::network::BoostEndpoint data_endpoint_;

        apsi::network::BoostEndpoint token_endpoint_;

        apsi::network::BoostEndpoint sharing_endpoint_;

        apsi::sender::Sender sender_;

        apsi::receiver::Receiver receiver_;

        std::vector<std::thread> workers_;

        volatile bool has_token_;

        bool stopped;

        int request_count = 0;
    };
}