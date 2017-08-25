#include "server.h"
#include "idashdefines.h"
#include <thread>
#include "Network/network_utils.h"
#include "memorypoolhandle.h"

using namespace std;
using namespace apsi;
using namespace apsi::network;
using namespace apsi::sender;
using namespace apsi::receiver;
using namespace seal;

namespace idash
{
    Server::Server(int id, const PSIParams &params)
        :id_(id), ios_(0), data_endpoint_(ios_, "127.0.0.1", SERVER_DATA_PORTS[id], true, DATA_ENDPOINT),
        token_endpoint_(ios_, "127.0.0.1", SERVER_TOKEN_PORTS[id], true, TOKEN_ENDPOINT),
        sharing_endpoint_(ios_, "127.0.0.1", SERVER_SHARING_PORTS[id], true, SHARING_ENDPOINT),
        sender_(params, MemoryPoolHandle::acquire_new(true)), receiver_(params, MemoryPoolHandle::acquire_new(true)),
        stopped(false), has_token_(false)
    {
        if (id_ < 0 || id_ >= NUM_SERVER)
            throw invalid_argument("Invalid server id.");
        
    }

    Server::~Server()
    {
        stop();
        data_endpoint_.stop();
    }

    void Server::start()
    {
        workers_.emplace_back(thread(&Server::data_engine, this));
        workers_.emplace_back(thread(&Server::psi_sender_engine, this));
        workers_.emplace_back(thread(&Server::psi_receiver_engine, this));
        workers_.emplace_back(thread(&Server::token_ring_engine, this));
    }

    void Server::stop()
    {
        sender_.stop();
        stopped = true;
        
        for (int i = 0; i < workers_.size(); i++)
            workers_[i].join();
    }

    void Server::data_engine()
    {
        while (true && !stopped)
        {
            Channel* data_channel = data_endpoint_.getNextQueuedChannel();
            if (data_channel == nullptr)
            {
                this_thread::sleep_for(chrono::milliseconds(50));
                continue;
            }

            collect(*data_channel);
            cout << string("[Server ") + to_string(id_) + "] Received request. [Total: " + to_string(++request_count) + ", Pending: " + to_string(req_queue_.size()) + "]" << endl;
        }
        data_endpoint_.stop();
    }

    void Server::collect(apsi::network::Channel &channel)
    {
        int size = 0;
        receive_int(size, channel);
        vector<string> batch_ids(size);
        vector<Item> batch_items(size);
        for (int i = 0; i < size; i++)
        {
            receive_string(batch_ids[i], channel);
            receive_item(batch_items[i], channel);
        }
        req_queue_.push_back(make_tuple(&channel, std::move(batch_ids), std::move(batch_items)));
    }

    void Server::token_ring_engine()
    {
        string token;
        while (true && !stopped)
        {
            Channel* token_channel = token_endpoint_.getNextQueuedChannel();
            if (token_channel == nullptr)
            {
                this_thread::sleep_for(chrono::milliseconds(50));
                continue;
            }
            receive_string(token, *token_channel);
            token_channel->close();

            if (token != TOKEN)
                throw runtime_error("Invalid token.");
            has_token_ = true;
            while (has_token_)
            {
                this_thread::sleep_for(chrono::milliseconds(50));
            }
        }
        token_endpoint_.stop();
    }

    void Server::pass_token()
    {
        int next_id = (id_ + 1) % NUM_SERVER;
        /* Pass the token to the next server. */
        BoostEndpoint client(ios_, SERVER_IPS[next_id], SERVER_TOKEN_PORTS[next_id], false, TOKEN_ENDPOINT);
        Channel& client_channel = client.addChannel("-", "-");
        send_string(TOKEN, client_channel);
        
        client_channel.close();
        client.stop();
        has_token_ = false;

        cout << string("[Server ") + to_string(id_) + "] Passed token to server " + to_string(next_id) + ". [Total: " + to_string(request_count) + ", Pending: " + to_string(req_queue_.size()) + "]" << endl;
    }

    void Server::psi_sender_engine()
    {
        sender_.clear_sender_db();
        sender_.offline_compute();

        /* Sharing channel. */
        int next_id = (id_ + 1) % NUM_SERVER;
        BoostEndpoint sharing_endpoint(ios_, SERVER_IPS[next_id], SERVER_SHARING_PORTS[next_id], false, SHARING_ENDPOINT);

        sender_.query_engine(&sharing_endpoint, true);

        sharing_endpoint.stop();
    }

    void Server::psi_receiver_engine()
    {
        while (true && !stopped)
        {
            if (req_queue_.empty() || !has_token_)
            {
                if (has_token_) /* If there is no pending requests on this server, release the token. */
                    pass_token();
                this_thread::sleep_for(chrono::milliseconds(50));
                continue;
            }
            cout << string("[Server ") + to_string(id_) + "] Processing request. [Total: " + to_string(request_count) + ", Pending: " + to_string(req_queue_.size()) + "]" << endl;
            tuple<Channel*, vector<string>, vector<Item>> query = req_queue_.front();

            const vector<string>& ids = std::get<1>(query);
            const vector<Item>& items = std::get<2>(query);
            vector<bool> intersection(items.size());
            
            // local intersecion
            for (int j = 0; j < ids.size(); j++)
            {
                if (record_ids_.find(ids[j]) != record_ids_.end())
                {
                    intersection[j] = true;
                    cout << string("*************** [Server ") + to_string(id_) + "] Found local duplicate " + ids[j] + " ******************" << endl;
                }
            }

            // remote intersection
            for (int i = 0; i < NUM_SERVER; i++)
            {
                if (i == id_) continue;
                
                vector<bool> partial = receiver_.query(items, SERVER_IPS[i], SERVER_APSI_PORTS[i]);
                for (int j = 0; j < intersection.size(); j++)
                {
                    intersection[j] = intersection[j] | partial[j];
                    if(partial[j])
                        cout << string("*************** [Server ") + to_string(id_) + "] Found remote duplicate " + ids[j] + " on server " + to_string(i) + " ******************" << endl;
                }
                
            }

            Channel* channel = std::get<0>(query);
            int count = 0;
            for (int j = 0; j < intersection.size(); j++)
                if (intersection[j]) count++;
            send_int(count, *channel);
            for (int j = 0; j < intersection.size(); j++)
            {
                if (intersection[j])
                    send_string(ids[j], *channel);
                else
                {
                    sender_.add_data(items[j]);
                    record_ids_.insert(ids[j]);
                }
            }
            
            channel->close();
            req_queue_.pop_front();
            cout << string("[Server ") + to_string(id_) + "] Done with request. [Total: " + to_string(request_count) + ", Pending: " + to_string(req_queue_.size()) + "]" << endl;
            pass_token();
        }
    }

    void Server::sharing_engine()
    {
        while (true && !stopped)
        {
            Channel* sharing_channel = sharing_endpoint_.getNextQueuedChannel();
            if (sharing_channel == nullptr)
            {
                this_thread::sleep_for(chrono::milliseconds(50));
                continue;
            }

            cout << string("[Server ") + to_string(id_) + "] Received request. [Total: " + to_string(++request_count) + ", Pending: " + to_string(req_queue_.size()) + "]" << endl;
        }
        data_endpoint_.stop();
    }
}