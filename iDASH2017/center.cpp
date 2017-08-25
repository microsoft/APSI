#include "center.h"
#include "idashdefines.h"
#include "Network/network_utils.h"
#include <random>
#include "Network/boost_endpoint.h"
#include "apsidefines.h"
#include <time.h>

using namespace std;
using namespace apsi::network;
using namespace apsi;

namespace idash
{
    Center::Center(int id): id_(id), ios_(0)
    {

    }

    void Center::load(istream &is)
    {
        string line = "";
        getline(is, line); // skip header
        while (!is.eof())
        {
            getline(is, line);
            if (line == "") continue;
            size_t first_delim = line.find(DELIM);
            records_[line.substr(0, first_delim)] = line.substr(first_delim + 1, line.length() - first_delim - 1);
        }
    }

    void Center::start()
    {
        srand(time(NULL));
        map<string, string>::iterator it = records_.begin();
        while(it != records_.end())
        {
            vector<pair<string, Item>> batch;
            for (int i = 0; (i < DATA_BATCH) && (it != records_.end()); i++, it++)
            {
                batch.emplace_back(make_pair(it->first, Item(it->second)));
            }
            dispatch(batch);

            this_thread::sleep_for(chrono::milliseconds(10));
        }
    }

    void Center::dispatch(const vector<pair<string, Item>> &batch)
    {
        int server_id = rand() % NUM_SERVER;
        BoostEndpoint client(ios_, SERVER_IPS[server_id], SERVER_DATA_PORTS[server_id], false, DATA_ENDPOINT);
        Channel& client_channel = client.addChannel("-", "-");

        send_int(batch.size(), client_channel);
        for (int i = 0; i < batch.size(); i++)
        {
            send_string(batch[i].first, client_channel);
            send_item(batch[i].second, client_channel);
        }
        cout << string("[Client ") + to_string(id_) + "] Sent request " + to_string(request_count++) + " to server " + to_string(server_id) << endl;

        int count = 0;
        receive_int(count, client_channel);
        vector<string> ids(count);
        for (int i = 0; i < count; i++)
        {
            receive_string(ids[i], client_channel);
            records_.erase(ids[i]);
            cout << string("*************** [Client ") + to_string(id_) + "] Removed record " + ids[i] + " ******************" <<endl;
        }

        client_channel.close();
        client.stop();
    }


}