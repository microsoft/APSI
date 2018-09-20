#include "apsi/network/network_utils.h"
#include <sstream>

using namespace std;
using namespace seal;
using namespace apsi::network;

namespace apsi
{
    void send_ciphertext(const Ciphertext &ciphertext, Channel &channel)
    {
        stringstream ss;
        ciphertext.save(ss);
        channel.send(ss.str());
    }

    void receive_ciphertext(Ciphertext &ciphertext, Channel &channel)
    {
        string buff;
        channel.receive(buff);
        stringstream ss(buff);
        ciphertext.load(ss);
    }

    void send_relinkeys(const seal::RelinKeys &keys, Channel &channel)
    {
        stringstream ss;
        keys.save(ss);
        channel.send(ss.str());
    }

    void receive_relinkeys(seal::RelinKeys &keys, Channel &channel)
    {
        string buff;
        channel.receive(buff);
        stringstream ss(buff);
        keys.load(ss);
    }

    void send_pubkey(const seal::PublicKey &pubkey, Channel &channel)
    {
        stringstream ss;
        pubkey.save(ss);
        channel.send(ss.str());
    }

    void receive_pubkey(seal::PublicKey &pubkey, Channel &channel)
    {
        string buff;
        channel.receive(buff);
        stringstream ss(buff);
        pubkey.load(ss);
    }
}
