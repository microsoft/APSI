#include "apsi/network/network_utils.h"
#include <sstream>

using namespace std;
using namespace seal;
using namespace apsi::network;

namespace apsi
{
    void send_plaintext(const Plaintext &plaintext, Channel &channel)
    {
        stringstream ss;
        plaintext.save(ss);
        channel.send(ss.str());
    }

    void receive_plaintext(Plaintext &plaintext, Channel &channel)
    {
        string buff;
        channel.receive(buff);
        stringstream ss(buff);
        plaintext.load(ss);
    }

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

    void send_ciphertext(const std::vector<seal::Ciphertext> &ciphers, Channel &channel)
    {
        vector<string> cipherstrings(ciphers.size());
        for (u64 i = 0; i < ciphers.size(); i++)
        {
            stringstream ss;
            ciphers[i].save(ss);
            cipherstrings[i] = ss.str();
        }

        channel.send(cipherstrings);
    }

    void receive_ciphertext(std::vector<seal::Ciphertext> &ciphers, Channel &channel)
    {
        vector<string> cipherstrings;
        channel.receive(cipherstrings);

        ciphers.resize(cipherstrings.size());
        for (u64 i = 0; i < cipherstrings.size(); i++)
        {
            stringstream ss(cipherstrings[i]);
            ciphers[i].load(ss);
        }
    }

    void send_compressed_ciphertext(const CiphertextCompressor &compressor, const Ciphertext &ciphertext, Channel &channel)
    {
        stringstream ss;
        compressor.compressed_save(ciphertext, ss);
        channel.send(ss.str());
    }

    void receive_compressed_ciphertext(const CiphertextCompressor &compressor, Ciphertext &ciphertext, Channel &channel)
    {
        string buff;
        channel.receive(buff);
        stringstream ss(buff);
        compressor.compressed_load(ss, ciphertext);
    }

    void send_compressed_ciphertext(const CiphertextCompressor &compressor, const std::vector<seal::Ciphertext> &ciphers, Channel &channel)
    {
        vector<string> cipherstrings(ciphers.size());

        for (u64 i = 0; i < ciphers.size(); i++)
        {
            stringstream ss;
            compressor.compressed_save(ciphers[i], ss);
            cipherstrings[i] = ss.str();
        }

        channel.send(cipherstrings);
    }

    void receive_compressed_ciphertext(const CiphertextCompressor &compressor, std::vector<seal::Ciphertext> &ciphers, Channel &channel)
    {
        vector<string> cipherstrings;
        channel.receive(cipherstrings);

        ciphers.resize(cipherstrings.size());
        for (u64 i = 0; i < cipherstrings.size(); i++)
        {
            stringstream ss(cipherstrings[i]);
            compressor.compressed_load(ss, ciphers[i]);
        }
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

    void send_prvkey(const seal::SecretKey &k, Channel &channel)
    {
        stringstream ss;
        k.save(ss);
        channel.send(ss.str());
    }

    void receive_prvkey(seal::SecretKey &k, Channel &channel)
    {
        string buff;
        channel.receive(buff);
        stringstream ss(buff);
        k.load(ss);
    }

    void send_item(const apsi::Item &item, Channel &channel)
    {
        static_assert(sizeof(apsi::Item) == sizeof(block), "Item should be the same size as block");
        channel.send(static_cast<block&>(item));
    }

    void receive_item(apsi::Item &item, Channel &channel)
    {
        static_assert(sizeof(apsi::Item) == sizeof(block), "Item should be the same size as block");
        channel.receive(static_cast<block&>(item));
    }

}
