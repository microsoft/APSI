#include "Network/network_utils.h"
#include <sstream>
#include "Network/byte_stream.h"

using namespace seal;
using namespace std;

namespace apsi
{
    namespace network
    {
        void send_plaintext(const Plaintext &plaintext, Channel &channel)
        {
            stringstream ss;
            plaintext.save(ss);
            unique_ptr<ByteStream> buff(new ByteStream(reinterpret_cast<const uint8_t*>(ss.str().data()), ss.str().size()));
            channel.asyncSend(std::move(buff));
        }

        void receive_plaintext(Plaintext &plaintext, Channel &channel)
        {
            ByteStream buff;
            channel.recv(buff);
            stringstream ss(string(reinterpret_cast<char*>(buff.data()), buff.size()));
            plaintext.load(ss);
        }

        void send_ciphertext(const Ciphertext &ciphertext, Channel &channel)
        {
            stringstream ss;
            ciphertext.save(ss);
            unique_ptr<ByteStream> buff(new ByteStream(reinterpret_cast<const uint8_t*>(ss.str().data()), ss.str().size()));
            channel.asyncSend(std::move(buff));
        }

        void receive_ciphertext(Ciphertext &ciphertext, Channel &channel)
        {
            ByteStream buff;
            channel.recv(buff);
            stringstream ss(string(reinterpret_cast<char*>(buff.data()), buff.size()));
            ciphertext.load(ss);
        }

        void send_ciphertext(const std::vector<seal::Ciphertext> &ciphers, Channel &channel)
        {
            send_int(ciphers.size(), channel);
            for (int i = 0; i < ciphers.size(); i++)
                send_ciphertext(ciphers[i], channel);
        }

        void receive_ciphertext(std::vector<seal::Ciphertext> &ciphers, Channel &channel)
        {
            int size = 0;
            receive_int(size, channel);
            ciphers.resize(size);
            for (int i = 0; i < ciphers.size(); i++)
                receive_ciphertext(ciphers[i], channel);
        }

        void send_int(int data, Channel &channel)
        {
            std::unique_ptr<ByteStream> buff(new ByteStream());
            buff->resize(sizeof(int));
            buff->getArrayView<int>()[0] = data;
            channel.asyncSend(std::move(buff));
        }

        void receive_int(int &data, Channel &channel)
        {
            ByteStream buff;
            channel.recv(buff);
            data = buff.getArrayView<int>()[0];
        }

        void send_uint64(uint64_t data, Channel &channel)
        {
            std::unique_ptr<ByteStream> buff(new ByteStream());
            buff->resize(sizeof(uint64_t));
            buff->getArrayView<uint64_t>()[0] = data;
            channel.asyncSend(std::move(buff));
        }

        void receive_uint64(uint64_t &data, Channel &channel)
        {
            ByteStream buff;
            channel.recv(buff);
            data = buff.getArrayView<uint64_t>()[0];
        }

        void send_string(const std::string &data, Channel &channel)
        {
            unique_ptr<ByteStream> buff(new ByteStream(reinterpret_cast<const uint8_t*>(data.data()), data.size()));
            channel.asyncSend(std::move(buff));
        }

        void receive_string(string &data, Channel &channel)
        {
            ByteStream buff;
            channel.recv(buff);
            data = string((char*)buff.data(), buff.size());
        }

        void send_evalkeys(const seal::EvaluationKeys &keys, Channel &channel)
        {
            stringstream ss;
            keys.save(ss);
            unique_ptr<ByteStream> buff(new ByteStream(reinterpret_cast<const uint8_t*>(ss.str().data()), ss.str().size()));
            channel.asyncSend(std::move(buff));
        }

        void receive_evalkeys(seal::EvaluationKeys &keys, Channel &channel)
        {
            ByteStream buff;
            channel.recv(buff);
            stringstream ss(string(reinterpret_cast<char*>(buff.data()), buff.size()));
            keys.load(ss);
        }

        void send_pubkey(const seal::PublicKey &pubkey, Channel &channel)
        {
            stringstream ss;
            pubkey.save(ss);
            unique_ptr<ByteStream> buff(new ByteStream(reinterpret_cast<const uint8_t*>(ss.str().data()), ss.str().size()));
            channel.asyncSend(std::move(buff));
        }

        void receive_pubkey(seal::PublicKey &pubkey, Channel &channel)
        {
            ByteStream buff;
            channel.recv(buff);
            stringstream ss(string(reinterpret_cast<char*>(buff.data()), buff.size()));
            pubkey.load(ss);
        }

        void send_item(const apsi::Item &item, Channel &channel)
        {
            stringstream ss;
            item.save(ss);
            unique_ptr<ByteStream> buff(new ByteStream(reinterpret_cast<const uint8_t*>(ss.str().data()), ss.str().size()));
            channel.asyncSend(std::move(buff));
        }

        void receive_item(apsi::Item &item, Channel &channel)
        {
            ByteStream buff;
            channel.recv(buff);
            stringstream ss(string(reinterpret_cast<char*>(buff.data()), buff.size()));
            item.load(ss);
        }
    }
}