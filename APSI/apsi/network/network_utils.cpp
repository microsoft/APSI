#include "apsi/network/network_utils.h"
#include <sstream>
#include "zmqpp/zmqpp.hpp"

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
        // Send the Ciphertext vector as a single message.
        zmqpp::message_t msg;
        msg.add(ciphers.size());
        for (auto& cipher : ciphers)
        {
            stringstream ss;
            cipher.save(ss);
            msg.add(ss.str());
        }

        channel.send(msg);
    }

    void receive_ciphertext(std::vector<seal::Ciphertext> &ciphers, Channel &channel)
    {
        size_t size = 0;

        // Vector is received as a single message
        zmqpp::message_t msg;
        channel.receive(msg);

        if (msg.parts() < 1)
            throw std::runtime_error("Should have at least size");

        // Size is first part
        size = msg.get<size_t>(0);

        if (msg.parts() < (size + 1))
            throw std::runtime_error("Not enough parts.");

        // Each additional part is a ciphertext
        ciphers.resize(size);
        for (int i = 0; i < size; i++)
        {
            string str = msg.get(i + 1);
            stringstream ss(str);
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
        // Vector will be sent as a single message
        zmqpp::message_t msg;
        msg.add(ciphers.size());

        for (auto& cipher : ciphers)
        {
            stringstream ss;
            compressor.compressed_save(cipher, ss);
            msg.add(ss.str());
        }

        channel.send(msg);
    }

    void receive_compressed_ciphertext(const CiphertextCompressor &compressor, std::vector<seal::Ciphertext> &ciphers, Channel &channel)
    {
        // Vector is received as a single message
        zmqpp::message_t msg;
        channel.receive(msg);

        if (msg.parts() < 1)
            throw std::runtime_error("Should have at least size");

        size_t size = msg.get<size_t>(0);

        if (msg.parts() < (size + 1))
            throw std::runtime_error("Not enough parts");

        ciphers.resize(size);
        for (int i = 0; i < size; i++)
        {
            string str = msg.get(i + 1);
            stringstream ss(str);
            compressor.compressed_load(ss, ciphers[i]);
        }
    }

    void send_evalkeys(const seal::EvaluationKeys &keys, Channel &channel)
    {
        stringstream ss;
        keys.save(ss);
        channel.send(ss.str());
    }

    void receive_evalkeys(seal::EvaluationKeys &keys, Channel &channel)
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
        item = channel.receive<block>();
    }

    //void send_ffield_array(const FFieldArray & val, Channel & channel)
    //{
    //    //channel.asyncSendCopy(val.data(), val.size());// *val.field()->d());

    //    // std::vector<_ffield_elt_coeff_t> coeffs(val.size() * val.field()->d());
    //    std::vector<_ffield_elt_coeff_t> coeffs;

    //    // All fields SHOULD have the same degree
    //    coeffs.reserve(val.size() * val.field(0)->d());
    //    for (unsigned i = 0; i < val.size(); ++i)
    //    {
    //        for (int j = 0; j < val.field(i)->d(); ++j)
    //        {
    //            coeffs.emplace_back(val.get_coeff_of(i, j));
    //        }
    //    }
    //    channel.asyncSend(std::move(coeffs));

    //    //std::cout << val.get(0).get_coeff( << std::endl;
    //    //oc::RandomOracle ro(sizeof(block));
    //    //{
    //    //    auto str = val.get(i).to_string();
    //    //    ro.Update(str.data(), str.size());
    //    //}
    //    //block b;
    //    //ro.Final(b);

    //    //std::cout << b<< std::endl;
    //}

    //void receive_ffield_array(FFieldArray & val, Channel & channel)
    //{
    //    if (val.size() == 0)
    //        throw std::runtime_error("resizeing is not performed");

    //    // std::vector<_ffield_elt_coeff_t> coeffs(val.size() * val.field()->d());
    //    std::vector<_ffield_elt_coeff_t> coeffs;

    //    // All fields SHOULD have the same degree
    //    coeffs.reserve(val.size() * val.field(0)->d());

    //    channel.recv(coeffs);

    //    auto iter = coeffs.begin();
    //    for (int i = 0; i < val.size(); ++i)
    //    {
    //        for (int j = 0; j < val.field(i)->d(); ++j)
    //        {
    //            val.set_coeff_of(i, j, *iter++);
    //        }
    //    }


        //channel.recv(val.data(), val.size());// * val.field()->d());

        //std::cout << val.get(0) << std::endl;

        //oc::RandomOracle ro(sizeof(block));
        //for (int i = 0; i < val.size(); ++i)
        //{
        //    auto str = val.get(i).to_string();
        //    ro.Update(str.data(), str.size());
        //}
        //block b;
        //ro.Final(b);

        //std::cout << b << std::endl;
    //}
}
