#include "apsi/network/network_utils.h"
#include <sstream>
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/RandomOracle.h"
using namespace seal;
using namespace std;
using namespace oc;

namespace apsi
{
	void send_plaintext(const Plaintext &plaintext, Channel &channel)
	{
        stringstream ss;
		plaintext.save(ss);
		channel.asyncSend(ss.str());
	}

	void receive_plaintext(Plaintext &plaintext, Channel &channel)
	{
		string buff;
		channel.recv(buff);
		stringstream ss(buff);
		plaintext.load(ss);
	}

	void send_ciphertext(const Ciphertext &ciphertext, Channel &channel)
	{
        stringstream ss;
		ciphertext.save(ss);
		channel.asyncSend(ss.str());
	}

	void receive_ciphertext(Ciphertext &ciphertext, Channel &channel)
	{
		string buff;
		channel.recv(buff);
		stringstream ss(buff);
		ciphertext.load(ss);
	}

	void send_ciphertext(const std::vector<seal::Ciphertext> &ciphers, Channel &channel)
	{
		int s = ciphers.size();
		channel.asyncSendCopy(s);
		for (int i = 0; i < ciphers.size(); i++)
			send_ciphertext(ciphers[i], channel);
	}

	void receive_ciphertext(std::vector<seal::Ciphertext> &ciphers, Channel &channel)
	{
		int size = 0;
		channel.recv(size);
		ciphers.resize(size);
		for (int i = 0; i < ciphers.size(); i++)
			receive_ciphertext(ciphers[i], channel);
	}

	void send_compressed_ciphertext(const CiphertextCompressor &compressor, const Ciphertext &ciphertext, Channel &channel)
	{
        stringstream ss;
        compressor.compressed_save(ciphertext, ss);
		channel.asyncSend(ss.str());
	}

	void receive_compressed_ciphertext(const CiphertextCompressor &compressor, Ciphertext &ciphertext, Channel &channel)
	{
		string buff;
		channel.recv(buff);
		stringstream ss(buff);
        compressor.compressed_load(ss, ciphertext);
	}

	void send_compressed_ciphertext(const CiphertextCompressor &compressor, const std::vector<seal::Ciphertext> &ciphers, Channel &channel)
	{
		int s = ciphers.size();
		channel.asyncSendCopy(s);
		for (int i = 0; i < ciphers.size(); i++)
			send_compressed_ciphertext(compressor, ciphers[i], channel);
	}

	void receive_compressed_ciphertext(const CiphertextCompressor &compressor, std::vector<seal::Ciphertext> &ciphers, Channel &channel)
	{
		int size = 0;
		channel.recv(size);
		ciphers.resize(size);
		for (int i = 0; i < ciphers.size(); i++)
			receive_compressed_ciphertext(compressor, ciphers[i], channel);
	}

	void send_relinkeys(const seal::RelinKeys &keys, Channel &channel)
	{
		stringstream ss;
		keys.save(ss);
		channel.asyncSend(ss.str());
	}

	void receive_relinkeys(seal::RelinKeys &keys, Channel &channel)
	{
		string buff;
		channel.recv(buff);
		stringstream ss(buff);
		keys.load(ss);
	}

	void send_pubkey(const seal::PublicKey &pubkey, Channel &channel)
	{
		stringstream ss;
		pubkey.save(ss);
		channel.asyncSend(ss.str());
	}

	void receive_pubkey(seal::PublicKey &pubkey, Channel &channel)
	{
		string buff;
		channel.recv(buff);
		stringstream ss(buff);
		pubkey.load(ss);
	}

    void send_prvkey(const seal::SecretKey &k, oc::Channel &channel)
    {
        stringstream ss;
        k.save(ss);
        channel.asyncSend(ss.str());
    }

    void receive_prvkey(seal::SecretKey &k, oc::Channel &channel)
    {
        string buff;
        channel.recv(buff);
        stringstream ss(buff);
        k.load(ss);
    }

	void send_item(const apsi::Item &item, Channel &channel)
	{
		static_assert(sizeof(apsi::Item) == sizeof(block), "");
		channel.asyncSendCopy((block&)item);
	}

	void receive_item(apsi::Item &item, Channel &channel)
	{
		channel.recv((block&)item);
	}

    void send_ffield_array(const FFieldArray & val, oc::Channel & channel)
    {
        //channel.asyncSendCopy(val.data(), val.size());// *val.field()->d());

        // std::vector<_ffield_elt_coeff_t> coeffs(val.size() * val.field()->d());
        std::vector<_ffield_elt_coeff_t> coeffs;

        // All fields SHOULD have the same degree
        coeffs.reserve(val.size() * val.field(0)->d());
        for (unsigned i = 0; i < val.size(); ++i)
        {
            for (int j = 0; j < val.field(i)->d(); ++j)
            {
                coeffs.emplace_back(val.get_coeff_of(i, j));
            }
        }
        channel.asyncSend(std::move(coeffs));

        //std::cout << val.get(0).get_coeff( << std::endl;
        //oc::RandomOracle ro(sizeof(block));
        //{
        //    auto str = val.get(i).to_string();
        //    ro.Update(str.data(), str.size());
        //}
        //block b;
        //ro.Final(b);

        //std::cout << b<< std::endl;
    }

    void receive_ffield_array(FFieldArray & val, oc::Channel & channel)
    {
        if (val.size() == 0)
            throw std::runtime_error("resizeing is not performed");

        // std::vector<_ffield_elt_coeff_t> coeffs(val.size() * val.field()->d());
        std::vector<_ffield_elt_coeff_t> coeffs;

        // All fields SHOULD have the same degree
        coeffs.reserve(val.size() * val.field(0)->d());

        channel.recv(coeffs);

        auto iter = coeffs.begin();
        for (int i = 0; i < val.size(); ++i)
        {
            for (int j = 0; j < val.field(i)->d(); ++j)
            {
                val.set_coeff_of(i, j, *iter++);
            }
        }


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
    }

}
