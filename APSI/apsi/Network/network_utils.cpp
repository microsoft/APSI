#include "apsi/network/network_utils.h"
#include <sstream>
#include "cryptoTools/Network/Channel.h"

using namespace seal;
using namespace std;
using namespace oc;

namespace apsi
{
	void send_plaintext(const Plaintext &plaintext, Channel &channel)
	{
		stringstream ss;
		plaintext.save(ss);
		channel.asyncSend(std::move(ss.str()));
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
		channel.asyncSend(std::move(ss.str()));
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

	void send_evalkeys(const seal::EvaluationKeys &keys, Channel &channel)
	{
		stringstream ss;
		keys.save(ss);
		channel.asyncSend(std::move(ss.str()));
	}

	void receive_evalkeys(seal::EvaluationKeys &keys, Channel &channel)
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
		channel.asyncSend(std::move(ss.str()));
	}

	void receive_pubkey(seal::PublicKey &pubkey, Channel &channel)
	{
		string buff;
		channel.recv(buff);
		stringstream ss(buff);
		pubkey.load(ss);
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

}