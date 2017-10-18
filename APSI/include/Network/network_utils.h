#pragma once

#include "ciphertext.h"
#include "cryptoTools/Network/Channel.h"
#include "evaluationkeys.h"
#include "publickey.h"
#include "item.h"
#include "plaintext.h"

namespace apsi
{
	void send_plaintext(const seal::Plaintext &plaintext, oc::Channel &channel);

	void receive_plaintext(seal::Plaintext &plaintext, oc::Channel &channel);

	void send_ciphertext(const seal::Ciphertext &ciphertext, oc::Channel &channel);

	void receive_ciphertext(seal::Ciphertext &ciphertext, oc::Channel &channel);

	void send_ciphertext(const std::vector<seal::Ciphertext> &ciphers, oc::Channel &channel);

	void receive_ciphertext(std::vector<seal::Ciphertext> &ciphers, oc::Channel &channel);

	void send_evalkeys(const seal::EvaluationKeys &keys, oc::Channel &channel);

	void receive_evalkeys(seal::EvaluationKeys &keys, oc::Channel &channel);

	void send_pubkey(const seal::PublicKey &pubkey, oc::Channel &channel);

	void receive_pubkey(seal::PublicKey &pubkey, oc::Channel &channel);

	void send_item(const apsi::Item &item, oc::Channel &channel);

	void receive_item(apsi::Item &item, oc::Channel &channel);

}
