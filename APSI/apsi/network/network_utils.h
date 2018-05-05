#pragma once

#include "seal/ciphertext.h"
#include "seal/evaluationkeys.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"
#include "seal/plaintext.h"
#include "cryptoTools/Network/Channel.h"
#include "apsi/item.h"
#include "apsi/ffield/ffield_array.h"
#include "apsi/tools/sealcompress.h"

namespace apsi
{
	void send_plaintext(const seal::Plaintext &plaintext, oc::Channel &channel);

	void receive_plaintext(seal::Plaintext &plaintext, oc::Channel &channel);

	void send_ciphertext(const seal::Ciphertext &ciphertext, oc::Channel &channel);

	void receive_ciphertext(seal::Ciphertext &ciphertext, oc::Channel &channel);

	void send_ciphertext(const std::vector<seal::Ciphertext> &ciphers, oc::Channel &channel);

	void receive_ciphertext(std::vector<seal::Ciphertext> &ciphers, oc::Channel &channel);

	void send_compressed_ciphertext(const CiphertextCompressor &compressor, const seal::Ciphertext &ciphertext, oc::Channel &channel);

	void receive_compressed_ciphertext(const CiphertextCompressor &compressor, seal::Ciphertext &ciphertext, oc::Channel &channel);

	void send_compressed_ciphertext(const CiphertextCompressor &compressor, const std::vector<seal::Ciphertext> &ciphers, oc::Channel &channel);

	void receive_compressed_ciphertext(const CiphertextCompressor &compressor, std::vector<seal::Ciphertext> &ciphers, oc::Channel &channel);

	void send_evalkeys(const seal::EvaluationKeys &keys, oc::Channel &channel);

	void receive_evalkeys(seal::EvaluationKeys &keys, oc::Channel &channel);

    void send_pubkey(const seal::PublicKey &pubkey, oc::Channel &channel);

    void receive_pubkey(seal::PublicKey &pubkey, oc::Channel &channel);

    void send_prvkey(const seal::SecretKey &k, oc::Channel &channel);

    void receive_prvkey(seal::SecretKey &k, oc::Channel &channel);

	void send_item(const apsi::Item &item, oc::Channel &channel);

	void receive_item(apsi::Item &item, oc::Channel &channel);

    void send_ffield_array(const FFieldArray& powers, oc::Channel &channel);

    void receive_ffield_array(FFieldArray& powers, oc::Channel &channel);

}
