#pragma once

#include "ciphertext.h"
#include "boost_channel.h"
#include "rnsevaluationkeys.h"
#include "publickey.h"
#include "item.h"
#include "plaintext.h"

namespace apsi
{
    namespace network
    {
        void send_plaintext(const seal::Plaintext &plaintext, Channel &channel);

        void receive_plaintext(seal::Plaintext &plaintext, Channel &channel);

        void send_ciphertext(const seal::Ciphertext &ciphertext, Channel &channel);

        void receive_ciphertext(seal::Ciphertext &ciphertext, Channel &channel);

        void send_ciphertext(const std::vector<seal::Ciphertext> &ciphers, Channel &channel);

        void receive_ciphertext(std::vector<seal::Ciphertext> &ciphers, Channel &channel);

        void send_int(int data, Channel &channel);

        void receive_int(int &data, Channel &channel);

        void send_uint64(uint64_t data, Channel &channel);

        void receive_uint64(uint64_t &data, Channel &channel);

        void send_string(const std::string &data, Channel &channel);

        void receive_string(std::string &data, Channel &channel);

        void send_evalkeys(const seal::RNSEvaluationKeys &keys, Channel &channel);

        void receive_evalkeys(seal::RNSEvaluationKeys &keys, Channel &channel);

        void send_pubkey(const seal::PublicKey &pubkey, Channel &channel);

        void receive_pubkey(seal::PublicKey &pubkey, Channel &channel);

        void send_item(const apsi::Item &item, Channel &channel);

        void receive_item(apsi::Item &item, Channel &channel);

        
    }
}
