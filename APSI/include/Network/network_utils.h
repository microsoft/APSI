#pragma once

#include "ciphertext.h"
#include "boost_channel.h"
#include "evaluationkeys.h"
#include "publickey.h"

namespace apsi
{
    namespace network
    {
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

        void send_evalkeys(const seal::EvaluationKeys &keys, Channel &channel);

        void receive_evalkeys(seal::EvaluationKeys &keys, Channel &channel);

        void send_pubkey(const seal::PublicKey &pubkey, Channel &channel);

        void receive_pubkey(seal::PublicKey &pubkey, Channel &channel);
    }
}
