#pragma once

// SEAL
#include "seal/ciphertext.h"
#include "seal/relinkeys.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"
#include "seal/plaintext.h"

// APSI
#include "apsi/item.h"
#include "apsi/ffield/ffield_array.h"
#include "apsi/tools/sealcompress.h"
#include "apsi/network/channel.h"

namespace apsi
{
    void send_ciphertext(const seal::Ciphertext &ciphertext, apsi::network::Channel &channel);

    void receive_ciphertext(seal::Ciphertext &ciphertext, apsi::network::Channel &channel);

    void send_relinkeys(const seal::RelinKeys &keys, apsi::network::Channel &channel);

    void receive_relinkeys(seal::RelinKeys &keys, apsi::network::Channel &channel);

    void send_pubkey(const seal::PublicKey &pubkey, apsi::network::Channel &channel);

    void receive_pubkey(seal::PublicKey &pubkey, apsi::network::Channel &channel);
}
