// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <seal/ciphertext.h>
#include <seal/relinkeys.h>
#include <seal/publickey.h>
#include <seal/secretkey.h>
#include <seal/plaintext.h>

namespace apsi
{
    /**
    Get string for a public key
    */
    void get_string(std::string& str, const seal::PublicKey& pub_key);

    /**
    Get string for a Ciphertext
    */
    void get_string(std::string& str, const seal::Ciphertext& ciphertext);

    /**
    Get string for a SmallModulus
    */
    void get_string(std::string& str, const seal::SmallModulus& sm);

    /**
    Get public key from a string
    */
    void get_public_key(std::shared_ptr<seal::SEALContext> context, seal::PublicKey& pub_key, const std::string& str);

    /**
    Get Relinearization keys from a string
    */
    void get_relin_keys(std::shared_ptr<seal::SEALContext> context, seal::RelinKeys& relin_keys, const std::string& str);

    /**
    Get Ciphertext from a string
    */
    void get_ciphertext(std::shared_ptr<seal::SEALContext> context, seal::Ciphertext& ciphertext, const std::string& str);

    /**
    Get SmallModulus from a string
    */
    void get_small_modulus(seal::SmallModulus& sm, const std::string& str);
} // namespace apsi