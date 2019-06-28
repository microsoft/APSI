// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

// STD
#include <sstream>

// APSI
#include "apsi/network/network_utils.h"

using namespace std;
using namespace seal;
using namespace apsi::network;

namespace apsi
{
    void get_string(string& str, const PublicKey& pub_key)
    {
        stringstream ss;
        pub_key.save(ss);
        str = ss.str();
    }

    void get_string(string& str, const RelinKeys& relin_keys)
    {
        stringstream ss;
        relin_keys.save(ss);
        str = ss.str();
    }

    void get_string(string& str, const Ciphertext& ciphertext)
    {
        stringstream ss;
        ciphertext.save(ss);
        str = ss.str();
    }

    void get_string(string& str, const SmallModulus& sm)
    {
        stringstream ss;
        sm.save(ss);
        str = ss.str();
    }

    void get_public_key(std::shared_ptr<seal::SEALContext> context, seal::PublicKey& pub_key, const std::string& str)
    {
        stringstream ss(str);
        pub_key.load(context, ss);
    }

    void get_relin_keys(std::shared_ptr<seal::SEALContext> context, seal::RelinKeys& relin_keys, const std::string& str)
    {
        stringstream ss(str);
        relin_keys.load(context, ss);
    }

    void get_ciphertext(std::shared_ptr<seal::SEALContext> context, seal::Ciphertext& ciphertext, const std::string& str)
    {
        stringstream ss(str);
        ciphertext.load(context, ss);
    }

    void get_small_modulus(seal::SmallModulus& sm, const std::string& str)
    {
        stringstream ss(str);
        sm.load(ss);
    }
}
