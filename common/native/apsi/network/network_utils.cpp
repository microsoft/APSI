// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <sstream>
#include "apsi/network/network_utils.h"

using namespace std;
using namespace seal;

namespace apsi
{
    void get_string(string& str, const PublicKey& pub_key)
    {
        stringstream ss;
        pub_key.save(ss);
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

    void get_public_key(shared_ptr<SEALContext> context, PublicKey& pub_key, const string& str)
    {
        stringstream ss(str);
        pub_key.load(context, ss);
    }

    void get_relin_keys(shared_ptr<SEALContext> context, RelinKeys& relin_keys, const string& str)
    {
        stringstream ss(str);
        relin_keys.load(context, ss);
    }

    void get_ciphertext(shared_ptr<SEALContext> context, Ciphertext& ciphertext, const string& str)
    {
        stringstream ss(str);
        ciphertext.load(context, ss);
    }

    void get_small_modulus(SmallModulus& sm, const string& str)
    {
        stringstream ss(str);
        sm.load(ss);
    }
} // namespace apsi
