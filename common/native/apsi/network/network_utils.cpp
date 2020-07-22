// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "apsi/network/network_utils.h"
#include <sstream>

using namespace std;
using namespace seal;

namespace apsi
{
    void get_string(string &str, const PublicKey &pub_key)
    {
        stringstream ss;
        pub_key.save(ss);
        str = ss.str();
    }

    void get_string(string &str, const Ciphertext &ciphertext)
    {
        stringstream ss;
        ciphertext.save(ss);
        str = ss.str();
    }

    void get_string(string &str, const Modulus &sm)
    {
        stringstream ss;
        sm.save(ss);
        str = ss.str();
    }

    void get_public_key(const shared_ptr<SEALContext> &context, PublicKey &public_key, const string &str)
    {
        stringstream ss(str);
        public_key.load(context, ss);
    }

    void get_secret_key(const shared_ptr<SEALContext> &context, SecretKey &secret_key, const string &str)
    {
        stringstream ss(str);
        secret_key.load(context, ss);
    }

    void get_relin_keys(const shared_ptr<SEALContext> &context, RelinKeys &relin_keys, const string &str)
    {
        stringstream ss(str);
        relin_keys.load(context, ss);
    }

    void get_ciphertext(const shared_ptr<SEALContext> &context, Ciphertext &ciphertext, const string &str)
    {
        stringstream ss(str);
        ciphertext.load(context, ss);
    }

    void get_modulus(Modulus &sm, const string &str)
    {
        stringstream ss(str);
        sm.load(ss);
    }
} // namespace apsi
