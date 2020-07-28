// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <string>
#include <sstream>

// SEAL
#include <seal/ciphertext.h>
#include <seal/plaintext.h>
#include <seal/publickey.h>
#include <seal/relinkeys.h>
#include <seal/secretkey.h>

namespace apsi
{
    /**
    Get string representing a serializable SEAL object.
    */
    template<typename T>
    std::string to_string(const T &obj)
    {
        std::stringstream ss;
        obj.save(ss, seal::compr_mode_type::deflate);
        return ss.str();
    }

    /**
    Load a serializable SEAL object from string.
    */
    template<typename T>
    void from_string(const std::shared_ptr<seal::SEALContext> &context, const std::string &str, T &destination)
    {
        std::stringstream ss(str);
        destination.load(context, ss);
    }

    /**
    Load a serializable SEAL object from string.
    */
    void from_string(const std::string &str, seal::Modulus &destination)
    {
        std::stringstream ss(str);
        destination.load(ss);
    }
} // namespace apsi
