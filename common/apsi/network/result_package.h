// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

// SEAL
#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/util/defines.h"

// APSI
#include "apsi/crypto_context.h"
#include "apsi/seal_object.h"

namespace apsi {
    namespace network {
        /**
        Stores a decrypted and decoded PSI response and optionally a labeled PSI response.
        */
        struct PlainResultPackage {
            std::uint32_t bundle_idx;

            std::vector<std::uint64_t> psi_result;

            std::uint32_t label_byte_count;

            std::uint32_t nonce_byte_count;

            std::vector<std::vector<std::uint64_t>> label_result;
        };

        /**
        Stores a PSI response and optionally labeled PSI response ciphertexts.
        */
        class ResultPackage {
        public:
            /**
            Writes the ResultPackage to a stream.
            */
            std::size_t save(std::ostream &out) const;

            /**
            Reads the ResultPackage from a stream.
            */
            std::size_t load(std::istream &in, std::shared_ptr<seal::SEALContext> context);

            PlainResultPackage extract(const CryptoContext &crypto_context);

            std::uint32_t bundle_idx;

            seal::compr_mode_type compr_mode = seal::Serialization::compr_mode_default;

            SEALObject<seal::Ciphertext> psi_result;

            std::uint32_t label_byte_count;

            std::uint32_t nonce_byte_count;

            std::vector<SEALObject<seal::Ciphertext>> label_result;
        }; // struct ResultPackage
    }      // namespace network
} // namespace apsi
