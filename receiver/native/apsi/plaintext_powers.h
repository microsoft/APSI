// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <unordered_map>
#include <vector>

// APSI
#include "apsi/crypto_context.h"
#include "apsi/powers.h"
#include "apsi/psi_params.h"
#include "apsi/seal_object.h"

// SEAL
#include "seal/ciphertext.h"
#include "seal/modulus.h"

// GSL
#include "gsl/span"

namespace apsi {
    namespace receiver {
        class PlaintextPowers {
        public:
            PlaintextPowers(
                std::vector<std::uint64_t> values, const PSIParams &params, const PowersDag &pd);

            std::unordered_map<std::uint32_t, SEALObject<seal::Ciphertext>> encrypt(
                const CryptoContext &crypto_context);

        private:
            seal::Modulus mod_;

            std::unordered_map<std::uint32_t, std::vector<std::uint64_t>> powers_;

            void square_array(gsl::span<std::uint64_t> in) const;

            void multiply_array(
                gsl::span<std::uint64_t> in1,
                gsl::span<std::uint64_t> in2,
                gsl::span<std::uint64_t> out) const;

            std::vector<std::uint64_t> exponentiate_array(
                std::vector<std::uint64_t> values, std::uint32_t exponent);

            void compute_powers(std::vector<std::uint64_t> values, const PowersDag &pd);
        };
    } // namespace receiver
} // namespace apsi
