// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <FourQ.h>
#include <array>
#include <cstddef>
#include <cstring>
#include <gsl/span>
#include <iostream>
#include <memory>
#include <seal/randomgen.h>

namespace apsi
{
    namespace oprf
    {
        class ECPoint
        {
        public:
            static constexpr std::size_t save_size = sizeof(f2elm_t);
            static constexpr std::size_t point_size = sizeof(point_t);
            static constexpr std::size_t order_size = sizeof(digit_t) * NWORDS_ORDER;

            using scalar_type = std::array<unsigned char, order_size>;
            using scalar_const_type = const scalar_type;

            using scalar_span_type = gsl::span<unsigned char, order_size>;
            using scalar_span_const_type = gsl::span<const unsigned char, order_size>;

            using input_span_const_type = gsl::span<const unsigned char, gsl::dynamic_extent>;

            // Output hash size is 120 bits
            static constexpr std::size_t hash_size = 15;

            using hash_span_type = gsl::span<unsigned char, hash_size>;

            // Initializes the ECPoint with the neutral element
            ECPoint() = default;

            // This function applies Blake2b on value and hashes the output to
            // a uniformly random elliptic curve point.
            ECPoint(input_span_const_type value);

            // Creates a random non-zero number modulo the prime order subgroup
            // order and computes its inverse.
            static void make_random_nonzero_scalar(
                scalar_span_type out, std::shared_ptr<seal::UniformRandomGenerator> rg = nullptr);

            static void invert_scalar(scalar_span_const_type in, scalar_span_type out);

            void scalar_multiply(scalar_span_const_type scalar);

            bool operator==(const ECPoint &compare);

            inline bool operator!=(const ECPoint &compare)
            {
                return !operator==(compare);
            }

            ECPoint &operator=(const ECPoint &assign)
            {
                if (&assign != this)
                {
                    std::memcpy(pt_, assign.pt_, point_size);
                }
                return *this;
            }

            void save(std::ostream &stream);

            void load(std::istream &stream);

            void save(gsl::span<unsigned char, save_size> out);

            void load(gsl::span<const unsigned char, save_size> in);

            void extract_hash(gsl::span<unsigned char, hash_size> out);

        private:
            // Initialize to neutral element
            point_t pt_ = { { {{0}}, {{1}} } }; // { {.x = { 0 }, .y = { 1 } }};
        };                              // class ECPoint
    }                                   // namespace oprf
} // namespace apsi
