// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <utility>

// APSI
#include "apsi/log.h"
#include "apsi/plaintext_powers.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/uintarithsmallmod.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi {
    namespace receiver {
        PlaintextPowers::PlaintextPowers(
            vector<uint64_t> values, const PSIParams &params, const PowersDag &pd)
            : mod_(params.seal_params().plain_modulus())
        {
            compute_powers(move(values), pd);
        }

        unordered_map<uint32_t, SEALObject<Ciphertext>> PlaintextPowers::encrypt(
            const CryptoContext &crypto_context)
        {
            if (!crypto_context.encryptor()) {
                throw invalid_argument("encryptor is not set in crypto_context");
            }

            unordered_map<uint32_t, SEALObject<Ciphertext>> result;
            for (auto &p : powers_) {
                Plaintext pt;
                crypto_context.encoder()->encode(p.second, pt);
                result.emplace(
                    make_pair(p.first, crypto_context.encryptor()->encrypt_symmetric(pt)));
            }

            return result;
        }

        void PlaintextPowers::square_array(gsl::span<uint64_t> in) const
        {
            transform(in.begin(), in.end(), in.begin(), [this](auto val) {
                return multiply_uint_mod(val, val, mod_);
            });
        }

        void PlaintextPowers::multiply_array(
            gsl::span<uint64_t> in1, gsl::span<uint64_t> in2, gsl::span<uint64_t> out) const
        {
            transform(
                in1.begin(), in1.end(), in2.begin(), out.begin(), [this](auto val1, auto val2) {
                    return multiply_uint_mod(val1, val2, mod_);
                });
        }

        vector<uint64_t> PlaintextPowers::exponentiate_array(
            vector<uint64_t> values, uint32_t exponent)
        {
            if (!exponent) {
                throw invalid_argument("exponent cannot be zero");
            }

            vector<uint64_t> result(values.size(), 1);
            while (exponent) {
                if (exponent & 1) {
                    multiply_array(values, result, result);
                }
                square_array(values);
                exponent >>= 1;
            }

            return result;
        }

        void PlaintextPowers::compute_powers(vector<uint64_t> values, const PowersDag &pd)
        {
            auto source_powers = pd.source_nodes();

            for (auto &s : source_powers) {
                powers_[s.power] = exponentiate_array(values, s.power);
            }

            vector<uint32_t> powers_vec;
            transform(powers_.begin(), powers_.end(), back_inserter(powers_vec), [](auto &p) {
                return p.first;
            });
            APSI_LOG_DEBUG("Plaintext powers computed: " << util::to_string(powers_vec));
        }
    } // namespace receiver
} // namespace apsi
