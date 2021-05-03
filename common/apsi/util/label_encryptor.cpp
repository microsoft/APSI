// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

// APSI
#include "apsi/fourq/random.h"
#include "apsi/util/label_encryptor.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/randomgen.h"
#include "seal/util/blake2.h"

using namespace std;
using namespace seal;

namespace apsi {
    namespace util {
        EncryptedLabel encrypt_label(
            const Label &label,
            const LabelKey &key,
            size_t label_byte_count,
            size_t nonce_byte_count)
        {
            if (nonce_byte_count > max_nonce_byte_count) {
                throw invalid_argument("nonce_byte_count is too large");
            }

            // We use up to max_nonce_byte_count nonce bytes. This is enough for securely using
            // "random nonces". In most cases the number of label changes is likely to be so small
            // that a much smaller nonce should provide an adequate level of security. We append the
            // key to the nonce and use the combined buffer as input to Blake2xb to create the
            // pseudo-random byte stream for encryption.

            // Set up the result and create the nonce
            size_t encrypted_label_byte_count = nonce_byte_count + label_byte_count;
            EncryptedLabel result(encrypted_label_byte_count);
            random_bytes(result.data(), static_cast<unsigned int>(nonce_byte_count));

            // Fill result with mask from Blake2xb
            APSI_blake2xb(
                reinterpret_cast<uint8_t *>(result.data() + nonce_byte_count),
                label_byte_count,
                reinterpret_cast<const uint8_t *>(result.data()),
                nonce_byte_count,
                reinterpret_cast<const uint8_t *>(key.data()),
                label_key_byte_count);

            // XOR in the label
            xor_buffers(
                result.data() + nonce_byte_count,
                label.data(),
                min<size_t>(label.size(), label_byte_count));

            return result;
        }

        Label decrypt_label(
            const EncryptedLabel &encrypted_label, const LabelKey &key, size_t nonce_byte_count)
        {
            if (nonce_byte_count > max_nonce_byte_count) {
                throw invalid_argument("nonce_byte_count is too large");
            }
            if (encrypted_label.size() < nonce_byte_count) {
                throw invalid_argument("encrypted_label cannot be smaller than nonce_byte_count");
            }

            // Set up the result
            size_t label_byte_count = encrypted_label.size() - nonce_byte_count;
            Label result(label_byte_count);

            // Fill result with mask from Blake2xb
            APSI_blake2xb(
                reinterpret_cast<uint8_t *>(result.data()),
                label_byte_count,
                reinterpret_cast<const uint8_t *>(encrypted_label.data()),
                nonce_byte_count,
                reinterpret_cast<const uint8_t *>(key.data()),
                label_key_byte_count);

            // XOR in the encrypted label
            xor_buffers(result.data(), encrypted_label.data() + nonce_byte_count, label_byte_count);

            return result;
        }
    } // namespace util
} // namespace apsi
