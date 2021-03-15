// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

// APSI
#include "apsi/util/label_encryptor.h"

// Sodium
#include "sodium/crypto_stream_xchacha20.h"

// SEAL
#include "seal/randomgen.h"

using namespace std;
using namespace seal;

namespace apsi
{
    namespace util
    {
        EncryptedLabel encrypt_label(
            Label label,
            const LabelKey &key,
            size_t label_byte_count,
            size_t nonce_byte_count)
        {
            if (nonce_byte_count > 16)
            {
                throw invalid_argument("nonce can be at most 16 bytes");
            }

            // Sample a random nonce; we only use up to 16 of the 24 nonce bytes for XChaCha20 and set the rest to
            // zero. This is enough for securely using "random nonces". In most cases the number of label changes is
            // likely to be so small that a much smaller nonce should provide an adequate level of security.
            array<unsigned char, 24> nonce{};
            random_bytes(reinterpret_cast<seal_byte*>(nonce.data()), nonce_byte_count);

            size_t encrypted_label_byte_count = label_byte_count + nonce_byte_count;

            // Resize the label to label_byte_count; truncate or pad with zeros if necessary
            label.resize(label_byte_count, 0);

            // Set up the result, copy the nonce, and encrypt
            EncryptedLabel result(encrypted_label_byte_count);
            copy_n(nonce.cbegin(), nonce_byte_count, result.begin());

            crypto_stream_xchacha20_xor(
                result.data() + nonce_byte_count,
                label.data(),
                label_byte_count,
                nonce.data(),
                key.data());

            return result;
        }

        Label decrypt_label(const EncryptedLabel &encrypted_label, const LabelKey &key, size_t nonce_byte_count)
        {
            if (nonce_byte_count > 16)
            {
                throw invalid_argument("nonce can be at most 16 bytes");
            }
            if (encrypted_label.size() < nonce_byte_count)
            {
                throw invalid_argument("encrypted_label cannot be smaller than nonce_byte_count");
            }

            // Read the nonce; we only use up to 16 of the 24 nonce bytes for XChaCha20 and set the rest to zero.
            array<unsigned char, 24> nonce{};
            copy_n(encrypted_label.cbegin(), nonce_byte_count, nonce.begin());

            // Set up the result and decrypt
            size_t label_byte_count = encrypted_label.size() - nonce_byte_count;
            Label result;
            result.resize(label_byte_count);
            crypto_stream_xchacha20_xor(
                result.data(),
                encrypted_label.data() + nonce_byte_count,
                label_byte_count,
                nonce.data(),
                key.data());

            return result;
        }
    }
}