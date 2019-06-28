// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#pragma once

#include "cuckoo/common.h"

namespace cuckoo
{
    class AESEnc
    {
    public:
        AESEnc() = default;

        AESEnc(const block &key);

        void set_key(const block &key);

        void ecb_encrypt(const block &plaintext, block &ciphertext) const;

        inline block ecb_encrypt(const block &plaintext) const
        {
            block ret;
            ecb_encrypt(plaintext, ret);
            return ret;
        }

        // ECB mode encryption
        void ecb_encrypt(const block *plaintext, u64 block_count, block *ciphertext) const;

        // Counter Mode encryption: encrypts the counter
        void counter_encrypt(u64 start_index, u64 block_count, block *ciphertext) const;

        // Counter Mode encryption: encrypts plaintext
        // TO DO

    private:
        block round_key_[11];
    };

    class AESDec
    {
    public:
        AESDec() = default;

        AESDec(const block &key);

        void set_key(const block &key);

        void ecb_decrypt(const block &ciphertext, block &plaintext);

        inline block ecb_decrypt(const block &ciphertext)
        {
            block ret;
            ecb_decrypt(ciphertext, ret);
            return ret;
        }

    private:
        block round_key_[11];
    };
}