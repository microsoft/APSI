// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#include "cuckoo/common.h"
#include "cuckoo/aes.h"

namespace cuckoo
{
    namespace
    {
        block keygen_helper(block key, block key_rcon)
        {
            key_rcon = _mm_shuffle_epi32(key_rcon, _MM_SHUFFLE(3, 3, 3, 3));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            return _mm_xor_si128(key, key_rcon);
        }
    }

    AESEnc::AESEnc(const block &key)
    {
        set_key(key);
    }

    void AESEnc::set_key(const block &key)
    {
        round_key_[0] = key;
        round_key_[1] = keygen_helper(round_key_[0], _mm_aeskeygenassist_si128(round_key_[0], 0x01));
        round_key_[2] = keygen_helper(round_key_[1], _mm_aeskeygenassist_si128(round_key_[1], 0x02));
        round_key_[3] = keygen_helper(round_key_[2], _mm_aeskeygenassist_si128(round_key_[2], 0x04));
        round_key_[4] = keygen_helper(round_key_[3], _mm_aeskeygenassist_si128(round_key_[3], 0x08));
        round_key_[5] = keygen_helper(round_key_[4], _mm_aeskeygenassist_si128(round_key_[4], 0x10));
        round_key_[6] = keygen_helper(round_key_[5], _mm_aeskeygenassist_si128(round_key_[5], 0x20));
        round_key_[7] = keygen_helper(round_key_[6], _mm_aeskeygenassist_si128(round_key_[6], 0x40));
        round_key_[8] = keygen_helper(round_key_[7], _mm_aeskeygenassist_si128(round_key_[7], 0x80));
        round_key_[9] = keygen_helper(round_key_[8], _mm_aeskeygenassist_si128(round_key_[8], 0x1B));
        round_key_[10] = keygen_helper(round_key_[9], _mm_aeskeygenassist_si128(round_key_[9], 0x36));
    }

    void AESEnc::ecb_encrypt(const block &plaintext, block &ciphertext) const
    {
        ciphertext = _mm_xor_si128(plaintext, round_key_[0]);
        ciphertext = _mm_aesenc_si128(ciphertext, round_key_[1]);
        ciphertext = _mm_aesenc_si128(ciphertext, round_key_[2]);
        ciphertext = _mm_aesenc_si128(ciphertext, round_key_[3]);
        ciphertext = _mm_aesenc_si128(ciphertext, round_key_[4]);
        ciphertext = _mm_aesenc_si128(ciphertext, round_key_[5]);
        ciphertext = _mm_aesenc_si128(ciphertext, round_key_[6]);
        ciphertext = _mm_aesenc_si128(ciphertext, round_key_[7]);
        ciphertext = _mm_aesenc_si128(ciphertext, round_key_[8]);
        ciphertext = _mm_aesenc_si128(ciphertext, round_key_[9]);
        ciphertext = _mm_aesenclast_si128(ciphertext, round_key_[10]);
    }

    void AESEnc::ecb_encrypt(const block *plaintext, u64 block_count, block *ciphertext) const
    {
        const u64 step = 8;
        u64 idx = 0;
        u64 length = block_count - block_count % step;

        for (; idx < length; idx += step)
        {
            ciphertext[idx + 0] = _mm_xor_si128(plaintext[idx + 0], round_key_[0]);
            ciphertext[idx + 1] = _mm_xor_si128(plaintext[idx + 1], round_key_[0]);
            ciphertext[idx + 2] = _mm_xor_si128(plaintext[idx + 2], round_key_[0]);
            ciphertext[idx + 3] = _mm_xor_si128(plaintext[idx + 3], round_key_[0]);
            ciphertext[idx + 4] = _mm_xor_si128(plaintext[idx + 4], round_key_[0]);
            ciphertext[idx + 5] = _mm_xor_si128(plaintext[idx + 5], round_key_[0]);
            ciphertext[idx + 6] = _mm_xor_si128(plaintext[idx + 6], round_key_[0]);
            ciphertext[idx + 7] = _mm_xor_si128(plaintext[idx + 7], round_key_[0]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[1]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[1]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[1]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[1]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[1]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[1]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[1]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[1]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[2]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[2]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[2]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[2]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[2]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[2]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[2]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[2]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[3]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[3]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[3]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[3]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[3]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[3]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[3]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[3]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[4]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[4]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[4]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[4]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[4]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[4]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[4]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[4]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[5]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[5]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[5]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[5]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[5]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[5]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[5]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[5]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[6]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[6]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[6]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[6]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[6]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[6]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[6]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[6]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[7]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[7]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[7]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[7]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[7]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[7]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[7]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[7]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[8]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[8]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[8]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[8]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[8]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[8]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[8]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[8]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[9]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[9]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[9]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[9]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[9]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[9]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[9]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[9]);

            ciphertext[idx + 0] = _mm_aesenclast_si128(ciphertext[idx + 0], round_key_[10]);
            ciphertext[idx + 1] = _mm_aesenclast_si128(ciphertext[idx + 1], round_key_[10]);
            ciphertext[idx + 2] = _mm_aesenclast_si128(ciphertext[idx + 2], round_key_[10]);
            ciphertext[idx + 3] = _mm_aesenclast_si128(ciphertext[idx + 3], round_key_[10]);
            ciphertext[idx + 4] = _mm_aesenclast_si128(ciphertext[idx + 4], round_key_[10]);
            ciphertext[idx + 5] = _mm_aesenclast_si128(ciphertext[idx + 5], round_key_[10]);
            ciphertext[idx + 6] = _mm_aesenclast_si128(ciphertext[idx + 6], round_key_[10]);
            ciphertext[idx + 7] = _mm_aesenclast_si128(ciphertext[idx + 7], round_key_[10]);
        }

        for (; idx < block_count; idx++)
        {
            ciphertext[idx] = _mm_xor_si128(plaintext[idx], round_key_[0]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[1]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[2]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[3]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[4]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[5]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[6]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[7]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[8]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[9]);
            ciphertext[idx] = _mm_aesenclast_si128(ciphertext[idx], round_key_[10]);
        }
    }

    void AESEnc::counter_encrypt(u64 start_index, u64 block_count, block *ciphertext) const
    {
        const u64 step = 8;
        u64 idx = 0;
        u64 length = block_count - block_count % step;

        for (; idx < length; idx += step, start_index += step)
        {
            ciphertext[idx + 0] = _mm_xor_si128(_mm_set_epi64x(0, start_index + 0), round_key_[0]);
            ciphertext[idx + 1] = _mm_xor_si128(_mm_set_epi64x(0, start_index + 1), round_key_[0]);
            ciphertext[idx + 2] = _mm_xor_si128(_mm_set_epi64x(0, start_index + 2), round_key_[0]);
            ciphertext[idx + 3] = _mm_xor_si128(_mm_set_epi64x(0, start_index + 3), round_key_[0]);
            ciphertext[idx + 4] = _mm_xor_si128(_mm_set_epi64x(0, start_index + 4), round_key_[0]);
            ciphertext[idx + 5] = _mm_xor_si128(_mm_set_epi64x(0, start_index + 5), round_key_[0]);
            ciphertext[idx + 6] = _mm_xor_si128(_mm_set_epi64x(0, start_index + 6), round_key_[0]);
            ciphertext[idx + 7] = _mm_xor_si128(_mm_set_epi64x(0, start_index + 7), round_key_[0]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[1]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[1]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[1]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[1]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[1]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[1]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[1]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[1]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[2]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[2]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[2]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[2]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[2]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[2]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[2]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[2]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[3]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[3]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[3]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[3]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[3]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[3]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[3]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[3]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[4]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[4]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[4]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[4]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[4]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[4]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[4]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[4]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[5]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[5]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[5]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[5]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[5]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[5]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[5]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[5]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[6]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[6]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[6]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[6]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[6]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[6]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[6]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[6]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[7]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[7]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[7]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[7]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[7]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[7]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[7]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[7]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[8]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[8]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[8]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[8]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[8]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[8]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[8]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[8]);

            ciphertext[idx + 0] = _mm_aesenc_si128(ciphertext[idx + 0], round_key_[9]);
            ciphertext[idx + 1] = _mm_aesenc_si128(ciphertext[idx + 1], round_key_[9]);
            ciphertext[idx + 2] = _mm_aesenc_si128(ciphertext[idx + 2], round_key_[9]);
            ciphertext[idx + 3] = _mm_aesenc_si128(ciphertext[idx + 3], round_key_[9]);
            ciphertext[idx + 4] = _mm_aesenc_si128(ciphertext[idx + 4], round_key_[9]);
            ciphertext[idx + 5] = _mm_aesenc_si128(ciphertext[idx + 5], round_key_[9]);
            ciphertext[idx + 6] = _mm_aesenc_si128(ciphertext[idx + 6], round_key_[9]);
            ciphertext[idx + 7] = _mm_aesenc_si128(ciphertext[idx + 7], round_key_[9]);

            ciphertext[idx + 0] = _mm_aesenclast_si128(ciphertext[idx + 0], round_key_[10]);
            ciphertext[idx + 1] = _mm_aesenclast_si128(ciphertext[idx + 1], round_key_[10]);
            ciphertext[idx + 2] = _mm_aesenclast_si128(ciphertext[idx + 2], round_key_[10]);
            ciphertext[idx + 3] = _mm_aesenclast_si128(ciphertext[idx + 3], round_key_[10]);
            ciphertext[idx + 4] = _mm_aesenclast_si128(ciphertext[idx + 4], round_key_[10]);
            ciphertext[idx + 5] = _mm_aesenclast_si128(ciphertext[idx + 5], round_key_[10]);
            ciphertext[idx + 6] = _mm_aesenclast_si128(ciphertext[idx + 6], round_key_[10]);
            ciphertext[idx + 7] = _mm_aesenclast_si128(ciphertext[idx + 7], round_key_[10]);
        }

        for (; idx < block_count; idx++, start_index++)
        {
            ciphertext[idx] = _mm_xor_si128(_mm_set_epi64x(0, start_index), round_key_[0]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[1]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[2]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[3]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[4]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[5]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[6]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[7]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[8]);
            ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], round_key_[9]);
            ciphertext[idx] = _mm_aesenclast_si128(ciphertext[idx], round_key_[10]);
        }
    }

    AESDec::AESDec(const block &key)
    {
        set_key(key);
    }

    void AESDec::set_key(const block &key)
    {
        const block &v0 = key;
        const block v1 = keygen_helper(v0, _mm_aeskeygenassist_si128(v0, 0x01));
        const block v2 = keygen_helper(v1, _mm_aeskeygenassist_si128(v1, 0x02));
        const block v3 = keygen_helper(v2, _mm_aeskeygenassist_si128(v2, 0x04));
        const block v4 = keygen_helper(v3, _mm_aeskeygenassist_si128(v3, 0x08));
        const block v5 = keygen_helper(v4, _mm_aeskeygenassist_si128(v4, 0x10));
        const block v6 = keygen_helper(v5, _mm_aeskeygenassist_si128(v5, 0x20));
        const block v7 = keygen_helper(v6, _mm_aeskeygenassist_si128(v6, 0x40));
        const block v8 = keygen_helper(v7, _mm_aeskeygenassist_si128(v7, 0x80));
        const block v9 = keygen_helper(v8, _mm_aeskeygenassist_si128(v8, 0x1B));
        const block v10 = keygen_helper(v9, _mm_aeskeygenassist_si128(v9, 0x36));

        _mm_storeu_si128(round_key_, v10);
        _mm_storeu_si128(round_key_ + 1, _mm_aesimc_si128(v9));
        _mm_storeu_si128(round_key_ + 2, _mm_aesimc_si128(v8));
        _mm_storeu_si128(round_key_ + 3, _mm_aesimc_si128(v7));
        _mm_storeu_si128(round_key_ + 4, _mm_aesimc_si128(v6));
        _mm_storeu_si128(round_key_ + 5, _mm_aesimc_si128(v5));
        _mm_storeu_si128(round_key_ + 6, _mm_aesimc_si128(v4));
        _mm_storeu_si128(round_key_ + 7, _mm_aesimc_si128(v3));
        _mm_storeu_si128(round_key_ + 8, _mm_aesimc_si128(v2));
        _mm_storeu_si128(round_key_ + 9, _mm_aesimc_si128(v1));
        _mm_storeu_si128(round_key_ + 10, v0);
    }

    void AESDec::ecb_decrypt(const block &ciphertext, block &plaintext)
    {
        plaintext = _mm_xor_si128(ciphertext, round_key_[0]);
        plaintext = _mm_aesdec_si128(plaintext, round_key_[1]);
        plaintext = _mm_aesdec_si128(plaintext, round_key_[2]);
        plaintext = _mm_aesdec_si128(plaintext, round_key_[3]);
        plaintext = _mm_aesdec_si128(plaintext, round_key_[4]);
        plaintext = _mm_aesdec_si128(plaintext, round_key_[5]);
        plaintext = _mm_aesdec_si128(plaintext, round_key_[6]);
        plaintext = _mm_aesdec_si128(plaintext, round_key_[7]);
        plaintext = _mm_aesdec_si128(plaintext, round_key_[8]);
        plaintext = _mm_aesdec_si128(plaintext, round_key_[9]);
        plaintext = _mm_aesdeclast_si128(plaintext, round_key_[10]);
    }
}