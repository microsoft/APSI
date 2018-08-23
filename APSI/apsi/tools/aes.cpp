#include "aes.h"

#include <array>

using namespace apsi;
using namespace apsi::tools;

namespace
{
    block key_gen_helper(block key, block key_rcon)
    {
        key_rcon = _mm_shuffle_epi32(key_rcon, _MM_SHUFFLE(3, 3, 3, 3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        return _mm_xor_si128(key, key_rcon);
    }
}

AES::AES(const block & user_key)
{
    set_key(user_key);
}

void AES::set_key(const block & user_key)
{
    round_key_[0] = user_key;
    round_key_[1] = key_gen_helper(round_key_[0], _mm_aeskeygenassist_si128(round_key_[0], 0x01));
    round_key_[2] = key_gen_helper(round_key_[1], _mm_aeskeygenassist_si128(round_key_[1], 0x02));
    round_key_[3] = key_gen_helper(round_key_[2], _mm_aeskeygenassist_si128(round_key_[2], 0x04));
    round_key_[4] = key_gen_helper(round_key_[3], _mm_aeskeygenassist_si128(round_key_[3], 0x08));
    round_key_[5] = key_gen_helper(round_key_[4], _mm_aeskeygenassist_si128(round_key_[4], 0x10));
    round_key_[6] = key_gen_helper(round_key_[5], _mm_aeskeygenassist_si128(round_key_[5], 0x20));
    round_key_[7] = key_gen_helper(round_key_[6], _mm_aeskeygenassist_si128(round_key_[6], 0x40));
    round_key_[8] = key_gen_helper(round_key_[7], _mm_aeskeygenassist_si128(round_key_[7], 0x80));
    round_key_[9] = key_gen_helper(round_key_[8], _mm_aeskeygenassist_si128(round_key_[8], 0x1B));
    round_key_[10] = key_gen_helper(round_key_[9], _mm_aeskeygenassist_si128(round_key_[9], 0x36));
}

void  AES::ecb_enc_block(const block & plaintext, block & cyphertext) const
{
    cyphertext = _mm_xor_si128(plaintext, round_key_[0]);
    cyphertext = _mm_aesenc_si128(cyphertext, round_key_[1]);
    cyphertext = _mm_aesenc_si128(cyphertext, round_key_[2]);
    cyphertext = _mm_aesenc_si128(cyphertext, round_key_[3]);
    cyphertext = _mm_aesenc_si128(cyphertext, round_key_[4]);
    cyphertext = _mm_aesenc_si128(cyphertext, round_key_[5]);
    cyphertext = _mm_aesenc_si128(cyphertext, round_key_[6]);
    cyphertext = _mm_aesenc_si128(cyphertext, round_key_[7]);
    cyphertext = _mm_aesenc_si128(cyphertext, round_key_[8]);
    cyphertext = _mm_aesenc_si128(cyphertext, round_key_[9]);
    cyphertext = _mm_aesenclast_si128(cyphertext, round_key_[10]);
}

block AES::ecb_enc_block(const block & plaintext) const
{
    block ret;
    ecb_enc_block(plaintext, ret);
    return ret;
}

void AES::ecb_enc_blocks(const block * plaintexts, u64 block_length, block * cyphertext) const
{
    const u64 step = 8;
    u64 idx = 0;
    u64 length = block_length - block_length % step;

    block temp[step];

    for (; idx < length; idx += step)
    {
        temp[0] = _mm_xor_si128(plaintexts[idx + 0], round_key_[0]);
        temp[1] = _mm_xor_si128(plaintexts[idx + 1], round_key_[0]);
        temp[2] = _mm_xor_si128(plaintexts[idx + 2], round_key_[0]);
        temp[3] = _mm_xor_si128(plaintexts[idx + 3], round_key_[0]);
        temp[4] = _mm_xor_si128(plaintexts[idx + 4], round_key_[0]);
        temp[5] = _mm_xor_si128(plaintexts[idx + 5], round_key_[0]);
        temp[6] = _mm_xor_si128(plaintexts[idx + 6], round_key_[0]);
        temp[7] = _mm_xor_si128(plaintexts[idx + 7], round_key_[0]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[1]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[1]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[1]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[1]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[1]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[1]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[1]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[1]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[2]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[2]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[2]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[2]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[2]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[2]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[2]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[2]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[3]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[3]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[3]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[3]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[3]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[3]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[3]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[3]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[4]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[4]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[4]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[4]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[4]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[4]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[4]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[4]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[5]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[5]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[5]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[5]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[5]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[5]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[5]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[5]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[6]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[6]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[6]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[6]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[6]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[6]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[6]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[6]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[7]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[7]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[7]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[7]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[7]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[7]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[7]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[7]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[8]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[8]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[8]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[8]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[8]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[8]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[8]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[8]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[9]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[9]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[9]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[9]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[9]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[9]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[9]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[9]);

        cyphertext[idx + 0] = _mm_aesenclast_si128(temp[0], round_key_[10]);
        cyphertext[idx + 1] = _mm_aesenclast_si128(temp[1], round_key_[10]);
        cyphertext[idx + 2] = _mm_aesenclast_si128(temp[2], round_key_[10]);
        cyphertext[idx + 3] = _mm_aesenclast_si128(temp[3], round_key_[10]);
        cyphertext[idx + 4] = _mm_aesenclast_si128(temp[4], round_key_[10]);
        cyphertext[idx + 5] = _mm_aesenclast_si128(temp[5], round_key_[10]);
        cyphertext[idx + 6] = _mm_aesenclast_si128(temp[6], round_key_[10]);
        cyphertext[idx + 7] = _mm_aesenclast_si128(temp[7], round_key_[10]);
    }

    for (; idx < block_length; ++idx)
    {
        cyphertext[idx] = _mm_xor_si128(plaintexts[idx], round_key_[0]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[1]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[2]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[3]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[4]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[5]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[6]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[7]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[8]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[9]);
        cyphertext[idx] = _mm_aesenclast_si128(cyphertext[idx], round_key_[10]);
    }
}


void AES::ecb_enc_two_blocks(const block * plaintexts, block * cyphertext) const
{
    cyphertext[0] = _mm_xor_si128(plaintexts[0], round_key_[0]);
    cyphertext[1] = _mm_xor_si128(plaintexts[1], round_key_[0]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[1]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[1]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[2]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[2]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[3]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[3]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[4]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[4]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[5]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[5]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[6]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[6]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[7]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[7]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[8]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[8]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[9]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[9]);

    cyphertext[0] = _mm_aesenclast_si128(cyphertext[0], round_key_[10]);
    cyphertext[1] = _mm_aesenclast_si128(cyphertext[1], round_key_[10]);
}

void AES::ecb_enc_four_blocks(const block * plaintexts, block * cyphertext) const
{
    cyphertext[0] = _mm_xor_si128(plaintexts[0], round_key_[0]);
    cyphertext[1] = _mm_xor_si128(plaintexts[1], round_key_[0]);
    cyphertext[2] = _mm_xor_si128(plaintexts[2], round_key_[0]);
    cyphertext[3] = _mm_xor_si128(plaintexts[3], round_key_[0]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[1]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[1]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[1]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[1]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[2]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[2]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[2]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[2]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[3]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[3]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[3]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[3]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[4]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[4]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[4]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[4]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[5]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[5]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[5]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[5]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[6]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[6]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[6]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[6]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[7]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[7]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[7]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[7]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[8]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[8]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[8]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[8]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[9]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[9]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[9]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[9]);

    cyphertext[0] = _mm_aesenclast_si128(cyphertext[0], round_key_[10]);
    cyphertext[1] = _mm_aesenclast_si128(cyphertext[1], round_key_[10]);
    cyphertext[2] = _mm_aesenclast_si128(cyphertext[2], round_key_[10]);
    cyphertext[3] = _mm_aesenclast_si128(cyphertext[3], round_key_[10]);
}

void AES::ecb_enc_16_blocks(const block * plaintexts, block * cyphertext) const
{
    cyphertext[0] = _mm_xor_si128(plaintexts[0], round_key_[0]);
    cyphertext[1] = _mm_xor_si128(plaintexts[1], round_key_[0]);
    cyphertext[2] = _mm_xor_si128(plaintexts[2], round_key_[0]);
    cyphertext[3] = _mm_xor_si128(plaintexts[3], round_key_[0]);
    cyphertext[4] = _mm_xor_si128(plaintexts[4], round_key_[0]);
    cyphertext[5] = _mm_xor_si128(plaintexts[5], round_key_[0]);
    cyphertext[6] = _mm_xor_si128(plaintexts[6], round_key_[0]);
    cyphertext[7] = _mm_xor_si128(plaintexts[7], round_key_[0]);
    cyphertext[8] = _mm_xor_si128(plaintexts[8], round_key_[0]);
    cyphertext[9] = _mm_xor_si128(plaintexts[9], round_key_[0]);
    cyphertext[10] = _mm_xor_si128(plaintexts[10], round_key_[0]);
    cyphertext[11] = _mm_xor_si128(plaintexts[11], round_key_[0]);
    cyphertext[12] = _mm_xor_si128(plaintexts[12], round_key_[0]);
    cyphertext[13] = _mm_xor_si128(plaintexts[13], round_key_[0]);
    cyphertext[14] = _mm_xor_si128(plaintexts[14], round_key_[0]);
    cyphertext[15] = _mm_xor_si128(plaintexts[15], round_key_[0]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[1]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[1]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[1]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[1]);
    cyphertext[4] = _mm_aesenc_si128(cyphertext[4], round_key_[1]);
    cyphertext[5] = _mm_aesenc_si128(cyphertext[5], round_key_[1]);
    cyphertext[6] = _mm_aesenc_si128(cyphertext[6], round_key_[1]);
    cyphertext[7] = _mm_aesenc_si128(cyphertext[7], round_key_[1]);
    cyphertext[8] = _mm_aesenc_si128(cyphertext[8], round_key_[1]);
    cyphertext[9] = _mm_aesenc_si128(cyphertext[9], round_key_[1]);
    cyphertext[10] = _mm_aesenc_si128(cyphertext[10], round_key_[1]);
    cyphertext[11] = _mm_aesenc_si128(cyphertext[11], round_key_[1]);
    cyphertext[12] = _mm_aesenc_si128(cyphertext[12], round_key_[1]);
    cyphertext[13] = _mm_aesenc_si128(cyphertext[13], round_key_[1]);
    cyphertext[14] = _mm_aesenc_si128(cyphertext[14], round_key_[1]);
    cyphertext[15] = _mm_aesenc_si128(cyphertext[15], round_key_[1]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[2]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[2]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[2]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[2]);
    cyphertext[4] = _mm_aesenc_si128(cyphertext[4], round_key_[2]);
    cyphertext[5] = _mm_aesenc_si128(cyphertext[5], round_key_[2]);
    cyphertext[6] = _mm_aesenc_si128(cyphertext[6], round_key_[2]);
    cyphertext[7] = _mm_aesenc_si128(cyphertext[7], round_key_[2]);
    cyphertext[8] = _mm_aesenc_si128(cyphertext[8], round_key_[2]);
    cyphertext[9] = _mm_aesenc_si128(cyphertext[9], round_key_[2]);
    cyphertext[10] = _mm_aesenc_si128(cyphertext[10], round_key_[2]);
    cyphertext[11] = _mm_aesenc_si128(cyphertext[11], round_key_[2]);
    cyphertext[12] = _mm_aesenc_si128(cyphertext[12], round_key_[2]);
    cyphertext[13] = _mm_aesenc_si128(cyphertext[13], round_key_[2]);
    cyphertext[14] = _mm_aesenc_si128(cyphertext[14], round_key_[2]);
    cyphertext[15] = _mm_aesenc_si128(cyphertext[15], round_key_[2]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[3]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[3]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[3]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[3]);
    cyphertext[4] = _mm_aesenc_si128(cyphertext[4], round_key_[3]);
    cyphertext[5] = _mm_aesenc_si128(cyphertext[5], round_key_[3]);
    cyphertext[6] = _mm_aesenc_si128(cyphertext[6], round_key_[3]);
    cyphertext[7] = _mm_aesenc_si128(cyphertext[7], round_key_[3]);
    cyphertext[8] = _mm_aesenc_si128(cyphertext[8], round_key_[3]);
    cyphertext[9] = _mm_aesenc_si128(cyphertext[9], round_key_[3]);
    cyphertext[10] = _mm_aesenc_si128(cyphertext[10], round_key_[3]);
    cyphertext[11] = _mm_aesenc_si128(cyphertext[11], round_key_[3]);
    cyphertext[12] = _mm_aesenc_si128(cyphertext[12], round_key_[3]);
    cyphertext[13] = _mm_aesenc_si128(cyphertext[13], round_key_[3]);
    cyphertext[14] = _mm_aesenc_si128(cyphertext[14], round_key_[3]);
    cyphertext[15] = _mm_aesenc_si128(cyphertext[15], round_key_[3]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[4]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[4]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[4]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[4]);
    cyphertext[4] = _mm_aesenc_si128(cyphertext[4], round_key_[4]);
    cyphertext[5] = _mm_aesenc_si128(cyphertext[5], round_key_[4]);
    cyphertext[6] = _mm_aesenc_si128(cyphertext[6], round_key_[4]);
    cyphertext[7] = _mm_aesenc_si128(cyphertext[7], round_key_[4]);
    cyphertext[8] = _mm_aesenc_si128(cyphertext[8], round_key_[4]);
    cyphertext[9] = _mm_aesenc_si128(cyphertext[9], round_key_[4]);
    cyphertext[10] = _mm_aesenc_si128(cyphertext[10], round_key_[4]);
    cyphertext[11] = _mm_aesenc_si128(cyphertext[11], round_key_[4]);
    cyphertext[12] = _mm_aesenc_si128(cyphertext[12], round_key_[4]);
    cyphertext[13] = _mm_aesenc_si128(cyphertext[13], round_key_[4]);
    cyphertext[14] = _mm_aesenc_si128(cyphertext[14], round_key_[4]);
    cyphertext[15] = _mm_aesenc_si128(cyphertext[15], round_key_[4]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[5]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[5]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[5]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[5]);
    cyphertext[4] = _mm_aesenc_si128(cyphertext[4], round_key_[5]);
    cyphertext[5] = _mm_aesenc_si128(cyphertext[5], round_key_[5]);
    cyphertext[6] = _mm_aesenc_si128(cyphertext[6], round_key_[5]);
    cyphertext[7] = _mm_aesenc_si128(cyphertext[7], round_key_[5]);
    cyphertext[8] = _mm_aesenc_si128(cyphertext[8], round_key_[5]);
    cyphertext[9] = _mm_aesenc_si128(cyphertext[9], round_key_[5]);
    cyphertext[10] = _mm_aesenc_si128(cyphertext[10], round_key_[5]);
    cyphertext[11] = _mm_aesenc_si128(cyphertext[11], round_key_[5]);
    cyphertext[12] = _mm_aesenc_si128(cyphertext[12], round_key_[5]);
    cyphertext[13] = _mm_aesenc_si128(cyphertext[13], round_key_[5]);
    cyphertext[14] = _mm_aesenc_si128(cyphertext[14], round_key_[5]);
    cyphertext[15] = _mm_aesenc_si128(cyphertext[15], round_key_[5]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[6]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[6]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[6]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[6]);
    cyphertext[4] = _mm_aesenc_si128(cyphertext[4], round_key_[6]);
    cyphertext[5] = _mm_aesenc_si128(cyphertext[5], round_key_[6]);
    cyphertext[6] = _mm_aesenc_si128(cyphertext[6], round_key_[6]);
    cyphertext[7] = _mm_aesenc_si128(cyphertext[7], round_key_[6]);
    cyphertext[8] = _mm_aesenc_si128(cyphertext[8], round_key_[6]);
    cyphertext[9] = _mm_aesenc_si128(cyphertext[9], round_key_[6]);
    cyphertext[10] = _mm_aesenc_si128(cyphertext[10], round_key_[6]);
    cyphertext[11] = _mm_aesenc_si128(cyphertext[11], round_key_[6]);
    cyphertext[12] = _mm_aesenc_si128(cyphertext[12], round_key_[6]);
    cyphertext[13] = _mm_aesenc_si128(cyphertext[13], round_key_[6]);
    cyphertext[14] = _mm_aesenc_si128(cyphertext[14], round_key_[6]);
    cyphertext[15] = _mm_aesenc_si128(cyphertext[15], round_key_[6]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[7]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[7]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[7]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[7]);
    cyphertext[4] = _mm_aesenc_si128(cyphertext[4], round_key_[7]);
    cyphertext[5] = _mm_aesenc_si128(cyphertext[5], round_key_[7]);
    cyphertext[6] = _mm_aesenc_si128(cyphertext[6], round_key_[7]);
    cyphertext[7] = _mm_aesenc_si128(cyphertext[7], round_key_[7]);
    cyphertext[8] = _mm_aesenc_si128(cyphertext[8], round_key_[7]);
    cyphertext[9] = _mm_aesenc_si128(cyphertext[9], round_key_[7]);
    cyphertext[10] = _mm_aesenc_si128(cyphertext[10], round_key_[7]);
    cyphertext[11] = _mm_aesenc_si128(cyphertext[11], round_key_[7]);
    cyphertext[12] = _mm_aesenc_si128(cyphertext[12], round_key_[7]);
    cyphertext[13] = _mm_aesenc_si128(cyphertext[13], round_key_[7]);
    cyphertext[14] = _mm_aesenc_si128(cyphertext[14], round_key_[7]);
    cyphertext[15] = _mm_aesenc_si128(cyphertext[15], round_key_[7]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[8]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[8]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[8]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[8]);
    cyphertext[4] = _mm_aesenc_si128(cyphertext[4], round_key_[8]);
    cyphertext[5] = _mm_aesenc_si128(cyphertext[5], round_key_[8]);
    cyphertext[6] = _mm_aesenc_si128(cyphertext[6], round_key_[8]);
    cyphertext[7] = _mm_aesenc_si128(cyphertext[7], round_key_[8]);
    cyphertext[8] = _mm_aesenc_si128(cyphertext[8], round_key_[8]);
    cyphertext[9] = _mm_aesenc_si128(cyphertext[9], round_key_[8]);
    cyphertext[10] = _mm_aesenc_si128(cyphertext[10], round_key_[8]);
    cyphertext[11] = _mm_aesenc_si128(cyphertext[11], round_key_[8]);
    cyphertext[12] = _mm_aesenc_si128(cyphertext[12], round_key_[8]);
    cyphertext[13] = _mm_aesenc_si128(cyphertext[13], round_key_[8]);
    cyphertext[14] = _mm_aesenc_si128(cyphertext[14], round_key_[8]);
    cyphertext[15] = _mm_aesenc_si128(cyphertext[15], round_key_[8]);

    cyphertext[0] = _mm_aesenc_si128(cyphertext[0], round_key_[9]);
    cyphertext[1] = _mm_aesenc_si128(cyphertext[1], round_key_[9]);
    cyphertext[2] = _mm_aesenc_si128(cyphertext[2], round_key_[9]);
    cyphertext[3] = _mm_aesenc_si128(cyphertext[3], round_key_[9]);
    cyphertext[4] = _mm_aesenc_si128(cyphertext[4], round_key_[9]);
    cyphertext[5] = _mm_aesenc_si128(cyphertext[5], round_key_[9]);
    cyphertext[6] = _mm_aesenc_si128(cyphertext[6], round_key_[9]);
    cyphertext[7] = _mm_aesenc_si128(cyphertext[7], round_key_[9]);
    cyphertext[8] = _mm_aesenc_si128(cyphertext[8], round_key_[9]);
    cyphertext[9] = _mm_aesenc_si128(cyphertext[9], round_key_[9]);
    cyphertext[10] = _mm_aesenc_si128(cyphertext[10], round_key_[9]);
    cyphertext[11] = _mm_aesenc_si128(cyphertext[11], round_key_[9]);
    cyphertext[12] = _mm_aesenc_si128(cyphertext[12], round_key_[9]);
    cyphertext[13] = _mm_aesenc_si128(cyphertext[13], round_key_[9]);
    cyphertext[14] = _mm_aesenc_si128(cyphertext[14], round_key_[9]);
    cyphertext[15] = _mm_aesenc_si128(cyphertext[15], round_key_[9]);

    cyphertext[0] = _mm_aesenclast_si128(cyphertext[0], round_key_[10]);
    cyphertext[1] = _mm_aesenclast_si128(cyphertext[1], round_key_[10]);
    cyphertext[2] = _mm_aesenclast_si128(cyphertext[2], round_key_[10]);
    cyphertext[3] = _mm_aesenclast_si128(cyphertext[3], round_key_[10]);
    cyphertext[4] = _mm_aesenclast_si128(cyphertext[4], round_key_[10]);
    cyphertext[5] = _mm_aesenclast_si128(cyphertext[5], round_key_[10]);
    cyphertext[6] = _mm_aesenclast_si128(cyphertext[6], round_key_[10]);
    cyphertext[7] = _mm_aesenclast_si128(cyphertext[7], round_key_[10]);
    cyphertext[8] = _mm_aesenclast_si128(cyphertext[8], round_key_[10]);
    cyphertext[9] = _mm_aesenclast_si128(cyphertext[9], round_key_[10]);
    cyphertext[10] = _mm_aesenclast_si128(cyphertext[10], round_key_[10]);
    cyphertext[11] = _mm_aesenclast_si128(cyphertext[11], round_key_[10]);
    cyphertext[12] = _mm_aesenclast_si128(cyphertext[12], round_key_[10]);
    cyphertext[13] = _mm_aesenclast_si128(cyphertext[13], round_key_[10]);
    cyphertext[14] = _mm_aesenclast_si128(cyphertext[14], round_key_[10]);
    cyphertext[15] = _mm_aesenclast_si128(cyphertext[15], round_key_[10]);
}

void AES::ecb_enc_counter_mode(u64 base_idx, u64 block_length, block * cyphertext) const
{
    const i32 step = 8;
    i32 idx = 0;
    i32 length = block_length - block_length % step;

    block temp[step];

    for (; idx < length; idx += step, base_idx += step)
    {
        temp[0] = _mm_xor_si128(_mm_set1_epi64x(base_idx + 0), round_key_[0]);
        temp[1] = _mm_xor_si128(_mm_set1_epi64x(base_idx + 1), round_key_[0]);
        temp[2] = _mm_xor_si128(_mm_set1_epi64x(base_idx + 2), round_key_[0]);
        temp[3] = _mm_xor_si128(_mm_set1_epi64x(base_idx + 3), round_key_[0]);
        temp[4] = _mm_xor_si128(_mm_set1_epi64x(base_idx + 4), round_key_[0]);
        temp[5] = _mm_xor_si128(_mm_set1_epi64x(base_idx + 5), round_key_[0]);
        temp[6] = _mm_xor_si128(_mm_set1_epi64x(base_idx + 6), round_key_[0]);
        temp[7] = _mm_xor_si128(_mm_set1_epi64x(base_idx + 7), round_key_[0]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[1]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[1]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[1]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[1]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[1]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[1]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[1]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[1]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[2]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[2]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[2]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[2]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[2]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[2]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[2]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[2]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[3]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[3]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[3]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[3]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[3]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[3]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[3]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[3]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[4]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[4]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[4]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[4]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[4]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[4]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[4]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[4]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[5]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[5]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[5]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[5]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[5]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[5]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[5]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[5]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[6]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[6]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[6]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[6]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[6]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[6]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[6]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[6]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[7]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[7]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[7]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[7]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[7]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[7]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[7]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[7]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[8]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[8]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[8]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[8]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[8]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[8]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[8]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[8]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key_[9]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key_[9]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key_[9]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key_[9]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key_[9]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key_[9]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key_[9]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key_[9]);

        cyphertext[idx + 0] = _mm_aesenclast_si128(temp[0], round_key_[10]);
        cyphertext[idx + 1] = _mm_aesenclast_si128(temp[1], round_key_[10]);
        cyphertext[idx + 2] = _mm_aesenclast_si128(temp[2], round_key_[10]);
        cyphertext[idx + 3] = _mm_aesenclast_si128(temp[3], round_key_[10]);
        cyphertext[idx + 4] = _mm_aesenclast_si128(temp[4], round_key_[10]);
        cyphertext[idx + 5] = _mm_aesenclast_si128(temp[5], round_key_[10]);
        cyphertext[idx + 6] = _mm_aesenclast_si128(temp[6], round_key_[10]);
        cyphertext[idx + 7] = _mm_aesenclast_si128(temp[7], round_key_[10]);
    }

    for (; idx < static_cast<i32>(block_length); ++idx, ++base_idx)
    {
        cyphertext[idx] = _mm_xor_si128(_mm_set1_epi64x(base_idx), round_key_[0]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[1]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[2]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[3]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[4]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[5]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[6]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[7]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[8]);
        cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], round_key_[9]);
        cyphertext[idx] = _mm_aesenclast_si128(cyphertext[idx], round_key_[10]);
    }
}

void AES::clear(AES& a)
{
    memset(a.round_key_, 0, key_elem_count * sizeof(block));
}


AESDec::AESDec(const block & user_key)
{
    set_key(user_key);
}

void AESDec::set_key(const block & user_key)
{
    const block& v0 = user_key;
    const block  v1 = key_gen_helper(v0, _mm_aeskeygenassist_si128(v0, 0x01));
    const block  v2 = key_gen_helper(v1, _mm_aeskeygenassist_si128(v1, 0x02));
    const block  v3 = key_gen_helper(v2, _mm_aeskeygenassist_si128(v2, 0x04));
    const block  v4 = key_gen_helper(v3, _mm_aeskeygenassist_si128(v3, 0x08));
    const block  v5 = key_gen_helper(v4, _mm_aeskeygenassist_si128(v4, 0x10));
    const block  v6 = key_gen_helper(v5, _mm_aeskeygenassist_si128(v5, 0x20));
    const block  v7 = key_gen_helper(v6, _mm_aeskeygenassist_si128(v6, 0x40));
    const block  v8 = key_gen_helper(v7, _mm_aeskeygenassist_si128(v7, 0x80));
    const block  v9 = key_gen_helper(v8, _mm_aeskeygenassist_si128(v8, 0x1B));
    const block  v10 = key_gen_helper(v9, _mm_aeskeygenassist_si128(v9, 0x36));


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

void  AESDec::ecb_dec_block(const block & cyphertext, block & plaintext)
{
    plaintext = _mm_xor_si128(cyphertext, round_key_[0]);
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

block AESDec::ecb_dec_block(const block & cyphertext)
{
    block plaintext;
    ecb_dec_block(cyphertext, plaintext);
    return plaintext;
}
