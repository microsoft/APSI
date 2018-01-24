#pragma once
 
#include "seal/util/defines.h"
#include <array>
#include <cstdint>
#include <wmmintrin.h>

namespace apsi
{
    //namespace tools
    //{
    //    class HashFunction
    //    {
    //    public:
    //        typedef __m128i aes_block_type;

    //        HashFunction(aes_block_type key = zero_block);

    //        void operator() (const std::uint64_t *input, int uint64_count, aes_block_type &destination) const;

    //        void operator() (std::uint64_t input, aes_block_type &destination) const;

    //        static const aes_block_type zero_block;

    //    private:
    //        aes_block_type keygen_helper(aes_block_type key, aes_block_type key_rcon);

    //        inline aes_block_type set_block(std::uint64_t hw, std::uint64_t lw) const;

    //        void aes_set_key(const aes_block_type &key);

    //        void aes_encrypt(const aes_block_type &plaintext, aes_block_type &ciphertext) const;

    //        aes_block_type aes_round_key_[11];
    //    };
    //}
}
