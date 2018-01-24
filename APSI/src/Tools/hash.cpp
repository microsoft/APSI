//#include "Tools/hash.h"
//
//using namespace std;
//
//namespace apsi
//{
//    namespace tools
//    {
//        const HashFunction::aes_block_type HashFunction::zero_block(_mm_setzero_si128());
//
//        HashFunction::aes_block_type HashFunction::keygen_helper(aes_block_type key, aes_block_type key_rcon)
//        {
//            key_rcon = _mm_shuffle_epi32(key_rcon, _MM_SHUFFLE(3, 3, 3, 3));
//            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
//            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
//            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
//            return _mm_xor_si128(key, key_rcon);
//        }
//
//        inline HashFunction::aes_block_type HashFunction::set_block(std::uint64_t hw, std::uint64_t lw) const
//        {
//            return _mm_set_epi64x(hw, lw);
//        }
//
//        HashFunction::HashFunction(aes_block_type key)
//        {
//            aes_set_key(key);
//        }
//
//        void HashFunction::aes_set_key(const aes_block_type &key)
//        {
//            aes_round_key_[0] = key;
//            aes_round_key_[1] = keygen_helper(aes_round_key_[0], _mm_aeskeygenassist_si128(aes_round_key_[0], 0x01));
//            aes_round_key_[2] = keygen_helper(aes_round_key_[1], _mm_aeskeygenassist_si128(aes_round_key_[1], 0x02));
//            aes_round_key_[3] = keygen_helper(aes_round_key_[2], _mm_aeskeygenassist_si128(aes_round_key_[2], 0x04));
//            aes_round_key_[4] = keygen_helper(aes_round_key_[3], _mm_aeskeygenassist_si128(aes_round_key_[3], 0x08));
//            aes_round_key_[5] = keygen_helper(aes_round_key_[4], _mm_aeskeygenassist_si128(aes_round_key_[4], 0x10));
//            aes_round_key_[6] = keygen_helper(aes_round_key_[5], _mm_aeskeygenassist_si128(aes_round_key_[5], 0x20));
//            aes_round_key_[7] = keygen_helper(aes_round_key_[6], _mm_aeskeygenassist_si128(aes_round_key_[6], 0x40));
//            aes_round_key_[8] = keygen_helper(aes_round_key_[7], _mm_aeskeygenassist_si128(aes_round_key_[7], 0x80));
//            aes_round_key_[9] = keygen_helper(aes_round_key_[8], _mm_aeskeygenassist_si128(aes_round_key_[8], 0x1B));
//            aes_round_key_[10] = keygen_helper(aes_round_key_[9], _mm_aeskeygenassist_si128(aes_round_key_[9], 0x36));
//        }
//
//        void HashFunction::aes_encrypt(const aes_block_type &plaintext, aes_block_type &ciphertext) const
//        {
//            ciphertext = _mm_xor_si128(plaintext, aes_round_key_[0]);
//            ciphertext = _mm_aesenc_si128(ciphertext, aes_round_key_[1]);
//            ciphertext = _mm_aesenc_si128(ciphertext, aes_round_key_[2]);
//            ciphertext = _mm_aesenc_si128(ciphertext, aes_round_key_[3]);
//            ciphertext = _mm_aesenc_si128(ciphertext, aes_round_key_[4]);
//            ciphertext = _mm_aesenc_si128(ciphertext, aes_round_key_[5]);
//            ciphertext = _mm_aesenc_si128(ciphertext, aes_round_key_[6]);
//            ciphertext = _mm_aesenc_si128(ciphertext, aes_round_key_[7]);
//            ciphertext = _mm_aesenc_si128(ciphertext, aes_round_key_[8]);
//            ciphertext = _mm_aesenc_si128(ciphertext, aes_round_key_[9]);
//            ciphertext = _mm_aesenclast_si128(ciphertext, aes_round_key_[10]);
//        }
//
//        void HashFunction::operator() (const uint64_t *input, int uint64_count, aes_block_type &destination) const
//        {
//            int index = 0;
//            for (; index < uint64_count - 1; index += 2, input += 2)
//            {
//                // Encrypt XOR of destination and current block
//                aes_encrypt(_mm_xor_si128(*reinterpret_cast<const aes_block_type*>(input), destination), destination);
//            }
//
//            // Append possible last uint64 with zeros
//            if (index < uint64_count)
//            {
//                // Encrypt last block
//                aes_encrypt(_mm_xor_si128(set_block(0, *input), destination), destination);
//            }
//        }
//
//        void HashFunction::operator() (uint64_t input, aes_block_type &destination) const
//        {
//            aes_encrypt(_mm_xor_si128(set_block(0, input), destination), destination);
//        }
//    }
//}