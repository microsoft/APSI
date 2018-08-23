#pragma once

#include <wmmintrin.h>

#include "apsi/apsidefines.h"

namespace apsi
{
    namespace tools
    {
        /**
        * An AES-NI implemenation of AES encryption. 
        */
        class AES
        {
        public:

            /**
            * Default constructor leave the class in an invalid state
            * until setKey(...) is called.
            */
            AES() = default;
            AES(const AES&) = default;

            /**
            * Constructor to initialize the class with the given key
            */
            AES(const block& userKey);

            /**
            * Set the key to be used for encryption.
            */
            void set_key(const block& userKey);

            /**
            * Encrypts the plaintext block and stores the result in cyphertext
            */
            void ecb_enc_block(const block& plaintext, block& cyphertext) const;

            /**
            * Encrypts the plaintext block and returns the result 
            */
            block ecb_enc_block(const block& plaintext) const;

            /**
            * Encrypts blockLength starting at the plaintexts pointer and writes the result
            * to the cyphertext pointer
            */
            void ecb_enc_blocks(const block* plaintexts, u64 block_length, block* cyphertext) const;

            /**
            * Encrypts 2 blocks pointer to by plaintexts and writes the result to cyphertext
            */
            void ecb_enc_two_blocks(const block* plaintexts, block* cyphertext) const;

            /**
            * Encrypts 4 blocks pointer to by plaintexts and writes the result to cyphertext
            */
            void ecb_enc_four_blocks(const block* plaintexts, block* cyphertext) const;

            /**
            * Encrypts 16 blocks pointer to by plaintexts and writes the result to cyphertext
            */
            void ecb_enc_16_blocks(const block* plaintexts, block* cyphertext) const;

            /**
            * Encrypts the vector of blocks {baseIdx, baseIdx + 1, ..., baseIdx + length - 1} 
            * and writes the result to cyphertext.
            */
            void ecb_enc_counter_mode(u64 base_idx, u64 length, block* cyphertext) const;

            /**
            * Returns the current key.
            */
            const block& get_key() const { return round_key_[0]; }

            /**
            * Clears an instance of AES class
            */
            static void clear(AES& a);

        private:
            static constexpr int key_elem_count = 11;

            // The expanded key.
            block round_key_[key_elem_count];
        };

        /**
        * A class to perform AES decryption.
        */
        class AESDec
        {
        public:
            /**
            * Default constructor leave the class in an invalid state
            * until setKey(...) is called.
            */
            AESDec() = default;

            /**
            * Constructor to initialize the class with the given key
            */
            AESDec(const block& user_key);

            /**
            * Set the key to be used for decryption.
            */
            void set_key(const block& user_key);

            /**
            * Decrypts the cyphertext block and stores the result in plaintext
            */
            void ecb_dec_block(const block& cyphertext, block& plaintext);

            /**
            * Decrypts the cyphertext block and returns the plaintext
            */
            block ecb_dec_block(const block& cyphertext);

        private:
            // The expanded key
            block round_key_[11];
        };
    }
}

