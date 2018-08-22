#pragma once

#include "apsi/item.h"
#include <cstddef>
#include <cryptopp/drbg.h>

namespace apsi
{
    namespace tools
    {
        /**
         * Deterministic Pseudo Random Number Generator
         *
         * This is a wrapper over crypto++'s Hash_DRBG class, to allow
         * using our types as seeds.
         */
        class DPRNG : public CryptoPP::Hash_DRBG</* HASH */ CryptoPP::SHA256, /* STRENGTH */ 16U, /* SEEDLENGTH */ 55U>
        {
        public:
            DPRNG(const std::byte* entropy, size_t entropy_length);
            DPRNG(const apsi::Item* item);
            DPRNG(__m128i block);
        };
    }
}
