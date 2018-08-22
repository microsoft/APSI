#pragma once

#include "apsi/item.h"
#include <cstddef>
#include <cryptopp/drbg.h>

namespace apsi
{
    namespace tools
    {
        class DPRNG : public CryptoPP::Hash_DRBG</* HASH */ CryptoPP::SHA256, /* STRENGTH */ 16U, /* SEEDLENGTH */ 55U>
        {
        public:
            DPRNG(const std::byte* entropy, size_t entropy_length);
            DPRNG(const apsi::Item* item);
            DPRNG(__m128i block);
        };
    }
}
