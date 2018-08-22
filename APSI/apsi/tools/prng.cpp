#include "prng.h"

using namespace apsi::tools;

DPRNG::DPRNG(const std::byte* entropy, size_t entropy_length)
    : Hash_DRBG(reinterpret_cast<const CryptoPP::byte*>(entropy), entropy_length)
{
}

DPRNG::DPRNG(const apsi::Item* item)
    : Hash_DRBG(reinterpret_cast<const CryptoPP::byte*>(item), sizeof(Item))
{
}

DPRNG::DPRNG(__m128i block)
    : Hash_DRBG(reinterpret_cast<const CryptoPP::byte*>(&block), sizeof(__m128i))
{
}
