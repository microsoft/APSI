
// STD

// APSI
#include "apsi/tools/fourq.h"

using namespace apsi;
using namespace apsi::tools;

FourQCoordinate::FourQCoordinate()
    : coord_{ 0 }
{
}

FourQCoordinate::FourQCoordinate(const u64* buffer)
{
    size_t sz = word_count() * sizeof(u64);
    memcpy(coord_, buffer, sz);
}

FourQCoordinate::FourQCoordinate(PRNG& prng)
{
    random(prng);
}

const u64* FourQCoordinate::data() const
{
    return coord_;
}

u64* FourQCoordinate::data()
{
    return coord_;
}

void FourQCoordinate::to_buffer(apsi::u8* buffer) const
{
    memcpy(buffer, coord_, byte_count());
}

void FourQCoordinate::from_buffer(const apsi::u8* buffer)
{
    coord_[NWORDS_ORDER - 1] = 0; // Since we are _not_ going to initialize the MSB
    memcpy(coord_, buffer, byte_count());
}

void FourQCoordinate::random(PRNG& prng)
{
    prng.get(coord_, NWORDS_ORDER);
    coord_[NWORDS_ORDER - 1] &= 0x003fffffffffffff;
    subtract_mod_order(coord_, curve_order, coord_);
}

void FourQCoordinate::multiply_mod_order(const FourQCoordinate& other)
{
    Montgomery_multiply_mod_order(coord_, other.data(), coord_);
}

void FourQCoordinate::multiply_mod_order(const u64* other)
{
    Montgomery_multiply_mod_order(coord_, other, coord_);
}

void FourQCoordinate::inversion_mod_order()
{
    Montgomery_inversion_mod_order(coord_, coord_);
}
