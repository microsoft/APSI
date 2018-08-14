#include "utils.h"

#include <FourQ_params.h>
#include <cstring>

// Save a point in an Elliptic Curve to a buffer
void ecpoint_to_buffer(const point_t point, unsigned char* buffer)
{
    auto byte_count = sizeof(point_t);
    memcpy(buffer, point->x, byte_count);
}

// Restore a point in an Elliptic Curve from a buffer
void buffer_to_ecppoint(const unsigned char* buffer, point_t point)
{
    auto byte_count = sizeof(point_t);
    memcpy(&point->x, buffer, byte_count);
}

void eccoord_to_buffer(const digit_t* coord, unsigned char* buffer)
{
    auto byte_count = sizeof(f2elm_t) - 1;
    memcpy(buffer, coord, byte_count);
}

void buffer_to_eccoord(const unsigned char* buffer, digit_t* coord)
{
    auto byte_count = sizeof(f2elm_t) - 1;
    coord[3] = 0; // Since we are _not_ going to initialize the MSB
    memcpy(coord, buffer, byte_count);
}

// Generate a random number within FourQ's order
void random_fourq(digit_t* a, osuCrypto::PRNG& pr)
{
    pr.get(a, 4);
    unsigned char* string = (unsigned char*)a;

    a[3] &= 0x003fffffffffffff;
    subtract_mod_order(a, (digit_t*)&curve_order, a);
}
