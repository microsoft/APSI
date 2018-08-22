#pragma once

// APSI
#include "prng.h"

// FourQLib
#include <FourQ_api.h>

// Save a point in an Elliptic Curve to a buffer
void ecpoint_to_buffer(const point_t point, unsigned char* buffer);

// Restore a point in an Elliptic Curve from a buffer
void buffer_to_ecpoint(const unsigned char* buffer, point_t point);

// Save a coordinate in an Elliptic Curve to a buffer
void eccoord_to_buffer(const digit_t* coord, unsigned char* buffer);

// Restore a coordinate in an Elliptic Curve from a buffer
void buffer_to_eccoord(const unsigned char* buffer, digit_t* coord);

// Generate a random number within FourQ's order
void random_fourq(digit_t* a, apsi::tools::DPRNG& pr);
