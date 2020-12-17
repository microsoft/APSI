/***********************************************************************************
* FourQlib: a high-performance crypto library based on the elliptic curve FourQ
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
* Abstract: FourQ's curve parameters
*
* This code is based on the paper "FourQ: four-dimensional decompositions on a 
* Q-curve over the Mersenne prime" by Craig Costello and Patrick Longa, in Advances 
* in Cryptology - ASIACRYPT, 2015.
* Preprint available at http://eprint.iacr.org/2015/565.
************************************************************************************/ 

#pragma once
#ifndef __FOURQ_PARAMS_H__
#define __FOURQ_PARAMS_H__

#include "apsi/fourq/FourQ_internal.h"


// Encoding of field elements, elements over Z_r and elements over GF(p^2):
// -----------------------------------------------------------------------
// Elements over GF(p) and Z_r are encoded with the least significant digit located in the leftmost position (i.e., little endian format). 
// Elements (a+b*i) over GF(p^2), where a and b are defined over GF(p), are encoded as a||b, with a in the least significant position.

static const uint64_t PARAMETER_d[4]       = { 0x0000000000000142, 0x00000000000000E4, 0xB3821488F1FC0C8D, 0x5E472F846657E0FC };
static const uint64_t GENERATOR_x[4]       = { 0x286592AD7B3833AA, 0x1A3472237C2FB305, 0x96869FB360AC77F6, 0x1E1F553F2878AA9C };
static const uint64_t GENERATOR_y[4]       = { 0xB924A2462BCBB287, 0x0E3FEE9BA120785A, 0x49A7C344844C8B5C, 0x6E1C4AF8630E0242 };
static const uint64_t curve_order[4]       = { 0x2FB2540EC7768CE7, 0xDFBD004DFE0F7999, 0xF05397829CBC14E5, 0x0029CBC14E5E0A72 };
static const uint64_t Montgomery_Rprime[4] = { 0xC81DB8795FF3D621, 0x173EA5AAEA6B387D, 0x3D01B7C72136F61C, 0x0006A5F16AC8F9D3 };
static const uint64_t Montgomery_rprime[4] = { 0xE12FE5F079BC3929, 0xD75E78B8D1FCDCF3, 0xBCE409ED76B5DB21, 0xF32702FDAFC1C074 };


// Constants for hash to FourQ function

#define c0l 1064406672104372656ULL
#define c0h 4737573565184866938ULL
#define b0l 11442141257964318772ULL
#define b0h 5379339658566403666ULL
#define b1l 17ULL
#define b1h 9223372036854775796ULL
#define A0l 1289ULL
#define A0h 9223372036854774896ULL
#define A1l 12311914987857864728ULL
#define A1h 7168186187914912079ULL

#if (RADIX == 64)
    static felm_t c0 = { c0l, c0h };
    static felm_t b0 = { b0l, b0h };
    static felm_t b1 = { b1l, b1h };
    static felm_t A0 = { A0l, A0h };
    static felm_t A1 = { A1l, A1h };
#else
    #define HIGHOF64(x) (uint32_t)(x >> 32)
    #define LOWOF64(x)  (uint32_t)(x)
    static felm_t c0 = { LOWOF64(c0l), HIGHOF64(c0l), LOWOF64(c0h), HIGHOF64(c0h) };
    static felm_t b0 = { LOWOF64(b0l), HIGHOF64(b0l), LOWOF64(b0h), HIGHOF64(b0h) };
    static felm_t b1 = { LOWOF64(b1l), HIGHOF64(b1l), LOWOF64(b1h), HIGHOF64(b1h) };
    static felm_t A0 = { LOWOF64(A0l), HIGHOF64(A0l), LOWOF64(A0h), HIGHOF64(A0h) };
    static felm_t A1 = { LOWOF64(A1l), HIGHOF64(A1l), LOWOF64(A1h), HIGHOF64(A1h) };
#endif

#endif