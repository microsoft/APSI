// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "apsi/ffield/ffield_elt.h"

using namespace std;
using namespace seal;

namespace apsi
{
    namespace details
    {
        void copy_with_bit_offset(gsl::span<const unsigned char> src, size_t bitOffset, size_t bitLength, gsl::span<unsigned char> dest)
        {
            // the number of bits to shift by to align with dest
            size_t lowOffset = bitOffset & 7;

            // the number of full bytes that should be written to dest
            size_t fullByteCount = bitLength >> 3;

            // the index of the first src word which contains our bits
            size_t wordBegin = bitOffset >> 3;

            size_t remBits = bitLength - fullByteCount * 8;
#ifndef NDEBUG
            if (bitOffset + bitLength > src.size() * 8)
                throw invalid_argument("invalid split_length, or index out of range");
            if (bitLength > dest.size() * 8)
                throw invalid_argument("bit length too long for dest");
#endif
            if (lowOffset)
            {
                // lowOffset mean we need to shift the bytes.
                // Populates all of the full bytes in dest.
                size_t i = 0;
                while (i < fullByteCount)
                {
                    unsigned char low = src[wordBegin + 0] >> lowOffset;
                    unsigned char high = static_cast<unsigned char>(static_cast<uint32_t>(src[wordBegin + 1]) << (8 - lowOffset));
                    dest[i] = low | high;
                    wordBegin++;
                    i++;
                }
            }
            else
            {
                // simple case, just do memcpy for all of the full bytes
                memcpy(dest.data(), &src[wordBegin], fullByteCount);
                wordBegin += fullByteCount;
            }

            // we are now done with
            // dest[0], ..., dest[fullByteCount - 1].
            //
            // what remains is to populate dest[fullByteCount]
            // if needed there are some remaining bits.
            if (remBits)
            {
                unsigned char &destWord = dest[fullByteCount];

                // we now populate the last unsigned char of dest. Branch on
                // if the src bits are contained in a single unsigned char or
                // in two bytes.
                bool oneWordSrc = lowOffset + remBits <= 8;
                if (oneWordSrc)
                {
                    // case 1: all the remaining bits live in src[wordBegin]
                    unsigned char mask = static_cast<unsigned char>(uint32_t(1) << remBits) - 1;

                    unsigned char low = src[wordBegin];
                    low = low >> lowOffset;
                    low = low & mask;

                    unsigned char high = destWord;
                    high = high & (~mask);

                    destWord = low | high;
                }
                else
                {
                    // extract the top bits out of src[wordBegin].
                    // these will become the bottom bits of destWord
                    size_t lowCount = 8 - lowOffset;
                    unsigned char lowMask = static_cast<unsigned char>(uint32_t(1) << lowCount) - 1;
                    unsigned char low = (src[wordBegin] >> lowOffset) & lowMask;

                    // extract the bottom bits out of src[wordBegin + 1].
                    // these will become the middle bits of destWord
                    size_t midCount = remBits - lowCount;
                    unsigned char midMask = static_cast<unsigned char>(uint32_t(1) << midCount) - 1;
                    unsigned char mid = static_cast<unsigned char>(static_cast<uint32_t>(src[wordBegin + 1] & midMask) << lowCount);

                    // keep the high bits of destWord
                    unsigned char highMask = static_cast<unsigned char>((~uint32_t(0)) << remBits);
                    unsigned char high = destWord & highMask;

                    // for everythign together;
                    destWord = low | mid | high;
                }
            }
        };

        // Copies bitLength bits from src starting at the bit index by srcBitOffset.
        // Bits are written to dest starting at the destBitOffset bit. All other bits in
        // dest are unchanged, e.g. the bit indexed by [0,1,...,destBitOffset - 1], [destBitOffset + bitLength, ...]
        void copy_with_bit_offset(
            gsl::span<const unsigned char> src, size_t srcBitOffset, size_t destBitOffset, size_t bitLength, gsl::span<unsigned char> dest)
        {
            size_t destNext = (destBitOffset + 7) >> 3;
            int diff = static_cast<int>(destNext * 8 - destBitOffset);

            if (bitLength > static_cast<size_t>(diff))
            {
                copy_with_bit_offset(src, srcBitOffset + static_cast<size_t>(diff), bitLength - static_cast<size_t>(diff), dest.subspan(destNext));
            }
            else
            {
                diff = static_cast<int>(bitLength);
            }

            if (diff)
            {
                size_t srcBegin = srcBitOffset >> 3;
                size_t destBegin = destBitOffset >> 3;
                size_t destOffset = destBitOffset & 7;
                size_t srcOffset = srcBitOffset & 7;
                int highDiff = static_cast<int>(srcOffset) + diff - 8;
                unsigned char &destVal = dest[destBegin];

                if (highDiff <= 0)
                {
                    unsigned char mask = static_cast<unsigned char>(uint32_t(1) << diff) - 1;
                    unsigned char mid = (src[srcBegin] >> srcOffset) & mask;

                    mask = ~static_cast<unsigned char>(static_cast<uint32_t>(mask) << destOffset);
                    mid = static_cast<unsigned char>(static_cast<uint32_t>(mid) << destOffset);

                    destVal = (destVal & mask) | mid;
                }
                else
                {
                    int lowDiff = diff - highDiff;

                    unsigned char lowMask = static_cast<unsigned char>(uint32_t(1) << lowDiff) - 1;
                    unsigned char low = src[srcBegin] >> srcOffset;
                    low &= lowMask;

                    unsigned char highMask = static_cast<unsigned char>(uint32_t(1) << highDiff) - 1;
                    unsigned char high = src[srcBegin + 1] & highMask;

                    low <<= destOffset;
                    high <<= (destOffset + static_cast<size_t>(lowDiff));

                    unsigned char mask = ~static_cast<unsigned char>(((uint32_t(1) << diff) - 1) << destOffset);

                    destVal = (destVal & mask) | low | high;
                }
            }
        }
    } // namespace details
} // namespace apsi
