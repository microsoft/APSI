#include "apsi/ffield/ffield_elt.h"

using namespace std;
using namespace gsl;

namespace apsi
{
    namespace details
    {
        void copy_with_bit_offset(
            gsl::span<const u8> src,
            int32_t bitOffset,
            int32_t bitLength,
            gsl::span<u8> dest)
        {
            // the number of bits to shift by to align with dest
            auto lowOffset = bitOffset & 7;

            // the number of full bytes that should be written to dest
            auto fullByteCount = bitLength >> 3;

            // the index of the first src word which contains our bits
            auto wordBegin = bitOffset >> 3;

            auto remBits = bitLength - fullByteCount * 8;
#ifndef NDEBUG
            if (bitOffset + bitLength > src.size() * 8)
                throw std::invalid_argument("invalid split_length, or index out of range");
            if (bitLength > dest.size() * 8)
                throw std::invalid_argument("bit length too long for dest");
#endif
            if (lowOffset)
            {
                // lowOffset mean we need to shift the bytes. 
                // Populates all of the full bytes in dest.
                int i = 0;
                while (i < fullByteCount)
                {
                    u8  low = src[wordBegin + 0] >> lowOffset;
                    u8 high = src[wordBegin + 1] << (8 - lowOffset);
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
                auto& destWord = dest[fullByteCount];

                // we now populate the last byte of dest. Branch on
                // if the src bits are contained in a single byte or
                // in two bytes.
                bool oneWordSrc = lowOffset + remBits <= 8;
                if (oneWordSrc)
                {
                    // case 1: all the remaining bits live in src[wordBegin]
                    u8 mask = (1 << remBits) - 1;

                    auto low = src[wordBegin];
                    low = low >> lowOffset;
                    low = low & mask;

                    auto high = destWord;
                    high = high & (~mask);

                    destWord = low | high;
                }
                else
                {
                    //extract the top bits out of src[wordBegin].
                    // these will become the bottom bits of destWord
                    auto lowCount = 8 - lowOffset;
                    u8 lowMask = (1 << lowCount) - 1;
                    auto low = (src[wordBegin] >> lowOffset) & lowMask;

                    //extract the bottom bits out of src[wordBegin + 1].
                    // these will become the middle bits of destWord
                    auto midCount = remBits - lowCount;
                    u8 midMask = (1 << midCount) - 1;
                    auto mid = (src[wordBegin + 1] & midMask) << lowCount;

                    // keep the high bits of destWord
                    u8 highMask = (~0) << remBits;
                    auto high = destWord & highMask;

                    // for everythign together;
                    destWord = low | mid | high;
                }
            }
        };

        // Copies bitLength bits from src starting at the bit index by srcBitOffset.
        // Bits are written to dest starting at the destBitOffset bit. All other bits in 
        // dest are unchanged, e.g. the bit indexed by [0,1,...,destBitOffset - 1], [destBitOffset + bitLength, ...]
        void copy_with_bit_offset(
            gsl::span<const u8> src,
            int32_t srcBitOffset,
            int32_t destBitOffset,
            int32_t bitLength,
            gsl::span<u8> dest)
        {
            auto destNext = (destBitOffset + 7) >> 3;
            auto diff = destNext * 8 - destBitOffset;

            if (bitLength - diff > 0)
            {
                copy_with_bit_offset(src, srcBitOffset + diff, bitLength - diff, dest.subspan(destNext));
            }
            else
            {
                diff = bitLength;
            }

            if (diff)
            {
                auto srcBegin = srcBitOffset >> 3;
                auto destBegin = destBitOffset >> 3;
                auto destOffset = destBitOffset & 7;
                auto srcOffset = srcBitOffset & 7;
                auto highDiff = srcOffset + diff - 8;
                auto& destVal = dest[destBegin];

                if (highDiff <= 0)
                {
                    u8 mask = (1 << diff) - 1;
                    u8 mid = (src[srcBegin] >> srcOffset) & mask;

                    mask = ~(mask << destOffset);
                    mid = mid << destOffset;

                    destVal = (destVal & mask) | mid;
                }
                else
                {
                    auto lowDiff = diff - highDiff;

                    u8 lowMask = (1 << lowDiff) - 1;
                    u8 low = src[srcBegin] >> srcOffset;
                    low &= lowMask;

                    u8 highMask = (1 << highDiff) - 1;
                    u8 high = src[srcBegin + 1] & highMask;

                    low <<= destOffset;
                    high <<= (destOffset + lowDiff);

                    u8 mask = ~(((1 << diff) - 1) << destOffset);

                    destVal = (destVal & mask) | low | high;
                }
            }
        }
    }
}
