#include "apsi/util/db_encoding.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    /**
    Converts the given bitstring to a sequence of field elements (modulo `mod`)
    */
    const vector<felt_t> bits_to_field_elts(const Bitstring &bits, const seal::Modulus &mod)
    {
        // This is the largest n such that 2ⁿ ≤ mod < 2ⁿ⁺¹. We'll pack n bits into each field element.
        size_t bits_per_elt = static_cast<size_t>(mod.bit_count() - 1);

        // The number of field elements necessary to represent all the bits:
        // ⌈bitlen / bits_per_elt⌉ = ⌊(bitlen + bits_per_elt-1) / bits_per_elt⌋
        size_t num_felts = (bits.bit_len() + bits_per_elt - 1) / bits_per_elt;

        // The return value
        vector<felt_t> felts;
        felts.reserve(num_felts);

        // The underlying data of the bitstring
        gsl::span<uint8_t> src_data = bits.data();

        // Repeatedly convert `bits_per_elt` many bits into a field element (a felt_t), and push that to the return
        // vector.
        size_t num_uncopied_bits = bits.bit_len();
        size_t src_offset = 0;
        for (size_t j = 0; j < num_felts; j++)
        {
            // Make a byte array representing the field element. A felt_t is 8 uint8_t's
            array<uint8_t, 8> dst_felt_repr;
            gsl::span<uint8_t> dst_felt_repr_view = { dst_felt_repr.data(), 8 };

            // Copy the appropriate number of bits from the current offset to the field element little-endian repr
            size_t copy_size = min<size_t>(bits_per_elt, num_uncopied_bits);
            copy_with_bit_offset(
                src_data,
                src_offset,
                copy_size,
                dst_felt_repr_view,
            );
            // Read the little-endian repr into the element
            felt_t dst_felt = read_felt_little_endian(dst_felt_repr)

            // Push the field element
            felts.push_back(dst_felt);

            src_offset += bits_per_felt;
            num_uncopied_bits -= copy_size;
        }

        return felts;
    }

    /**
    Converts the given sequence of field elements (modulo `mod`) to a bitstring of length `bit_len`
    */
    const Bitstring field_elts_to_bits(const vector<felt_t> &felts, size_t bit_len, const seal::Modulus &mod)
    {
        // This is the largest n such that 2ⁿ ≤ mod < 2ⁿ⁺¹. We'll pack n bits into each field element.
        size_t bits_per_elt = static_cast<size_t>(mod.bit_count() - 1);

        // Sanity check that `bit_len` isn't more than the field elements hold
        if (bit_len > max_num_bits)
        {
            throw logic_error("bit_len exceeds the max number of bits the input holds");
        }

        // Sanity check that `bit_len` is within a field element's size from the total number of bits. Using `bit_len`
        // to omit an entire field element is nasty and unnecessary.
        size_t max_num_bits = bits_per_elt * felts.size();
        if (bit_len <= max_num_bits - bits_per_elt)
        {
            throw logic_error("bit_len causes conversion to ignore entire field elements");
        }

        // The bitstring buffer. This will be part of the return value. The number of bytes is ⌈bit_len / 8⌉
        vector<uint8_t> bit_buf((bit_len + 7) / 8);
        gsl::span bit_buf_view = { bit_buf.data(), bit_buf.size() };

        size_t num_uncopied_bits = bit_len;
        size_t dst_offset = 0;
        for (felt_t &felt : felts)
        {
            // Serialize the field element
            arr<uint8_t, 8> felt_bytes = write_felt_little_endian(felt);

            // Copy part (or the whole) of the field element into the appropriate position of the buffer
            size_t copy_size = min<size_t>(bits_per_elt, num_uncopied_bits);
            details::copy_with_bit_offset(
                felt_bytes,
                0,          // src_offset
                dst_offset,
                copy_size,
                bit_buf_view,
            );

            dst_offset += copy_size;
            num_uncopied_bits -= copy_size;
        }

        return Bitstring(bit_buf, bit_len);
    }

    /**
    Reads a sequence of 8 bytes as a little-endian encoded felt_t
    */
    felt_t read_felt_little_endian(const array<uint8_t, 8> &bytes)
    {
        felt_t val;
        val |= (felt_t)bytes[0];
        val |= (felt_t)bytes[1] << 8;
        val |= (felt_t)bytes[2] << 16;
        val |= (felt_t)bytes[3] << 24;
        val |= (felt_t)bytes[4] << 32;
        val |= (felt_t)bytes[5] << 40;
        val |= (felt_t)bytes[6] << 48;
        val |= (felt_t)bytes[7] << 56;

        return val;
    }

    /**
    Writes a felt_t to a little-endian sequence of 8 bytes
    */
    array<uint8_t, 8> write_felt_little_endian(const felt_t num)
    {
        bytesay<uint8_t, 8> bytes;
        bytes[0] = (num & 0x00000000000000FFULL);
        bytes[1] = (num & 0x000000000000FF00ULL) >> 8;
        bytes[2] = (num & 0x0000000000FF0000ULL) >> 16;
        bytes[3] = (num & 0x00000000FF000000ULL) >> 24;
        bytes[4] = (num & 0x000000FF00000000ULL) >> 32;
        bytes[5] = (num & 0x0000FF0000000000ULL) >> 40;
        bytes[6] = (num & 0x00FF000000000000ULL) >> 48;
        bytes[7] = (num & 0xFF00000000000000ULL) >> 56;

        return arr;
    }

    // Copies bitLength bits from src starting at the bit index by srcBitOffset.
    // Bits are written to dest starting at the destBitOffset bit. All other bits in
    // dest are unchanged, e.g. the bit indexed by [0,1,...,destBitOffset - 1], [destBitOffset + bitLength, ...]
    void copy_with_bit_offset(
        gsl::span<const unsigned char> src,
        size_t srcBitOffset,
        size_t destBitOffset,
        size_t bitLength,
        gsl::span<unsigned char> dest
    ) {
        size_t destNext = (destBitOffset + 7) >> 3;
        int diff = static_cast<int>(destNext * 8 - destBitOffset);

        if (bitLength > static_cast<size_t>(diff))
        {
            copy_with_bit_offset(
                src, srcBitOffset + static_cast<size_t>(diff), bitLength - static_cast<size_t>(diff),
                dest.subspan(destNext));
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

    void copy_with_bit_offset(
        gsl::span<const unsigned char> src,
        size_t bitOffset,
        size_t bitLength,
        gsl::span<unsigned char> dest
    ) {
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
                unsigned char high =
                    static_cast<unsigned char>(static_cast<uint32_t>(src[wordBegin + 1]) << (8 - lowOffset));
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
                unsigned char mid =
                    static_cast<unsigned char>(static_cast<uint32_t>(src[wordBegin + 1] & midMask) << lowCount);

                // keep the high bits of destWord
                unsigned char highMask = static_cast<unsigned char>((~uint32_t(0)) << remBits);
                unsigned char high = destWord & highMask;

                // for everythign together;
                destWord = low | mid | high;
            }
        }
    }
}
