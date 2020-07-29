// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>
#include <stdexcept>

// APSi
#include "apsi/util/db_encoding.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    namespace
    {
        void copy_with_bit_offset(
            gsl::span<const SEAL_BYTE> src,
            size_t bit_offset,
            size_t bit_count,
            gsl::span<SEAL_BYTE> dest
        ) {
            // the number of bits to shift by to align with dest
            size_t low_offset = bit_offset & 7;

            // the number of full bytes that should be written to dest
            size_t full_byte_count = bit_count >> 3;

            // the index of the first src word which contains our bits
            size_t word_begin = bit_offset >> 3;

            size_t rem_bits = bit_count - full_byte_count * 8;
#ifndef NDEBUG
            if (bit_offset + bit_count > src.size() * 8)
                throw invalid_argument("invalid split_length, or index out of range");
            if (bit_count > dest.size() * 8)
                throw invalid_argument("bit_count too large for dest");
#endif
            if (low_offset)
            {
                // low_offset mean we need to shift the bytes.
                // Populates all of the full bytes in dest.
                size_t i = 0;
                while (i < full_byte_count)
                {
                    SEAL_BYTE low = src[word_begin + 0] >> low_offset;
                    SEAL_BYTE high =
                        static_cast<SEAL_BYTE>(static_cast<uint32_t>(src[word_begin + 1]) << (8 - low_offset));
                    dest[i] = low | high;
                    word_begin++;
                    i++;
                }
            }
            else
            {
                // simple case, just do memcpy for all of the full bytes
                memcpy(dest.data(), &src[word_begin], full_byte_count);
                word_begin += full_byte_count;
            }

            // we are now done with
            // dest[0], ..., dest[full_byte_count - 1].
            //
            // what remains is to populate dest[full_byte_count]
            // if needed there are some remaining bits.
            if (rem_bits)
            {
                SEAL_BYTE &dest_word = dest[full_byte_count];

                // we now populate the last SEAL_BYTE of dest. Branch on
                // if the src bits are contained in a single SEAL_BYTE or
                // in two bytes.
                bool one_word_src = low_offset + rem_bits <= 8;
                if (one_word_src)
                {
                    // case 1: all the remaining bits live in src[word_begin]
                    SEAL_BYTE mask = static_cast<SEAL_BYTE>(uint32_t(1) << rem_bits) - 1;

                    SEAL_BYTE low = src[word_begin];
                    low = low >> low_offset;
                    low = low & mask;

                    SEAL_BYTE high = dest_word;
                    high = high & (~mask);

                    dest_word = low | high;
                }
                else
                {
                    // extract the top bits out of src[word_begin].
                    // these will become the bottom bits of dest_word
                    size_t low_count = 8 - low_offset;
                    SEAL_BYTE low_mask = static_cast<SEAL_BYTE>(uint32_t(1) << low_count) - 1;
                    SEAL_BYTE low = (src[word_begin] >> low_offset) & low_mask;

                    // extract the bottom bits out of src[word_begin + 1].
                    // these will become the middle bits of dest_word
                    size_t mid_count = rem_bits - low_count;
                    SEAL_BYTE mid_mask = static_cast<SEAL_BYTE>(uint32_t(1) << mid_count) - 1;
                    SEAL_BYTE mid =
                        static_cast<SEAL_BYTE>(static_cast<uint32_t>(src[word_begin + 1] & mid_mask) << low_count);

                    // keep the high bits of dest_word
                    SEAL_BYTE high_mask = static_cast<SEAL_BYTE>((~uint32_t(0)) << rem_bits);
                    SEAL_BYTE high = dest_word & high_mask;

                    // for everythign together;
                    dest_word = low | mid | high;
                }
            }
        }

        // Copies bit_count bits from src starting at the bit index by src_bit_offset.
        // Bits are written to dest starting at the dest_bit_offset bit. All other bits in
        // dest are unchanged, e.g. the bit indexed by [0,1,...,dest_bit_offset - 1], [dest_bit_offset + bit_count, ...]
        void copy_with_bit_offset(
            gsl::span<const SEAL_BYTE> src,
            size_t src_bit_offset,
            size_t dest_bit_offset,
            size_t bit_count,
            gsl::span<SEAL_BYTE> dest
        ) {
            size_t dest_next = (dest_bit_offset + 7) >> 3;
            int diff = static_cast<int>(dest_next * 8 - dest_bit_offset);

            if (bit_count > static_cast<size_t>(diff))
            {
                copy_with_bit_offset(
                    src, src_bit_offset + static_cast<size_t>(diff), bit_count - static_cast<size_t>(diff),
                    dest.subspan(dest_next));
            }
            else
            {
                diff = static_cast<int>(bit_count);
            }

            if (diff)
            {
                size_t src_begin = src_bit_offset >> 3;
                size_t dest_begin = dest_bit_offset >> 3;
                size_t dest_offset = dest_bit_offset & 7;
                size_t src_offset = src_bit_offset & 7;
                int high_diff = static_cast<int>(src_offset) + diff - 8;
                SEAL_BYTE &dest_val = dest[dest_begin];

                if (high_diff <= 0)
                {
                    SEAL_BYTE mask = static_cast<SEAL_BYTE>(uint32_t(1) << diff) - 1;
                    SEAL_BYTE mid = (src[src_begin] >> src_offset) & mask;

                    mask = ~static_cast<SEAL_BYTE>(static_cast<uint32_t>(mask) << dest_offset);
                    mid = static_cast<SEAL_BYTE>(static_cast<uint32_t>(mid) << dest_offset);

                    dest_val = (dest_val & mask) | mid;
                }
                else
                {
                    int lowDiff = diff - high_diff;

                    SEAL_BYTE low_mask = static_cast<SEAL_BYTE>(uint32_t(1) << lowDiff) - 1;
                    SEAL_BYTE low = src[src_begin] >> src_offset;
                    low &= low_mask;

                    SEAL_BYTE high_mask = static_cast<SEAL_BYTE>(uint32_t(1) << high_diff) - 1;
                    SEAL_BYTE high = src[src_begin + 1] & high_mask;

                    low <<= dest_offset;
                    high <<= (dest_offset + static_cast<size_t>(lowDiff));

                    SEAL_BYTE mask = ~static_cast<SEAL_BYTE>(((uint32_t(1) << diff) - 1) << dest_offset);

                    dest_val = (dest_val & mask) | low | high;
                }
            }
        }

        /**
        Reads a sequence of 8 bytes as a little-endian encoded felt_t
        */
        felt_t read_felt_little_endian(const array<SEAL_BYTE, 8> &bytes)
        {
            felt_t val;
            val |= static_cast<felt_t>(bytes[0]);
            val |= static_cast<felt_t>(bytes[1]) << 8;
            val |= static_cast<felt_t>(bytes[2]) << 16;
            val |= static_cast<felt_t>(bytes[3]) << 24;
            val |= static_cast<felt_t>(bytes[4]) << 32;
            val |= static_cast<felt_t>(bytes[5]) << 40;
            val |= static_cast<felt_t>(bytes[6]) << 48;
            val |= static_cast<felt_t>(bytes[7]) << 56;

            return val;
        }

        /**
        Writes a felt_t to a little-endian sequence of 8 bytes
        */
        array<SEAL_BYTE, 8> write_felt_little_endian(const felt_t num)
        {
            bytesay<SEAL_BYTE, 8> bytes;
            bytes[0] = static_cast<SEAL_BYTE>(num & 0x00000000000000FFULL);
            bytes[1] = static_cast<SEAL_BYTE>((num & 0x000000000000FF00ULL) >> 8);
            bytes[2] = static_cast<SEAL_BYTE((num & 0x0000000000FF0000ULL) >> 16);
            bytes[3] = static_cast<SEAL_BYTE((num & 0x00000000FF000000ULL) >> 24);
            bytes[4] = static_cast<SEAL_BYTE((num & 0x000000FF00000000ULL) >> 32);
            bytes[5] = static_cast<SEAL_BYTE((num & 0x0000FF0000000000ULL) >> 40);
            bytes[6] = static_cast<SEAL_BYTE((num & 0x00FF000000000000ULL) >> 48);
            bytes[7] = static_cast<SEAL_BYTE((num & 0xFF00000000000000ULL) >> 56);

            return arr;
        }
    }

    /**
    Converts the given bitstring to a sequence of field elements (modulo `mod`)
    */
    vector<felt_t> bits_to_field_elts(const Bitstring &bits, const Modulus &mod)
    {
        // This is the largest n such that 2ⁿ ≤ mod < 2ⁿ⁺¹. We'll pack n bits into each field element.
        size_t bits_per_elt = static_cast<size_t>(mod.bit_count() - 1);

        // The number of field elements necessary to represent all the bits:
        // ⌈bit_count / bits_per_elt⌉ = ⌊(bit_count + bits_per_elt-1) / bits_per_elt⌋
        size_t num_felts = (bits.bit_count() + bits_per_elt - 1) / bits_per_elt;

        // The return value
        vector<felt_t> felts;
        felts.reserve(num_felts);

        // The underlying data of the bitstring
        gsl::span<SEAL_BYTE> src_data = bits.data();

        // Repeatedly convert `bits_per_elt` many bits into a field element (a felt_t), and push that to the return
        // vector.
        size_t num_uncopied_bits = bits.bit_count();
        size_t src_offset = 0;
        for (size_t j = 0; j < num_felts; j++)
        {
            // Make a byte array representing the field element. A felt_t is 8 SEAL_BYTE's
            array<SEAL_BYTE, 8> dst_felt_repr;
            gsl::span<SEAL_BYTE> dst_felt_repr_view = { dst_felt_repr.data(), 8 };

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
    Converts the given sequence of field elements (modulo `mod`) to a bitstring of length `bit_count`
    */
    Bitstring field_elts_to_bits(const vector<felt_t> &felts, size_t bit_count, const Modulus &mod)
    {
        // This is the largest n such that 2ⁿ ≤ mod < 2ⁿ⁺¹. We'll pack n bits into each field element.
        size_t bits_per_elt = static_cast<size_t>(mod.bit_count() - 1);

        // Sanity check that `bit_count` isn't more than the field elements hold
        if (bit_count > max_num_bits)
        {
            throw logic_error("bit_count exceeds the max number of bits the input holds");
        }

        // Sanity check that `bit_count` is within a field element's size from the total number of bits. Using `bit_count`
        // to omit an entire field element is nasty and unnecessary.
        size_t max_num_bits = bits_per_elt * felts.size();
        if (bit_count <= max_num_bits - bits_per_elt)
        {
            throw logic_error("bit_count causes conversion to ignore entire field elements");
        }

        // The bitstring buffer. This will be part of the return value. The number of bytes is ⌈bit_count / 8⌉
        vector<SEAL_BYTE> bit_buf((bit_count + 7) / 8);
        gsl::span bit_buf_view = { bit_buf.data(), bit_buf.size() };

        size_t num_uncopied_bits = bit_count;
        size_t dst_offset = 0;
        for (felt_t &felt : felts)
        {
            // Serialize the field element
            arr<SEAL_BYTE, 8> felt_bytes = write_felt_little_endian(felt);

            // Copy part (or the whole) of the field element into the appropriate position of the buffer
            size_t copy_size = min<size_t>(bits_per_elt, num_uncopied_bits);
            copy_with_bit_offset(
                felt_bytes,
                0,          // src_offset
                dst_offset,
                copy_size,
                bit_buf_view,
            );

            dst_offset += copy_size;
            num_uncopied_bits -= copy_size;
        }

        return Bitstring(bit_buf, bit_count);
    }
}
