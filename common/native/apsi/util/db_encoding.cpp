// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>
#include <stdexcept>

// APSI
#include "apsi/util/db_encoding.h"

// SEAL
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    namespace util
    {
        namespace
        {
            void copy_with_bit_offset(
                gsl::span<const seal_byte> src,
                uint32_t bit_offset,
                uint32_t bit_count,
                gsl::span<seal_byte> dest
            ) {
                // the number of bits to shift by to align with dest
                uint32_t low_offset = bit_offset & 7;

                // the number of full bytes that should be written to dest
                uint32_t full_byte_count = bit_count >> 3;

                // the index of the first src word which contains our bits
                uint32_t word_begin = bit_offset >> 3;

                uint32_t rem_bits = bit_count - full_byte_count * 8;
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
                    uint32_t i = 0;
                    while (i < full_byte_count)
                    {
                        seal_byte low = src[word_begin + 0] >> low_offset;
                        seal_byte high =
                            static_cast<seal_byte>(static_cast<uint32_t>(src[word_begin + 1]) << (8 - low_offset));
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
                    seal_byte &dest_word = dest[full_byte_count];

                    // we now populate the last seal_byte of dest. Branch on
                    // if the src bits are contained in a single seal_byte or
                    // in two bytes.
                    bool one_word_src = low_offset + rem_bits <= 8;
                    if (one_word_src)
                    {
                        // case 1: all the remaining bits live in src[word_begin]
                        seal_byte mask = static_cast<seal_byte>((uint32_t(1) << rem_bits) - 1);

                        seal_byte low = src[word_begin];
                        low = low >> low_offset;
                        low = low & mask;

                        seal_byte high = dest_word;
                        high = high & (~mask);

                        dest_word = low | high;
                    }
                    else
                    {
                        // extract the top bits out of src[word_begin].
                        // these will become the bottom bits of dest_word
                        uint32_t low_count = 8 - low_offset;
                        seal_byte low_mask = static_cast<seal_byte>((uint32_t(1) << low_count) - 1);
                        seal_byte low = (src[word_begin] >> low_offset) & low_mask;

                        // extract the bottom bits out of src[word_begin + 1].
                        // these will become the middle bits of dest_word
                        uint32_t mid_count = rem_bits - low_count;
                        seal_byte mid_mask = static_cast<seal_byte>((uint32_t(1) << mid_count) - 1);
                        seal_byte mid =
                            static_cast<seal_byte>(static_cast<uint32_t>(src[word_begin + 1] & mid_mask) << low_count);

                        // keep the high bits of dest_word
                        seal_byte high_mask = static_cast<seal_byte>((~uint32_t(0)) << rem_bits);
                        seal_byte high = dest_word & high_mask;

                        // for everythign together;
                        dest_word = low | mid | high;
                    }
                }
            }

            // Copies bit_count bits from src starting at the bit index by src_bit_offset.
            // Bits are written to dest starting at the dest_bit_offset bit. All other bits in
            // dest are unchanged, e.g. the bit indexed by [0,1,...,dest_bit_offset - 1], [dest_bit_offset + bit_count, ...]
            void copy_with_bit_offset(
                gsl::span<const seal_byte> src,
                uint32_t src_bit_offset,
                uint32_t dest_bit_offset,
                uint32_t bit_count,
                gsl::span<seal_byte> dest
            ) {
                uint32_t dest_next = (dest_bit_offset + 7) >> 3;
                uint32_t diff = dest_next * 8 - dest_bit_offset;

                if (bit_count > diff)
                {
                    copy_with_bit_offset(
                        src, src_bit_offset + diff, bit_count - diff,
                        dest.subspan(dest_next));
                }
                else
                {
                    diff = bit_count;
                }

                if (diff)
                {
                    uint32_t src_begin = src_bit_offset >> 3;
                    uint32_t dest_begin = dest_bit_offset >> 3;
                    uint32_t dest_offset = dest_bit_offset & 7;
                    uint32_t src_offset = src_bit_offset & 7;
                    uint32_t high_diff = src_offset + diff - 8;
                    seal_byte &dest_val = dest[dest_begin];

                    if (high_diff <= 0)
                    {
                        seal_byte mask = static_cast<seal_byte>((uint32_t(1) << diff) - 1);
                        seal_byte mid = (src[src_begin] >> src_offset) & mask;

                        mask = ~static_cast<seal_byte>(static_cast<uint32_t>(mask) << dest_offset);
                        mid = static_cast<seal_byte>(static_cast<uint32_t>(mid) << dest_offset);

                        dest_val = (dest_val & mask) | mid;
                    }
                    else
                    {
                        uint32_t low_diff = diff - high_diff;

                        seal_byte low_mask = static_cast<seal_byte>((uint32_t(1) << low_diff) - 1);
                        seal_byte low = src[src_begin] >> src_offset;
                        low &= low_mask;

                        seal_byte high_mask = static_cast<seal_byte>((uint32_t(1) << high_diff) - 1);
                        seal_byte high = src[src_begin + 1] & high_mask;

                        low <<= dest_offset;
                        high <<= (dest_offset + low_diff);

                        seal_byte mask = ~static_cast<seal_byte>(((uint32_t(1) << diff) - 1) << dest_offset);

                        dest_val = (dest_val & mask) | low | high;
                    }
                }
            }

            /**
            Reads a sequence of 8 bytes as a little-endian encoded felt_t
            */
            felt_t read_felt_little_endian(const array<seal_byte, 8> &bytes)
            {
                felt_t val = 0;
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
            array<seal_byte, 8> write_felt_little_endian(const felt_t num)
            {
                array<seal_byte, 8> bytes;

                bytes[0] = static_cast<seal_byte>( num & 0x00000000000000FFULL);
                bytes[1] = static_cast<seal_byte>((num & 0x000000000000FF00ULL) >> 8);
                bytes[2] = static_cast<seal_byte>((num & 0x0000000000FF0000ULL) >> 16);
                bytes[3] = static_cast<seal_byte>((num & 0x00000000FF000000ULL) >> 24);
                bytes[4] = static_cast<seal_byte>((num & 0x000000FF00000000ULL) >> 32);
                bytes[5] = static_cast<seal_byte>((num & 0x0000FF0000000000ULL) >> 40);
                bytes[6] = static_cast<seal_byte>((num & 0x00FF000000000000ULL) >> 48);
                bytes[7] = static_cast<seal_byte>((num & 0xFF00000000000000ULL) >> 56);

                return bytes;
            }
        }

        /**
        Converts the given bitstring to a sequence of field elements (modulo `mod`)
        */
        vector<felt_t> bits_to_field_elts(BitstringView<const seal::seal_byte> bits, const Modulus &mod)
        {
            if (mod.is_zero())
            {
                throw invalid_argument("mod cannot be zero");
            }

            // This is the largest n such that 2ⁿ ≤ mod < 2ⁿ⁺¹. We'll pack n bits into each field element.
            uint32_t bits_per_felt = static_cast<uint32_t>(mod.bit_count() - 1);

            // The number of field elements necessary to represent all the bits:
            // ⌈bit_count / bits_per_felt⌉ = ⌊(bit_count + bits_per_felt-1) / bits_per_felt⌋
            uint32_t num_felts = (bits.bit_count() + bits_per_felt - 1) / bits_per_felt;

            // The return value
            vector<felt_t> felts;
            felts.reserve(num_felts);

            // The underlying data of the bitstring
            gsl::span<const seal_byte> src_data = bits.data();

            // Repeatedly convert `bits_per_felt` many bits into a field element (a felt_t), and push that to the return
            // vector.
            uint32_t num_uncopied_bits = bits.bit_count();
            uint32_t src_offset = 0;
            for (size_t j = 0; j < num_felts; j++)
            {
                // Make a byte array representing the field element. A felt_t is 8 seal_byte's
                array<seal_byte, 8> dst_felt_repr = {};
                gsl::span<seal_byte> dst_felt_repr_view = { dst_felt_repr.data(), 8 };

                // Copy the appropriate number of bits from the current offset to the field element little-endian repr
                uint32_t copy_size = min(bits_per_felt, num_uncopied_bits);
                copy_with_bit_offset(
                    src_data,
                    src_offset,
                    copy_size,
                    dst_felt_repr_view
                );

                // Read the little-endian repr into the element
                felt_t dst_felt = read_felt_little_endian(dst_felt_repr);

                // Push the field element
                felts.push_back(dst_felt);

                src_offset += bits_per_felt;
                num_uncopied_bits -= copy_size;
            }

            return felts;
        }

        vector<felt_t> bits_to_field_elts(BitstringView<seal_byte> bits, const Modulus &mod)
        {
            return bits_to_field_elts(BitstringView<const seal_byte>(bits), mod);
        }

        /**
        Converts the given sequence of field elements (modulo `mod`) to a bitstring of length `bit_count`
        */
        Bitstring field_elts_to_bits(gsl::span<const felt_t> felts, uint32_t bit_count, const Modulus &mod)
        {
            if (felts.empty())
            {
                throw invalid_argument("felts cannot be empty");
            }
            if (mod.is_zero())
            {
                throw invalid_argument("mod cannot be zero");
            }

            // This is the largest n such that 2ⁿ ≤ mod < 2ⁿ⁺¹. We'll pack n bits into each field element.
            uint32_t bits_per_felt = static_cast<uint32_t>(mod.bit_count() - 1);

            // Sanity check that `bit_count` isn't more than the field elements hold
            uint32_t max_num_bits = mul_safe(bits_per_felt, safe_cast<uint32_t>(felts.size()));
            if (bit_count > max_num_bits)
            {
                throw invalid_argument("bit_count exceeds the max number of bits the input holds");
            }

            // Sanity check that `bit_count` is within a field element's size from the total number of bits. Using `bit_count`
            // to omit an entire field element is nasty and unnecessary.
            if (bit_count <= max_num_bits - bits_per_felt)
            {
                throw invalid_argument("bit_count causes conversion to ignore entire field elements");
            }

            // The bitstring buffer. This will be part of the return value. The number of bytes is ⌈bit_count / 8⌉
            vector<seal_byte> bit_buf((bit_count + 7) / 8, seal_byte(0));
            gsl::span<seal_byte> bit_buf_view(bit_buf.data(), bit_buf.size());

            uint32_t num_uncopied_bits = bit_count;
            uint32_t dst_offset = 0;
            for (const felt_t &felt : felts)
            {
                // Serialize the field element
                array<seal_byte, 8> felt_bytes = write_felt_little_endian(felt);

                // Copy part (or the whole) of the field element into the appropriate position of the buffer
                uint32_t copy_size = min(bits_per_felt, num_uncopied_bits);
                copy_with_bit_offset(
                    felt_bytes,
                    0,          // src_offset
                    dst_offset,
                    copy_size,
                    bit_buf_view
                );

                dst_offset += copy_size;
                num_uncopied_bits -= copy_size;
            }

            return Bitstring(move(bit_buf), bit_count);
        }


        /**
        Converts an item and label into a sequence of (felt_t, felt_t) pairs, where the the first pair value is a chunk of
        the item, and the second is a chunk of the label. item_bit_count denotes the bit length of the items and labels
        (they're the same length). mod denotes the modulus of the prime field.
        */
        AlgItemLabel<felt_t> algebraize_item_label(
            const Item &item, const FullWidthLabel &label, size_t item_bit_count, const Modulus &mod)
        {
            // Convert the item from to a sequence of field elements. This is the "algebraic item".
            vector<felt_t> alg_item = bits_to_field_elts(item.to_bitstring(item_bit_count), mod);

            // Convert the label from to a sequence of field elements. This is the "algebraic label".
            vector<felt_t> alg_label = bits_to_field_elts(label.to_bitstring(item_bit_count), mod);

            // The number of field elements necessary to represent both these values MUST be the same
            if (alg_item.size() != alg_label.size())
            {
                throw invalid_argument("items must take up as many slots as labels");
            }

            // Convert pair of vector to vector of pairs
            AlgItemLabel<felt_t> ret;
            for (size_t i = 0; i < alg_item.size(); i++)
            {
                ret.emplace_back(make_pair(alg_item[i], alg_label[i]));
            }

            return ret;
        }

        /**
        Converts an item into a sequence of (felt_t, monostate) pairs, where the the first pair value is a chunk of the
        item, and the second is the unit type. item_bit_count denotes the bit length of the items and labels (they're the
        same length). mod denotes the modulus of the prime field. mod denotes the modulus of the prime field.
        */
        AlgItemLabel<monostate> algebraize_item(const Item &item, size_t item_bit_count, const Modulus &mod)
        {
            // Convert the item from to a sequence of field elements. This is the "algebraic item".
            vector<felt_t> alg_item = bits_to_field_elts(item.to_bitstring(item_bit_count), mod);

            // Convert vector to vector of pairs where the second element of each pair is monostate
            AlgItemLabel<monostate> ret;
            for (size_t i = 0; i < alg_item.size(); i++)
            {
                ret.emplace_back(make_pair(alg_item[i], monostate{}));
            }

            return ret;
        }
    }
}
