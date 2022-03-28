// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>
#include <stdexcept>

// APSI
#include "apsi/util/db_encoding.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi {
    namespace util {
        namespace {
            uint64_t read_u64_little_endian(const array<unsigned char, 8> &bytes)
            {
                uint64_t val = 0;
                val |= static_cast<uint64_t>(bytes[0]);
                val |= static_cast<uint64_t>(bytes[1]) << 8;
                val |= static_cast<uint64_t>(bytes[2]) << 16;
                val |= static_cast<uint64_t>(bytes[3]) << 24;
                val |= static_cast<uint64_t>(bytes[4]) << 32;
                val |= static_cast<uint64_t>(bytes[5]) << 40;
                val |= static_cast<uint64_t>(bytes[6]) << 48;
                val |= static_cast<uint64_t>(bytes[7]) << 56;

                return val;
            }

            array<unsigned char, 8> write_u64_little_endian(uint64_t num)
            {
                array<unsigned char, 8> bytes;
                bytes[0] = static_cast<unsigned char>(num & 0x00000000000000FFULL);
                bytes[1] = static_cast<unsigned char>((num & 0x000000000000FF00ULL) >> 8);
                bytes[2] = static_cast<unsigned char>((num & 0x0000000000FF0000ULL) >> 16);
                bytes[3] = static_cast<unsigned char>((num & 0x00000000FF000000ULL) >> 24);
                bytes[4] = static_cast<unsigned char>((num & 0x000000FF00000000ULL) >> 32);
                bytes[5] = static_cast<unsigned char>((num & 0x0000FF0000000000ULL) >> 40);
                bytes[6] = static_cast<unsigned char>((num & 0x00FF000000000000ULL) >> 48);
                bytes[7] = static_cast<unsigned char>((num & 0xFF00000000000000ULL) >> 56);

                return bytes;
            }

            void copy_with_bit_offset(
                gsl::span<const unsigned char> src,
                uint32_t bit_offset,
                uint32_t bit_count,
                gsl::span<unsigned char> dest)
            {
                // The number of bits to shift by to align with dest
                uint32_t low_offset = bit_offset & 7;

                // The number of full bytes that should be written to dest
                uint32_t full_byte_count = bit_count >> 3;

                // The index of the first src word which contains our bits
                uint32_t word_begin = bit_offset >> 3;

                uint32_t rem_bits = bit_count - full_byte_count * 8;
#ifdef APSI_DEBUG
                if (bit_offset + bit_count > src.size() * 8) {
                    throw invalid_argument("invalid split_length, or index out of range");
                }
                if (bit_count > dest.size() * 8) {
                    throw invalid_argument("bit_count is too large for dest");
                }
#endif
                if (low_offset) {
                    // Low_offset mean we need to shift the bytes.
                    // Populates all of the full bytes in dest.
                    uint32_t i = 0;
                    while (i < full_byte_count) {
                        unsigned char low =
                            static_cast<unsigned char>(src[word_begin] >> low_offset);
                        unsigned char high = static_cast<unsigned char>(
                            static_cast<uint32_t>(src[word_begin + 1]) << (8 - low_offset));
                        dest[i] = low | high;
                        word_begin++;
                        i++;
                    }
                } else {
                    // Simple case, just copy all full bytes
                    copy_bytes(&src[word_begin], full_byte_count, dest.data());
                    word_begin += full_byte_count;
                }

                // We are now done with
                // dest[0], ..., dest[full_byte_count - 1].
                //
                // what remains is to populate dest[full_byte_count]
                // if needed there are some remaining bits.
                if (rem_bits) {
                    unsigned char &dest_word = dest[full_byte_count];

                    // We now populate the last unsigned char of dest. Branch on
                    // if the src bits are contained in a single byte or in two bytes.
                    bool one_word_src = low_offset + rem_bits <= 8;
                    if (one_word_src) {
                        // All the remaining bits live in src[word_begin]
                        unsigned char mask =
                            static_cast<unsigned char>((uint32_t(1) << rem_bits) - 1);

                        unsigned char low = src[word_begin];
                        low = static_cast<unsigned char>(low >> low_offset);
                        low = low & mask;

                        unsigned char high = dest_word;
                        high = static_cast<unsigned char>(high & (~mask));

                        dest_word = low | high;
                    } else {
                        // Extract the top bits out of src[word_begin].
                        // These will become the bottom bits of dest_word
                        uint32_t low_count = 8 - low_offset;
                        unsigned char low_mask =
                            static_cast<unsigned char>((uint32_t(1) << low_count) - 1);
                        unsigned char low =
                            static_cast<unsigned char>((src[word_begin] >> low_offset) & low_mask);

                        // Extract the bottom bits out of src[word_begin + 1].
                        // These will become the middle bits of dest_word
                        uint32_t mid_count = rem_bits - low_count;
                        unsigned char mid_mask =
                            static_cast<unsigned char>((uint32_t(1) << mid_count) - 1);
                        unsigned char mid = static_cast<unsigned char>(
                            static_cast<uint32_t>(src[word_begin + 1] & mid_mask) << low_count);

                        // Keep the high bits of dest_word
                        unsigned char high_mask =
                            static_cast<unsigned char>((~uint32_t(0)) << rem_bits);
                        unsigned char high = dest_word & high_mask;

                        // Or everything together
                        dest_word = low | mid | high;
                    }
                }
            }

            // Copies bit_count bits from src starting at the bit index by src_bit_offset.
            // Bits are written to dest starting at the dest_bit_offset bit. All other bits in
            // dest are unchanged, e.g. the bit indexed by [0,1,...,dest_bit_offset - 1],
            // [dest_bit_offset + bit_count, ...]
            void copy_with_bit_offset(
                gsl::span<const unsigned char> src,
                uint32_t src_bit_offset,
                uint32_t dest_bit_offset,
                uint32_t bit_count,
                gsl::span<unsigned char> dest)
            {
                uint32_t dest_next = (dest_bit_offset + 7) >> 3;
                uint32_t diff = dest_next * 8 - dest_bit_offset;

                if (bit_count > diff) {
                    copy_with_bit_offset(
                        src, src_bit_offset + diff, bit_count - diff, dest.subspan(dest_next));
                } else {
                    diff = bit_count;
                }

                if (diff) {
                    uint32_t src_begin = src_bit_offset >> 3;
                    uint32_t dest_begin = dest_bit_offset >> 3;
                    uint32_t dest_offset = dest_bit_offset & 7;
                    uint32_t src_offset = src_bit_offset & 7;
                    uint32_t high_diff = src_offset + diff - 8;
                    unsigned char &dest_val = dest[dest_begin];

                    if (high_diff <= 0) {
                        unsigned char mask = static_cast<unsigned char>((uint32_t(1) << diff) - 1);
                        unsigned char mid =
                            static_cast<unsigned char>((src[src_begin] >> src_offset) & mask);

                        mask = static_cast<unsigned char>(
                            ~(static_cast<uint32_t>(mask) << dest_offset));
                        mid = static_cast<unsigned char>(static_cast<uint32_t>(mid) << dest_offset);

                        dest_val = (dest_val & mask) | mid;
                    } else {
                        uint32_t low_diff = diff - high_diff;

                        unsigned char low_mask =
                            static_cast<unsigned char>((uint32_t(1) << low_diff) - 1);
                        unsigned char low =
                            static_cast<unsigned char>(src[src_begin] >> src_offset);
                        low &= low_mask;

                        unsigned char high_mask =
                            static_cast<unsigned char>((uint32_t(1) << high_diff) - 1);
                        unsigned char high = src[src_begin + 1] & high_mask;

                        low = static_cast<unsigned char>(low << dest_offset);
                        high = static_cast<unsigned char>(high << (dest_offset + low_diff));

                        unsigned char mask = static_cast<unsigned char>(
                            ~(((uint32_t(1) << diff) - 1) << dest_offset));

                        dest_val = (dest_val & mask) | low | high;
                    }
                }
            }
        } // namespace

        vector<felt_t> bits_to_field_elts(
            BitstringView<const unsigned char> bits, const Modulus &mod)
        {
            if (mod.is_zero()) {
                throw invalid_argument("mod cannot be zero");
            }

            // This is the largest n such that 2ⁿ ≤ mod < 2ⁿ⁺¹. We'll pack n bits into each field
            // element.
            uint32_t bits_per_felt = static_cast<uint32_t>(mod.bit_count() - 1);

            // The number of field elements necessary to represent all the bits:
            // ⌈bit_count / bits_per_felt⌉ = ⌊(bit_count + bits_per_felt-1) / bits_per_felt⌋
            uint32_t num_felts = (bits.bit_count() + bits_per_felt - 1) / bits_per_felt;

            // The return value
            vector<felt_t> felts;
            felts.reserve(num_felts);

            // The underlying data of the bitstring
            gsl::span<const unsigned char> src_data = bits.data();

            // Repeatedly convert `bits_per_felt` many bits into a field element (a felt_t), and
            // push that to the return vector.
            uint32_t num_uncopied_bits = bits.bit_count();
            uint32_t src_offset = 0;
            for (size_t j = 0; j < num_felts; j++) {
                // Make a byte array representing the field element. A felt_t is 8 unsigned char's
                array<unsigned char, 8> dst_felt_repr = {};
                gsl::span<unsigned char> dst_felt_repr_view = { dst_felt_repr.data(), 8 };

                // Copy the appropriate number of bits from the current offset to the field element
                // little-endian repr
                uint32_t copy_size = min(bits_per_felt, num_uncopied_bits);
                copy_with_bit_offset(src_data, src_offset, copy_size, dst_felt_repr_view);

                // Read the little-endian repr into the element
                felt_t dst_felt = read_u64_little_endian(dst_felt_repr);

                // Push the field element
                felts.push_back(dst_felt);

                src_offset += bits_per_felt;
                num_uncopied_bits -= copy_size;
            }

            return felts;
        }

        vector<felt_t> bits_to_field_elts(BitstringView<unsigned char> bits, const Modulus &mod)
        {
            return bits_to_field_elts(BitstringView<const unsigned char>(bits), mod);
        }

        Bitstring field_elts_to_bits(
            gsl::span<const felt_t> felts, uint32_t bit_count, const Modulus &mod)
        {
            if (felts.empty()) {
                throw invalid_argument("felts cannot be empty");
            }
            if (mod.is_zero()) {
                throw invalid_argument("mod cannot be zero");
            }

            // This is the largest n such that 2ⁿ ≤ mod < 2ⁿ⁺¹. We'll pack n bits into each field
            // element.
            uint32_t bits_per_felt = static_cast<uint32_t>(mod.bit_count() - 1);

            // Sanity check that bit_count isn't more than the field elements hold
            uint32_t max_num_bits = mul_safe(bits_per_felt, safe_cast<uint32_t>(felts.size()));
            if (bit_count > max_num_bits) {
                throw invalid_argument("bit_count exceeds the max number of bits the input holds");
            }

            // Sanity check that bit_count is within a field element's size from the total number of
            // bits. Using bit_count to omit an entire field element is nasty and unnecessary.
            if (bit_count <= max_num_bits - bits_per_felt) {
                throw invalid_argument(
                    "bit_count causes conversion to ignore entire field elements");
            }

            // The bitstring buffer. This will be part of the return value. The number of bytes is
            // ⌈bit_count / 8⌉
            vector<unsigned char> bit_buf((bit_count + 7) / 8, 0);
            gsl::span<unsigned char> bit_buf_view(bit_buf.data(), bit_buf.size());

            uint32_t num_uncopied_bits = bit_count;
            uint32_t dst_offset = 0;
            for (const felt_t &felt : felts) {
                // Serialize the field element
                array<unsigned char, 8> felt_bytes = write_u64_little_endian(felt);

                // Copy part (or the whole) of the field element into the appropriate position of
                // the buffer
                uint32_t copy_size = min(bits_per_felt, num_uncopied_bits);
                copy_with_bit_offset(
                    felt_bytes,
                    0, // src_offset
                    dst_offset,
                    copy_size,
                    bit_buf_view);

                dst_offset += copy_size;
                num_uncopied_bits -= copy_size;
            }

            return Bitstring(move(bit_buf), bit_count);
        }

        AlgItemLabel algebraize_item_label(
            const HashedItem &item,
            const EncryptedLabel &label,
            size_t item_bit_count,
            const Modulus &mod)
        {
            // Convert the item to a sequence of field elements. This is the "algebraic item".
            BitstringView<const unsigned char> item_bsw(
                item.get_as<const unsigned char>(), safe_cast<uint32_t>(item_bit_count));
            vector<felt_t> alg_item = bits_to_field_elts(item_bsw, mod);
            size_t felts_per_item = alg_item.size();

            // Convert the label to a sequence of field elements. This is the "algebraic label".
            BitstringView<const unsigned char> label_bsw(
                label.data(), safe_cast<uint32_t>(label.size() * 8));
            vector<felt_t> alg_label = bits_to_field_elts(label_bsw, mod);

            // Pad alg_label with zeros to be a multiple of alg_item length; label_size indicates
            // number of multiples of item length
            size_t label_size = (alg_label.size() + felts_per_item - 1) / felts_per_item;
            size_t alg_label_padded_size = label_size * felts_per_item;
            alg_label.resize(alg_label_padded_size);

            // We rearrange the alg_label field elements here so the receiver receives them in a
            // order where they can just be concatenated. Another option would be for the receiver
            // to do the work.
            AlgItemLabel ret;
            for (size_t felt_item_idx = 0; felt_item_idx < felts_per_item; felt_item_idx++) {
                // Create a vector of size label_size and populate it here
                vector<felt_t> label_parts;
                label_parts.reserve(label_size);
                for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                    label_parts.push_back(alg_label[felts_per_item * label_idx + felt_item_idx]);
                }

                // Append to the AlgItemLabel
                ret.emplace_back(make_pair(alg_item[felt_item_idx], move(label_parts)));
            }

            return ret;
        }

        AlgItem algebraize_item(const HashedItem &item, size_t item_bit_count, const Modulus &mod)
        {
            // Convert the item from to a sequence of field elements. This is the "algebraic item".
            BitstringView<const unsigned char> item_bsw(
                item.get_as<const unsigned char>(), safe_cast<uint32_t>(item_bit_count));
            return bits_to_field_elts(item_bsw, mod);
        }

        HashedItem dealgebraize_item(const AlgItem &item, size_t item_bit_count, const Modulus &mod)
        {
            Bitstring bits = field_elts_to_bits(item, safe_cast<uint32_t>(item_bit_count), mod);
            return HashedItem(bits.to_view());
        }

        EncryptedLabel dealgebraize_label(
            const AlgLabel &label, size_t label_bit_count, const Modulus &mod)
        {
            vector<unsigned char> bits(
                field_elts_to_bits(label, safe_cast<uint32_t>(label_bit_count), mod).release());
            return EncryptedLabel(move(bits), allocator<unsigned char>());
        }
    } // namespace util
} // namespace apsi
