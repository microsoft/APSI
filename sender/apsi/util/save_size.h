// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// This header is internal to APSI and is not installed. It holds the bounds with which
// SenderDB::save and BinBundle::save refuse a buffer that SenderDB::Load might not read, and a
// hook with which tests lower the limit. The two functions that compute the bounds are defined
// next to the code they mirror, in bin_bundle.cpp and sender_db.cpp.

// STD
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>

// FlatBuffers
#include "flatbuffers/base.h"
#include "flatbuffers/buffer.h"

// SEAL
#include "seal/context.h"
#include "seal/serialization.h"

namespace apsi::sender {
    class BinBundle;
} // namespace apsi::sender

namespace apsi::sender::util {
    /**
    Bounds on the size of a buffer in bytes: it is at least lower and at most upper.
    */
    struct SaveSizeBounds {
        std::size_t lower = 0;

        std::size_t upper = 0;
    };

    /**
    Returns why a buffer whose size has the given bounds is refused as possibly larger than
    max_size bytes: "takes at least N bytes, more than the M bytes SenderDB::Load reads" if even
    the lower bound is larger, and "takes up to N bytes, ..." with the upper bound otherwise.
    */
    std::string refusal_reason(const SaveSizeBounds &bounds, std::size_t max_size);

    /**
    A field of a FlatBuffers table: the voffset that the generated code names it by, and its size
    and alignment in the table.
    */
    struct FlatBufferField {
        flatbuffers::voffset_t voffset = 0;

        std::size_t size = 0;

        std::size_t alignment = 1;
    };

    /**
    Returns a field that refers to a table or a vector.
    */
    constexpr FlatBufferField offset_field(flatbuffers::voffset_t voffset) noexcept
    {
        return { voffset, sizeof(flatbuffers::uoffset_t), sizeof(flatbuffers::uoffset_t) };
    }

    /**
    Returns a scalar field of type T.
    */
    template <typename T>
    constexpr FlatBufferField scalar_field(flatbuffers::voffset_t voffset) noexcept
    {
        return { voffset, sizeof(T), sizeof(T) };
    }

    /**
    Returns a field that holds a struct of type T.
    */
    template <typename T>
    constexpr FlatBufferField struct_field(flatbuffers::voffset_t voffset) noexcept
    {
        return { voffset, sizeof(T), flatbuffers::AlignOf<T>() };
    }

    /**
    Computes bounds on the size of a size-prefixed FlatBuffer from the vectors and tables it is
    built from, in time proportional to their number, whatever their order. The lower bound counts
    the elements, fields, lengths and offsets that every vector and table has; the upper bound adds
    the padding that the builder can put before each of them, and a vtable for every table. The
    functions are inline and do no overflow checks, as they are called for every object a BinBundle
    saves, and the sizes they add up are those of objects in memory.
    */
    class FlatBufferSizeBounds {
    public:
        /**
        Adds a vector of count elements of elem_size bytes and the given alignment.
        */
        void add_vector(std::size_t count, std::size_t elem_size, std::size_t alignment) noexcept
        {
            add_vector(SaveSizeBounds{ count, count }, elem_size, alignment);
        }

        /**
        Adds a vector of between count.lower and count.upper elements of elem_size bytes and the
        given alignment.
        */
        void add_vector(
            const SaveSizeBounds &count, std::size_t elem_size, std::size_t alignment) noexcept
        {
            // Aligning the end of the elements, first for the length and then for the elements,
            // adds less than the larger of the two alignments; an empty vector is aligned only for
            // the length
            constexpr std::size_t length_size = sizeof(flatbuffers::uoffset_t);
            std::size_t padding_max = (alignment > length_size ? alignment : length_size) - 1;
            bounds_.lower += count.lower * elem_size + length_size;
            bounds_.upper += count.upper * elem_size + length_size + padding_max;
            max_alignment_ = alignment > max_alignment_ ? alignment : max_alignment_;
        }

        /**
        Adds a table with the given fields.
        */
        void add_table(const FlatBufferField *fields, std::size_t field_count) noexcept
        {
            // Aligning each field, and then the offset to the vtable, adds less than its
            // alignment. The vtable is the size of a slot for each field up to the last, and two
            // more, unless the table shares it with one built before.
            constexpr std::size_t soffset_size = sizeof(flatbuffers::soffset_t);
            std::size_t lower = soffset_size;
            std::size_t upper = 2 * soffset_size - 1;
            std::size_t vtable_size = 2 * sizeof(flatbuffers::voffset_t);
            for (std::size_t i = 0; i < field_count; i++) {
                const FlatBufferField &field = fields[i];
                std::size_t field_vtable_size = field.voffset + sizeof(flatbuffers::voffset_t);
                lower += field.size;
                upper += field.size + field.alignment - 1;
                vtable_size = field_vtable_size > vtable_size ? field_vtable_size : vtable_size;
                max_alignment_ =
                    field.alignment > max_alignment_ ? field.alignment : max_alignment_;
            }
            bounds_.lower += lower;
            bounds_.upper += upper + vtable_size;
        }

        /**
        Adds a table with the given fields; see the overload taking a pointer.
        */
        void add_table(std::initializer_list<FlatBufferField> fields) noexcept
        {
            add_table(fields.begin(), fields.size());
        }

        /**
        Adds the root offset and the size prefix that FinishSizePrefixed adds.
        */
        void finish_size_prefixed() noexcept
        {
            // Aligning the whole buffer adds less than the largest alignment of anything in it
            bounds_.lower += 2 * sizeof(flatbuffers::uoffset_t);
            bounds_.upper += 2 * sizeof(flatbuffers::uoffset_t) + max_alignment_ - 1;
        }

        /**
        Returns the bounds on the size of what has been added so far.
        */
        [[nodiscard]] const SaveSizeBounds &bounds() const noexcept
        {
            return bounds_;
        }

    private:
        SaveSizeBounds bounds_;

        std::size_t max_alignment_ = sizeof(flatbuffers::uoffset_t);
    };

    /**
    Returns bounds on the size of the buffer, with its size prefix, that BinBundle::save writes for
    bb at bundle_idx: with the plaintexts of the cache as bb holds them, or saved again in
    plaintext_compr_mode. seal_context must be the one bb was created with. This takes time
    proportional to the number of objects the buffer holds, and saves no plaintext again.
    */
    SaveSizeBounds bin_bundle_save_size_bounds(
        const BinBundle &bb,
        std::uint32_t bundle_idx,
        std::optional<seal::compr_mode_type> plaintext_compr_mode,
        const seal::SEALContext &seal_context);

    /**
    Returns bounds on the size of the buffer, with its size prefix, that SenderDB::save writes ahead
    of the BinBundles: the parameters, saved in params_byte_count bytes, the OPRF key, the
    HashedItem of each of hashed_item_count items, of which a stripped SenderDB has none, and the
    number of BinBundles. Only the HashedItems make it large, by 16 bytes each.
    */
    SaveSizeBounds sender_db_header_save_size_bounds(
        std::size_t params_byte_count,
        std::size_t oprf_key_byte_count,
        std::size_t hashed_item_count,
        std::size_t bin_bundle_count);

    /**
    Returns the limit on the size of a buffer that SenderDB::save and BinBundle::save write on the
    calling thread: apsi::util::max_buffer_size, the most SenderDB::Load reads, unless a
    ScopedSaveSizeLimit on the thread lowers it.
    */
    [[nodiscard]] std::size_t save_size_limit() noexcept;

    /**
    Lowers save_size_limit on the calling thread for as long as it exists, so that a test can have
    a small BinBundle refused. It never raises the limit. For tests only.
    */
    class ScopedSaveSizeLimit {
    public:
        explicit ScopedSaveSizeLimit(std::size_t limit) noexcept;

        ScopedSaveSizeLimit(const ScopedSaveSizeLimit &) = delete;

        ScopedSaveSizeLimit &operator=(const ScopedSaveSizeLimit &) = delete;

        ~ScopedSaveSizeLimit() noexcept;

    private:
        std::size_t previous_limit_;
    };
} // namespace apsi::sender::util
