// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <algorithm>
#include <cstddef>
#include <gsl/span>
#include <limits>
#include <seal/util/numth.h>
#include <seal/util/uintarithsmallmod.h>
#include "apsi/ffield/ffield.h"

namespace apsi
{
    namespace details
    {
        // Copies bitLength bits from src starting at the bit index by bitOffset.
        // Bits are written to dest starting at the first bit. All other bits in
        // dest are unchanged, e.g. the bit indexed by [bitLength, bitLength + 1, ...]
        void copy_with_bit_offset(gsl::span<const unsigned char> src, size_t bitOffset, size_t bitLength, gsl::span<unsigned char> dest);

        // Copies bitLength bits from src starting at the bit index by srcBitOffset.
        // Bits are written to dest starting at the destBitOffset bit. All other bits in
        // dest are unchanged, e.g. the bit indexed by [0,1,...,destBitOffset - 1], [destBitOffset + bitLength, ...]
        void copy_with_bit_offset(
            gsl::span<const unsigned char> src, size_t srcBitOffset, size_t destBitOffset, size_t bitLength, gsl::span<unsigned char> dest);
    } // namespace details

    class FFieldElt
    {
        friend class FFieldArray;
        friend class FFieldBatchEncoder;

    public:
        FFieldElt(FField field, const _ffield_elt_t &elt) : field_(field), elt_(elt)
        {}

        FFieldElt(FField field) : field_(std::move(field))
        {
            elt_.resize(static_cast<std::size_t>(field_.d_));
        }

        FFieldElt(FField field, const _ffield_elt_coeff_t *value) : field_(field)
        {
            std::copy_n(value, field_.d_, std::back_inserter(elt_));
        }

        inline _ffield_elt_coeff_t get_coeff(std::size_t index) const
        {
            // This function returns 0 when index is beyond the size of the poly,
            // which is critical for correct operation.
            return (index >= field_.d_) ? 0 : elt_[index];
        }

        inline void set_coeff(std::size_t index, _ffield_elt_coeff_t in)
        {
            if (index >= field_.d_)
            {
                throw std::out_of_range("index");
            }
            elt_[index] = in;
        }

        inline void set_zero()
        {
            std::fill(elt_.begin(), elt_.end(), 0);
        }

        inline void set_one()
        {
            std::fill(elt_.begin(), elt_.end(), 1);
        }

        inline bool is_zero() const
        {
            return std::all_of(elt_.cbegin(), elt_.cend(), [](auto val) { return !val; });
        }

        inline bool is_one() const
        {
            return std::all_of(elt_.cbegin(), elt_.cend(), [](auto val) { return val == 1; });
        }

        inline FField field() const
        {
            return field_;
        }

        inline void add(FFieldElt &out, const FFieldElt &in) const
        {
            const seal::Modulus &ch = field_.ch_;
            std::transform(elt_.cbegin(), elt_.cend(), in.elt_.cbegin(), out.elt_.begin(), [&ch](auto a, auto b) {
                return seal::util::add_uint64_mod(a, b, ch);
            });
        }

        inline void sub(FFieldElt &out, const FFieldElt &in) const
        {
            const seal::Modulus &ch = field_.ch_;
            std::transform(elt_.cbegin(), elt_.cend(), in.elt_.cbegin(), out.elt_.begin(), [&ch](auto a, auto b) {
                return seal::util::sub_uint64_mod(a, b, ch);
            });
        }

        inline void mul(FFieldElt &out, const FFieldElt &in) const
        {
            const seal::Modulus &ch = field_.ch_;
            std::transform(elt_.cbegin(), elt_.cend(), in.elt_.cbegin(), out.elt_.begin(), [&ch](auto a, auto b) {
                return seal::util::multiply_uint_mod(a, b, ch);
            });
        }

        inline void div(FFieldElt &out, const FFieldElt &in) const
        {
            const seal::Modulus &ch = field_.ch_;
            std::transform(elt_.cbegin(), elt_.cend(), in.elt_.cbegin(), out.elt_.begin(), [&ch](auto a, auto b) {
                _ffield_elt_coeff_t inv;
                if (!seal::util::try_invert_uint_mod(b, ch, inv))
                {
                    throw std::logic_error("division by zero");
                }
                return seal::util::multiply_uint_mod(a, inv, ch);
            });
        }

        inline void inv(FFieldElt &out) const
        {
            const seal::Modulus &ch = field_.ch_;
            std::transform(elt_.cbegin(), elt_.cend(), out.elt_.begin(), [&ch](auto a) {
                _ffield_elt_coeff_t inv;
                if (!seal::util::try_invert_uint_mod(a, ch, inv))
                {
                    throw std::logic_error("division by zero");
                }
                return inv;
            });
        }

        inline void inv()
        {
            inv(*this);
        }

        inline void neg(FFieldElt &out) const
        {
            const seal::Modulus &ch = field_.ch_;
            std::transform(elt_.cbegin(), elt_.cend(), out.elt_.begin(), [&ch](auto a) {
                return seal::util::negate_uint_mod(a, ch);
            });
        }

        inline void neg()
        {
            neg(*this);
        }

        inline void pow(FFieldElt &out, std::uint64_t e) const
        {
            const seal::Modulus &ch = field_.ch_;
            std::transform(elt_.cbegin(), elt_.cend(), out.elt_.begin(), [ch, e](auto a) {
                return seal::util::exponentiate_uint_mod(a, e, ch);
            });
        }

        inline void set(const FFieldElt &in)
        {
            if (field_ != in.field_)
            {
                throw std::logic_error("incompatible fields");
            }
            std::copy(in.elt_.cbegin(), in.elt_.cend(), elt_.begin());
        }

        inline bool equals(const FFieldElt &in) const
        {
            return std::equal(elt_.cbegin(), elt_.cend(), in.elt_.cbegin());
        }

        inline FFieldElt operator+(const FFieldElt &in) const
        {
            FFieldElt result(field_);
            add(result, in);
            return result;
        }

        inline FFieldElt operator-(const FFieldElt &in) const
        {
            FFieldElt result(field_);
            sub(result, in);
            return result;
        }

        inline FFieldElt operator*(const FFieldElt &in) const
        {
            FFieldElt result(field_);
            mul(result, in);
            return result;
        }

        inline FFieldElt operator/(const FFieldElt &in) const
        {
            FFieldElt result(field_);
            div(result, in);
            return result;
        }

        inline FFieldElt operator-() const
        {
            FFieldElt result(field_);
            neg(result);
            return result;
        }

        inline FFieldElt operator^(std::uint64_t e) const
        {
            FFieldElt result(field_);
            pow(result, e);
            return result;
        }

        inline void operator+=(const FFieldElt &in)
        {
            add(*this, in);
        }

        inline void operator-=(const FFieldElt &in)
        {
            sub(*this, in);
        }

        inline void operator*=(const FFieldElt &in)
        {
            mul(*this, in);
        }

        inline void operator/=(const FFieldElt &in)
        {
            div(*this, in);
        }

        inline void operator^=(std::uint64_t e)
        {
            pow(*this, e);
        }

        inline void operator=(const FFieldElt &in)
        {
            set(in);
        }

        inline bool operator==(const FFieldElt &compare) const
        {
            return equals(compare);
        }

        inline bool operator!=(const FFieldElt &compare) const
        {
            return !operator==(compare);
        }

        inline _ffield_elt_coeff_t *data()
        {
            return elt_.data();
        }

        inline const _ffield_elt_coeff_t *data() const
        {
            return elt_.data();
        }

        template <typename T>
        typename std::enable_if<std::is_pod<T>::value>::type encode(gsl::span<T> value, std::size_t bit_length)
        {
            gsl::span<const unsigned char> v2(reinterpret_cast<unsigned char *>(value.data()), value.size() * sizeof(T));

            // Should minus 1 to avoid wrapping around p
            std::size_t split_length = static_cast<std::size_t>(field_.ch_.bit_count() - 1);

            // How many coefficients do we need
            std::size_t split_index_bound = (bit_length + split_length - 1) / split_length;

            static_assert(std::is_pod<_ffield_elt_coeff_t>::value, "must be pod type");

            if (field_.d_ < static_cast<std::uint64_t>(split_index_bound))
            {
                throw std::invalid_argument("bit_length too large for extension field");
            }

            std::size_t offset = 0;
            for (std::size_t j = 0; j < split_index_bound; j++)
            {
                auto size = std::min<std::size_t>(split_length, bit_length);
                details::copy_with_bit_offset(
                    v2, offset, size, { reinterpret_cast<unsigned char *>(elt_.data() + j), sizeof(_ffield_elt_coeff_t) });

                offset += split_length;
                bit_length -= split_length;
            }
        }

        template <typename T>
        typename std::enable_if<std::is_pod<T>::value>::type decode(gsl::span<T> value, std::size_t bit_length)
        {
            gsl::span<unsigned char> v2(reinterpret_cast<unsigned char *>(value.data()), value.size() * sizeof(T));

            // Should minus 1 to avoid wrapping around p
            std::size_t split_length = static_cast<std::size_t>(field_.ch_.bit_count() - 1);

            // How many coefficients do we need in the FFieldElt
            std::size_t split_index_bound = (bit_length + split_length - 1) / split_length;
#ifndef NDEBUG
            if (static_cast<std::uint64_t>(split_index_bound) > field_.d_)
            {
                throw std::invalid_argument("too many bits required");
            }
#endif
            static_assert(std::is_pod<_ffield_elt_coeff_t>::value, "must be pod type");

            std::size_t offset = 0;
            for (std::size_t j = 0; j < split_index_bound; j++)
            {
                std::size_t size = std::min<std::size_t>(split_length, bit_length);
                details::copy_with_bit_offset(
                    { reinterpret_cast<unsigned char *>(elt_.data() + j), sizeof(_ffield_elt_coeff_t) }, 0, offset, size, v2);

                offset += split_length;
                bit_length -= split_length;
            }
        }

    private:
        FField field_;
        _ffield_elt_t elt_;
    }; // class FFieldElt

    // Easy printing
    inline std::ostream &operator<<(std::ostream &os, const FFieldElt &in)
    {
        for (std::size_t i = 0; i < in.field().d() - 1; i++)
        {
            os << in.data()[i] << " ";
        }
        os << in.data()[in.field().d()];
        return os;
    }
} // namespace apsi
