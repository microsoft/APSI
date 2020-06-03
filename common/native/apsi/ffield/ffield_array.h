// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include "apsi/ffield/ffield_elt.h"

namespace apsi
{
    class FFieldArray
    {
        friend class FFieldBatchEncoder;

    public:
        FFieldArray(std::size_t size, FField field) : size_(size), field_(field)
        {
            // Initialize array
            array_.resize(static_cast<std::size_t>(field_.degree_ * size_), 0);
        }

        FFieldArray(const FFieldArray &copy) = default;

        inline std::size_t size() const
        {
            return size_;
        }

        inline FFieldElt get(std::size_t index) const
        {
#ifdef APSI_DEBUG
            if (index >= size_)
            {
                throw std::out_of_range("index");
            }
#endif
            return { field_, data(index) };
        }

        inline FFieldElt::CoeffType get_coeff_of(std::size_t index, std::size_t coeff) const
        {
#ifdef APSI_DEBUG
            if (index >= size_)
            {
                throw std::out_of_range("index");
            }
            if (coeff >= field_.degree_)
            {
                throw std::out_of_range("coeff");
            }
#endif
            return *(data(index) + coeff);
        }

        inline void set(std::size_t index, const FFieldElt &in)
        {
#ifdef APSI_DEBUG
            if (index >= size_)
            {
                throw std::out_of_range("index");
            }
            if (field_ != in.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            std::copy_n(in.data(), field_.degree_, data(index));
        }

        inline void set(std::size_t dest_index, std::size_t src_index, const FFieldArray &in)
        {
#ifdef APSI_DEBUG
            if (dest_index >= size_)
            {
                throw std::out_of_range("dest_index");
            }
            if (src_index > in.size_)
            {
                throw std::out_of_range("src_index");
            }
            if (field_ != in.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            std::copy(in.data(src_index), in.data(src_index + 1), data(dest_index));
        }

        inline void set_coeff_of(std::size_t index, std::size_t coeff, FFieldElt::CoeffType value)
        {
#ifdef APSI_DEBUG
            if (index >= size_)
            {
                throw std::out_of_range("index");
            }
            if (coeff >= field_.degree_)
            {
                throw std::out_of_range("coeff");
            }
#endif
            *(data(index) + coeff) = value;
        }

        inline void set_zero(std::size_t index)
        {
#ifdef APSI_DEBUG
            if (index >= size_)
            {
                throw std::out_of_range("index");
            }
#endif
            std::fill_n(data(index), field_.degree_, 0);
        }

        inline bool is_zero() const
        {
            return std::all_of(array_.cbegin(), array_.cend(), [](auto a) { return !a; });
        }

        inline bool is_zero(std::size_t index) const
        {
            return std::all_of(data(index), data(index + 1), [](auto a) { return !a; });
        }

        inline void set(const FFieldArray &in)
        {
#ifdef APSI_DEBUG
            if (in.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != in.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            std::copy(in.array_.cbegin(), in.array_.cend(), array_.begin());
        }

        inline bool equals(const FFieldArray &in) const
        {
#ifdef APSI_DEBUG
            if (in.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != in.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            return std::equal(array_.cbegin(), array_.cend(), in.array_.cbegin());
        }

        inline FField field() const
        {
            return field_;
        }

        inline void add(FFieldArray &out, const FFieldArray &in) const
        {
#ifdef APSI_DEBUG
            if (in.size_ != size_ || out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != in.field_ || field_ != out.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            const seal::Modulus &ch = field_.characteristic_;
            std::transform(
                array_.cbegin(), array_.cend(), in.array_.cbegin(), out.array_.begin(),
                [&ch](auto a, auto b) { return seal::util::add_uint64_mod(a, b, ch); });
        }

        inline void sub(FFieldArray &out, const FFieldArray &in) const
        {
#ifdef APSI_DEBUG
            if (in.size_ != size_ || out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != in.field_ || field_ != out.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            const seal::Modulus &ch = field_.characteristic_;
            std::transform(
                array_.cbegin(), array_.cend(), in.array_.cbegin(), out.array_.begin(),
                [&ch](auto a, auto b) { return seal::util::sub_uint64_mod(a, b, ch); });
        }

        inline void mul(FFieldArray &out, const FFieldArray &in) const
        {
#ifdef APSI_DEBUG
            if (in.size_ != size_ || out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != in.field_ || field_ != out.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            const seal::Modulus &ch = field_.characteristic_;
            std::transform(
                array_.cbegin(), array_.cend(), in.array_.cbegin(), out.array_.begin(),
                [&ch](auto a, auto b) { return seal::util::multiply_uint_mod(a, b, ch); });
        }

        inline void div(FFieldArray &out, const FFieldArray &in) const
        {
#ifdef APSI_DEBUG
            if (in.size_ != size_ || out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != in.field_ || field_ != out.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            const seal::Modulus &ch = field_.characteristic_;
            std::transform(
                array_.cbegin(), array_.cend(), in.array_.cbegin(), out.array_.begin(), [&ch](auto a, auto b) {
                    FFieldElt::CoeffType inv;
                    if (!seal::util::try_invert_uint_mod(b, ch, inv))
                    {
                        throw std::logic_error("division by zero");
                    }
                    return seal::util::multiply_uint_mod(a, inv, ch);
                });
        }

        inline void inv(FFieldArray &out) const
        {
#ifdef APSI_DEBUG
            if (out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != out.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            const seal::Modulus &ch = field_.characteristic_;
            std::transform(array_.cbegin(), array_.cend(), out.array_.begin(), [&ch](auto a) {
                FFieldElt::CoeffType inv;
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

        inline void neg(FFieldArray &out) const
        {
#ifdef APSI_DEBUG
            if (out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != out.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            const seal::Modulus &ch = field_.characteristic_;
            std::transform(array_.cbegin(), array_.cend(), out.array_.begin(), [&ch](auto a) {
                return seal::util::negate_uint_mod(a, ch);
            });
        }

        inline void neg()
        {
            neg(*this);
        }

        inline void sq(FFieldArray &out) const
        {
#ifdef APSI_DEBUG
            if (out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != out.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            const seal::Modulus &ch = field_.characteristic_;
            std::transform(array_.cbegin(), array_.cend(), out.array_.begin(), [&ch](auto a) {
                return seal::util::multiply_uint_mod(a, a, ch);
            });
        }

        inline void sq()
        {
            sq(*this);
        }

        inline FFieldArray operator+(const FFieldArray &in) const
        {
            FFieldArray result(size_, field_);
            add(result, in);
            return result;
        }

        inline FFieldArray operator-(const FFieldArray &in) const
        {
            FFieldArray result(size_, field_);
            sub(result, in);
            return result;
        }

        inline FFieldArray operator*(const FFieldArray &in) const
        {
            FFieldArray result(size_, field_);
            mul(result, in);
            return result;
        }

        inline FFieldArray operator/(const FFieldArray &in) const
        {
            FFieldArray result(size_, field_);
            div(result, in);
            return result;
        }

        inline FFieldArray operator-() const
        {
            FFieldArray result(size_, field_);
            neg(result);
            return result;
        }

        inline void operator+=(const FFieldArray &in)
        {
            add(*this, in);
        }

        inline void operator-=(const FFieldArray &in)
        {
            sub(*this, in);
        }

        inline void operator*=(const FFieldArray &in)
        {
            mul(*this, in);
        }

        inline void operator/=(const FFieldArray &in)
        {
            div(*this, in);
        }

        inline void operator=(const FFieldArray &in)
        {
            set(in);
        }

        inline bool operator==(const FFieldArray &compare) const
        {
            return equals(compare);
        }

        inline bool operator!=(const FFieldArray &compare) const
        {
            return !operator==(compare);
        }

        inline FFieldElt::CoeffType *data()
        {
            return array_.data();
        }

        inline const FFieldElt::CoeffType *data() const
        {
            return array_.data();
        }

        inline FFieldElt::CoeffType *data(std::size_t index)
        {
            return array_.data() + index * field_.degree_;
        }

        inline const FFieldElt::CoeffType *data(std::size_t index) const
        {
            return array_.data() + index * field_.degree_;
        }

    private:
        std::size_t size_;
        FField field_;
        std::vector<FFieldElt::CoeffType> array_;
    }; // class FFieldArray
} // namespace apsi
