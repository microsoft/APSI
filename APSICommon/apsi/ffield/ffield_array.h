// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <algorithm>
#include <vector>

// APSI
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_elt.h"
#include "apsi/tools/prng.h"

// GSL
#include <gsl/span>

namespace apsi
{
    class FFieldArray
    {
        friend class FFieldFastBatchEncoder;

    public:
        FFieldArray(std::size_t size, FField field) : 
            size_(size),
            field_(field)
        {
            // Initialize array
            array_.resize(field_.d_ * size_, 0);
        }

        FFieldArray(const FFieldArray &copy) = default;

        inline std::size_t size() const
        {
            return size_;
        }

        inline FFieldElt get(std::size_t index) const
        {
#ifndef NDEBUG
            if (index >= size_)
            {
                throw std::out_of_range("index");
            }
#endif
            return { field_, data(index) };
        }

        inline _ffield_elt_coeff_t get_coeff_of(std::size_t index, std::size_t coeff) const
        {
#ifndef NDEBUG
            if (index >= size_)
            {
                throw std::out_of_range("index");
            }
            if (coeff >= field_.d_)
            {
                throw std::out_of_range("coeff");
            }
#endif
            return *(data(index) + coeff);
        }

        inline void set(std::size_t index, const FFieldElt &in)
        {
#ifndef NDEBUG
            if (index >= size_)
            {
                throw std::out_of_range("index");
            }
            if (field_ != in.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            std::copy_n(in.data(), field_.d_, data(index));
        }

        inline void set(std::size_t dest_index, std::size_t src_index, const FFieldArray &in)
        {
#ifndef NDEBUG
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

        inline void set_coeff_of(
            std::size_t index, std::size_t coeff, _ffield_elt_coeff_t value)
        {
#ifndef NDEBUG
            if (index >= size_)
            {
                throw std::out_of_range("index");
            }
            if (coeff >= field_.d_)
            {
                throw std::out_of_range("coeff");
            }
#endif
            *(data(index) + coeff) = value;
        }

        inline void set_zero(std::size_t index)
        {
#ifndef NDEBUG
            if (index >= size_)
            {
                throw std::out_of_range("index");
            }
#endif
            std::fill_n(data(index), field_.d_, 0);
        }

        inline void set_random(apsi::tools::PRNG &prng)
        {
            auto max_int = std::numeric_limits<_ffield_elt_coeff_t>::max(); 
            _ffield_elt_coeff_t max_value = max_int - max_int % field_.ch_.value();
            for (std::size_t i = 0; i < array_.size(); i++)
            {
                // Rejection sampling
                _ffield_elt_coeff_t temp_value;
                do
                {
                    temp_value = prng.get<_ffield_elt_coeff_t>();
                } while(temp_value > max_value);
                array_[i] = temp_value % field_.ch_.value();
            }
        }

        inline void set_random_nonzero(apsi::tools::PRNG &prng)
        {
            auto max_int = std::numeric_limits<_ffield_elt_coeff_t>::max(); 
            _ffield_elt_coeff_t max_value = max_int - max_int % field_.ch_.value();
            for (std::size_t i = 0; i < array_.size(); i++)
            {
                // Rejection sampling
                _ffield_elt_coeff_t temp_value;
                do
                {
                    temp_value = prng.get<_ffield_elt_coeff_t>();
                } while(temp_value > max_value || !temp_value);
                array_[i] = temp_value % field_.ch_.value();
            }
        }

        inline bool is_zero() const
        {
            return std::all_of(array_.cbegin(), array_.cend(),
                [](auto a) { return !a; });
        }

        inline bool is_zero(std::size_t index) const
        {
            return std::all_of(data(index), data(index + 1),
                [](auto a) { return !a; });
        }

        inline void set(const FFieldArray &in) 
        {
#ifndef NDEBUG
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
#ifndef NDEBUG
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
#ifndef NDEBUG
            if (in.size_ != size_ || out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != in.field_ || field_ != out.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            const seal::SmallModulus &ch = field_.ch_;
            std::transform(array_.cbegin(), array_.cend(), in.array_.cbegin(), out.array_.begin(),
                [&ch](auto a, auto b) { return seal::util::add_uint_uint_mod(a, b, ch); });
        }

        inline void sub(FFieldArray &out, const FFieldArray &in) const
        {
#ifndef NDEBUG
            if (in.size_ != size_ || out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != in.field_ || field_ != out.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            const seal::SmallModulus &ch = field_.ch_;
            std::transform(array_.cbegin(), array_.cend(), in.array_.cbegin(), out.array_.begin(),
                [&ch](auto a, auto b) { return seal::util::sub_uint_uint_mod(a, b, ch); });
        }

        inline void mul(FFieldArray &out, const FFieldArray &in) const
        {
#ifndef NDEBUG
            if (in.size_ != size_ || out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != in.field_ || field_ != out.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            const seal::SmallModulus &ch = field_.ch_;
            std::transform(array_.cbegin(), array_.cend(), in.array_.cbegin(), out.array_.begin(),
                [&ch](auto a, auto b) { return seal::util::multiply_uint_uint_mod(a, b, ch); });
        }

        inline void div(FFieldArray &out, const FFieldArray &in) const
        {
#ifndef NDEBUG
            if (in.size_ != size_ || out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != in.field_ || field_ != out.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            const seal::SmallModulus &ch = field_.ch_;
            std::transform(array_.cbegin(), array_.cend(), in.array_.cbegin(), out.array_.begin(),
                [&ch](auto a, auto b) {
                    _ffield_elt_coeff_t inv;
                    if (!seal::util::try_invert_uint_mod(b, ch, inv)) {
                        throw std::logic_error("division by zero");
                    }
                    return seal::util::multiply_uint_uint_mod(a, inv, ch);
                });
        }

        inline void inv(FFieldArray &out) const
        {
#ifndef NDEBUG
            if (out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != out.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            const seal::SmallModulus &ch = field_.ch_;
            std::transform(array_.cbegin(), array_.cend(), out.array_.begin(), [&ch](auto a) {
                    _ffield_elt_coeff_t inv;
                    if (!seal::util::try_invert_uint_mod(a, ch, inv)) {
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
#ifndef NDEBUG
            if (out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != out.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            const seal::SmallModulus &ch = field_.ch_;
            std::transform(array_.cbegin(), array_.cend(), out.array_.begin(),
                [&ch](auto a) { return seal::util::negate_uint_mod(a, ch); });
        }
        
        inline void neg()
        {
            neg(*this);
        }

        inline void sq(FFieldArray &out) const
        {
#ifndef NDEBUG
            if (out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            if (field_ != out.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            const seal::SmallModulus &ch = field_.ch_;
            std::transform(array_.cbegin(), array_.cend(), out.array_.begin(),
                [&ch](auto a) { return seal::util::multiply_uint_uint_mod(a, a, ch); });
        }

        inline void sq() 
        {
            sq(*this);
        }

        inline FFieldArray operator +(const FFieldArray &in) const
        {
            FFieldArray result(size_, field_);
            add(result, in);
            return result;
        }

        inline FFieldArray operator -(const FFieldArray &in) const
        {
            FFieldArray result(size_, field_);
            sub(result, in);
            return result;
        }

        inline FFieldArray operator *(const FFieldArray &in) const
        {
            FFieldArray result(size_, field_);
            mul(result, in);
            return result;
        }

        inline FFieldArray operator /(const FFieldArray &in) const
        {
            FFieldArray result(size_, field_);
            div(result, in);
            return result;
        }

        inline FFieldArray operator -() const
        {
            FFieldArray result(size_, field_);
            neg(result);
            return result;
        }

        inline void operator +=(const FFieldArray &in)
        {
           add(*this, in); 
        }

        inline void operator -=(const FFieldArray &in)
        {
           sub(*this, in); 
        }

        inline void operator *=(const FFieldArray &in)
        {
           mul(*this, in); 
        }

        inline void operator /=(const FFieldArray &in)
        {
           div(*this, in); 
        }

        inline void operator =(const FFieldArray &in)
        {
            set(in);
        }

        inline bool operator ==(const FFieldArray &compare) const
        {
            return equals(compare);
        }

        inline bool operator !=(const FFieldArray &compare) const 
        {
            return !operator ==(compare);
        }

        inline _ffield_elt_coeff_t *data()
        {
            return array_.data();
        }

        inline const _ffield_elt_coeff_t *data() const
        {
            return array_.data();
        }

        inline _ffield_elt_coeff_t *data(std::size_t index)
        {
            return array_.data() + index * field_.d_;
        }

        inline const _ffield_elt_coeff_t *data(std::size_t index) const
        {
            return array_.data() + index * field_.d_;
        }

    private:
        std::size_t size_;
        FField field_;
        std::vector<_ffield_elt_coeff_t> array_;
    };
}
