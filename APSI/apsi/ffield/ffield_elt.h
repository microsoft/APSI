#pragma once

// APSI
#include "apsi/ffield/ffield.h"

// CryptoTools
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitIterator.h"

// GLS
#include <gsl/span>

namespace apsi
{
    namespace details
    {
        // Copies bitLength bits from src starting at the bit index by bitOffset.
        // Bits are written to dest starting at the first bit. All other bits in 
        // dest are unchanged, e.g. the bit indexed by  [bitLength, bitLength + 1, ...]
        void copy_with_bit_offset(
            gsl::span<const oc::u8> src,
            std::int32_t bitOffset,
            int32_t bitLength,
            gsl::span<oc::u8> dest);

        // Copies bitLength bits from src starting at the bit index by srcBitOffset.
        // Bits are written to dest starting at the destBitOffset bit. All other bits in 
        // dest are unchanged, e.g. the bit indexed by [0,1,...,destBitOffset - 1], [destBitOffset + bitLength, ...]
        void copy_with_bit_offset(
            gsl::span<const oc::u8> src,
            std::int32_t srcBitOffset,
            std::int32_t destBitOffset,
            std::int32_t bitLength,
            gsl::span<oc::u8> dest);
    }

    class FFieldElt
    {
        friend class FFieldArray;
        friend class FFieldPoly;
        friend class FFieldNTT;
        friend class FFieldBatchEncoder;
        friend class FFieldFastBatchEncoder;

    public:
        FFieldElt(std::shared_ptr<FField> field) :
            field_(std::move(field))
        {
            // Allocate enough space to be an element of the field
            fq_nmod_init2(elt_, field_->ctx_);
        }

        FFieldElt(std::shared_ptr<FField> field, const seal::BigPoly &in) :
            field_(std::move(field))
        {
            // Allocate enough space to be an element of the field
            fq_nmod_init2(elt_, field_->ctx_);
            set(in);
        }

        FFieldElt(std::shared_ptr<FField> field, std::string in) :
            field_(std::move(field))
        {
            // Allocate enough space to be an element of the field
            fq_nmod_init2(elt_, field_->ctx_);
            set(in);
        }

        ~FFieldElt()
        {
            fq_nmod_clear(elt_, field_->ctx_);
        }

        FFieldElt(const FFieldElt &copy) :
            FFieldElt(copy.field_)
        {
            set(copy);
        }

        inline _ffield_elt_coeff_t get_coeff(std::size_t index) const
        {
            // This function returns 0 when index is beyond the size of the poly,
            // which is critical for correct operation.
            return nmod_poly_get_coeff_ui(elt_, index);
        }

        inline void set_coeff(std::size_t index, _ffield_elt_coeff_t in)
        {
            if (index >= field_->d_)
            {
                throw std::out_of_range("index");
            }
            nmod_poly_set_coeff_ui(elt_, index, in);
        }

        inline void set_zero()
        {
            fq_nmod_zero(elt_, field_->ctx_);
        }

        inline void set_one()
        {
            fq_nmod_one(elt_, field_->ctx_);
        }

        inline void set_random(oc::PRNG &prng)
        {
            auto field_degree = field_->d_;
            for (unsigned i = 0; i < field_degree; i++)
            {
                nmod_poly_set_coeff_ui(elt_, i, prng.get<mp_limb_t>());
            }
        }

        inline void set_random_nonzero(oc::PRNG &prng)
        {
            do
            {
                set_random(prng);
            } while (is_zero());
        }

        inline bool is_zero() const
        {
            return fq_nmod_is_zero(elt_, field_->ctx_);
        }

        inline bool is_one() const
        {
            return fq_nmod_is_one(elt_, field_->ctx_);
        }

        inline std::shared_ptr<FField> field() const
        {
            return field_;
        }

        inline void set(const seal::BigPoly &in)
        {
            if (static_cast<unsigned>(in.coeff_count()) > field_->d_)
            {
                throw std::invalid_argument("input too large");
            }
            bigpoly_to_nmod_poly(in, elt_);
        }

        inline void set(std::string in)
        {
            set(seal::BigPoly(in));
        }

        inline seal::BigPoly to_bigpoly() const
        {
            seal::BigPoly result;
            nmod_poly_to_bigpoly(elt_, result);
            return result;
        }

        inline std::string to_string() const
        {
            seal::BigPoly result;
            nmod_poly_to_bigpoly(elt_, result);
            return result.to_string();
        }

        inline void add(FFieldElt &out, const FFieldElt &in) const
        {
            fq_nmod_add(out.elt_, elt_, in.elt_, field_->ctx_);
        }

        inline void sub(FFieldElt &out, const FFieldElt &in) const
        {
            fq_nmod_sub(out.elt_, elt_, in.elt_, field_->ctx_);
        }

        inline void mul(FFieldElt &out, const FFieldElt &in) const
        {
            fq_nmod_mul(out.elt_, elt_, in.elt_, field_->ctx_);
        }

        inline void div(FFieldElt &out, const FFieldElt &in) const
        {
            fq_nmod_div(out.elt_, elt_, in.elt_, field_->ctx_);
        }

        inline void inv(FFieldElt &out) const
        {
            fq_nmod_inv(out.elt_, elt_, field_->ctx_);
        }

        inline void inv()
        {
            inv(*this);
        }

        inline void neg(FFieldElt &out) const
        {
            fq_nmod_neg(out.elt_, elt_, field_->ctx_);
        }

        inline void neg()
        {
            neg(*this);
        }

        inline void pow(FFieldElt &out, const _bigint_t e) const
        {
            fq_nmod_pow(out.elt_, elt_, e, field_->ctx_);
        }

        inline void pow(FFieldElt &out, std::uint64_t e) const
        {
            fq_nmod_pow_ui(out.elt_, elt_, e, field_->ctx_);
        }

        inline void pow(FFieldElt &out, const seal::BigUInt &e) const
        {
            _bigint_t flint_e;
            fmpz_init(flint_e);
            biguint_to_fmpz(e, flint_e);
            pow(out, flint_e);
        }

        inline void pow(FFieldElt &out, std::string e) const
        {
            pow(out, seal::BigUInt(e));
        }

        inline FFieldElt frob(unsigned e = 1) const
        {
            FFieldElt result(field_);

            if(field_->frob_populated_)
            {
                // Fast lookup approach
                if (e == 0)
                {
                    fq_nmod_set(result.elt_, elt_, field_->ctx_);
                    return result;
                }
                FFieldElt temp(field_);
                for (unsigned i = 0; i < elt_->length; i++)
                {
                    fq_nmod_mul_ui(temp.elt_, &field_->frob_table_(e, i), elt_->coeffs[i], field_->ctx_);
                    result += temp;
                }
            }
            else
            {
                // Slow Frobenius
                fq_nmod_frobenius(result.elt_, elt_, e, field_->ctx_);
            }
            return result;
        }

        inline void set(const FFieldElt &in)
        {
            fq_nmod_set(elt_, in.elt_, field_->ctx_);
        }

        inline bool equals(const FFieldElt &in) const
        {
            return fq_nmod_equal(elt_, in.elt_, field_->ctx_);
        }

        inline FFieldElt operator +(const FFieldElt &in) const
        {
            FFieldElt result(field_);
            add(result, in);
            return result;
        }

        inline FFieldElt operator -(const FFieldElt &in) const
        {
            FFieldElt result(field_);
            sub(result, in);
            return result;
        }

        inline FFieldElt operator *(const FFieldElt &in) const
        {
            FFieldElt result(field_);
            mul(result, in);
            return result;
        }

        inline FFieldElt operator /(const FFieldElt &in) const
        {
            FFieldElt result(field_);
            div(result, in);
            return result;
        }

        inline FFieldElt operator -() const
        {
            FFieldElt result(field_);
            neg(result);
            return result;
        }

        inline FFieldElt operator ^(const _bigint_t &e) const
        {
            FFieldElt result(field_);
            pow(result, e);
            return result;
        }

        inline FFieldElt operator ^(std::uint64_t e) const
        {
            FFieldElt result(field_);
            pow(result, e);
            return result;
        }

        inline FFieldElt operator ^(const seal::BigUInt &e) const
        {
            FFieldElt result(field_);
            pow(result, e);
            return result;
        }

        inline FFieldElt operator ^(std::string e) const
        {
            FFieldElt result(field_);
            pow(result, e);
            return result;
        }

        inline void operator +=(const FFieldElt &in)
        {
            add(*this, in);
        }

        inline void operator -=(const FFieldElt &in)
        {
            sub(*this, in);
        }

        inline void operator *=(const FFieldElt &in)
        {
            mul(*this, in);
        }

        inline void operator /=(const FFieldElt &in)
        {
            div(*this, in);
        }

        inline void operator ^=(const _bigint_t &e)
        {
            pow(*this, e);
        }

        inline void operator ^=(std::uint64_t e)
        {
            pow(*this, e);
        }

        inline void operator ^=(const seal::BigUInt &e)
        {
            pow(*this, e);
        }

        inline void operator ^=(std::string e)
        {
            pow(*this, e);
        }

        inline void operator =(const FFieldElt &in)
        {
            set(in);
        }

        inline void operator =(const seal::BigPoly &in)
        {
            set(in);
        }

        inline void operator =(std::string in)
        {
            set(in);
        }

        inline bool operator ==(const FFieldElt &compare) const
        {
            return equals(compare);
        }

        inline bool operator !=(const FFieldElt &compare) const
        {
            return !operator ==(compare);
        }

        inline _ffield_elt_ptr_t data()
        {
            return &elt_[0];
        }

        inline _ffield_elt_const_ptr_t data() const
        {
            return &elt_[0];
        }

        template<typename T>
        typename std::enable_if<std::is_pod<T>::value>::type
            encode(gsl::span<T> value, unsigned bit_length)
        {
            gsl::span<const oc::u8> v2(reinterpret_cast<oc::u8*>(value.data()), value.size() * sizeof(T));

            // Should minus 1 to avoid wrapping around p
            unsigned split_length = seal::util::get_significant_bit_count(field_->ch()) - 1;

            // How many coefficients do we need in the ExFieldElement
            unsigned split_index_bound = (bit_length + split_length - 1) / split_length;

            static_assert(std::is_pod<_ffield_elt_coeff_t>::value, "must be pod type");
            _ffield_elt_coeff_t temp = 0;
            gsl::span<oc::u8> temp_span(reinterpret_cast<oc::u8*>(&temp), sizeof(_ffield_elt_coeff_t));

            //auto end = std::min<unsigned>(field_->d_, split_index_bound);
            if (field_->d_ < split_index_bound)
                throw std::invalid_argument("bit_length too large for extension field");

            auto offset = 0;
            for (unsigned j = 0; j < split_index_bound; j++)
            {
                auto size = std::min<int>(split_length, bit_length);
                temp = 0;
                details::copy_with_bit_offset(v2, offset, size, temp_span);
                nmod_poly_set_coeff_ui(elt_, j, temp);

                offset += split_length;
                bit_length -= split_length;
            }

            //temp = 0;
            //for (auto j = split_index_bound; j < field_->d_; ++j)
            //{
            //    nmod_poly_set_coeff_ui(elt_, j, temp);
            //}
        }

        template<typename T>
        typename std::enable_if<std::is_pod<T>::value>::type
            decode(gsl::span<T> value, unsigned bit_length)
        {
            gsl::span<oc::u8> v2(reinterpret_cast<oc::u8*>(value.data()), value.size() * sizeof(T));

            // Should minus 1 to avoid wrapping around p
            unsigned split_length = seal::util::get_significant_bit_count(field_->ch()) - 1;

            // How many coefficients do we need in the FFieldElt
            unsigned split_index_bound = (bit_length + split_length - 1) / split_length;
#ifndef NDEBUG
            if (split_index_bound > field_->d_)
            {
                throw std::invalid_argument("too many bits required");
            }
#endif
            static_assert(std::is_pod<_ffield_elt_coeff_t>::value, "must be pod type");
            _ffield_elt_coeff_t temp = 0;
            auto offset = 0;
            gsl::span<const oc::u8> temp_span(reinterpret_cast<oc::u8*>(&temp), sizeof(_ffield_elt_coeff_t));

            for (unsigned j = 0; j < split_index_bound; j++)
            {
                auto size = std::min<int>(split_length, bit_length);

                temp = nmod_poly_get_coeff_ui(elt_, j);
                details::copy_with_bit_offset(temp_span, 0, offset, size, v2);

                offset += split_length;
                bit_length -= split_length;
            }
        }

    private:
        FFieldElt(std::shared_ptr<FField> field, const _ffield_elt_ptr_t in) :
            field_(std::move(field))
        {
            // Allocate enough space to be an element of the field
            fq_nmod_init2(elt_, field_->ctx_);
            fq_nmod_set(elt_, in, field_->ctx_);
        }

        std::shared_ptr<FField> field_;
        _ffield_elt_t elt_;
    };

    // Easy printing
    inline std::ostream &operator <<(std::ostream &os, const FFieldElt &in)
    {
        return os << in.to_string();
    }
}
