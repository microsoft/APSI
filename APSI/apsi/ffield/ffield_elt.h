#pragma once

// APSI
#include "apsi/ffield/ffield.h"

// CryptoTools
#include "cryptoTools/Crypto/PRNG.h"

namespace apsi
{
    class FFieldElt
    {
        friend class FFieldArray;
        friend class FFieldPoly;
        friend class FFieldNTT;
        friend class FFieldCRTBuilder;

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
            if(index >= field_->d_)
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
            for(unsigned i = 0; i < field_degree; i++)
            {
                nmod_poly_set_coeff_ui(elt_, i, prng.get<mp_limb_t>()); 
            }
        }

        inline void set_random_nonzero(oc::PRNG &prng)
        {
            do
            {
                set_random(prng);
            } while(is_zero());
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
            if(static_cast<unsigned>(in.coeff_count()) > field_->d_)
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
            // // Slow Frobenius
            // FFieldElt result(field_);
            // fq_nmod_frobenius(result.elt_, elt_, e, field_->ctx_);
            // return result;
           
            // Fast lookup approach
            FFieldElt result(field_);
            if(e == 0)
            {
                fq_nmod_set(result.elt_, elt_, field_->ctx_);
                return result;
            }
            FFieldElt temp(field_);
            for(unsigned i = 0; i < elt_->length; i++)
            {
                fq_nmod_mul_ui(temp.elt_, &field_->frob_table_(e, i), elt_->coeffs[i], field_->ctx_);
                result += temp;
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

    private:
        FFieldElt(std::shared_ptr<FField> field, const _ffield_elt_t in) : 
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
