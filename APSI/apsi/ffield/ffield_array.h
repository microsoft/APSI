#pragma once

// APSI
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_elt.h"

// CryptoTools
#include "cryptoTools/Crypto/PRNG.h"

namespace apsi
{
    class FFieldArray
    {
        friend class FFieldPoly;
        friend class FFieldCRTBuilder;
        friend class FFieldNTT;

    public:
        FFieldArray(std::shared_ptr<FField> field, std::size_t size) : 
            field_(std::move(field)), 
            size_(size),
            array_(_fq_nmod_vec_init(size, field_->ctx_))
        {
        } 

        ~FFieldArray()
        {
            _fq_nmod_vec_clear(array_, size_, field_->ctx_);
        }

        FFieldArray(const FFieldArray &copy) :
            FFieldArray(copy.field_, copy.size_)
        {
            set(copy);
        }

        inline std::size_t size() const
        {
            return size_;
        }

        inline FFieldElt get(std::size_t index) const
        {
            if(index > size_)
            {
                throw std::out_of_range("index");
            }
            return FFieldElt(field_, array_ + index);
        }

        inline void set(std::size_t index, const FFieldElt &in)
        {
            if(index > size_)
            {
                throw std::out_of_range("index");
            }
            fq_nmod_set(array_ + index, in.elt_, field_->ctx_);
        }

        inline void set(std::size_t index, const seal::BigPoly &in)
        {
            if(index > size_)
            {
                throw std::out_of_range("index");
            }
            if(static_cast<unsigned>(in.coeff_count()) > field_->d_)
            {
                throw std::invalid_argument("input too large");
            }
            bigpoly_to_nmod_poly(in, array_ + index);
        }

        inline void set(std::size_t index, std::string in)
        {
            set(index, seal::BigPoly(in));
        }

        inline _ffield_elt_coeff_t get_coeff_of(std::size_t array_index, std::size_t elt_index) 
        {
            return nmod_poly_get_coeff_ui(array_ + array_index, elt_index);
        }

        inline void set_coeff_of(std::size_t array_index, std::size_t elt_index, _ffield_elt_coeff_t in) 
        {
            if(array_index > size_)
            {
                throw std::out_of_range("array_index");
            }
            if(elt_index >= field_->d_)
            {
                throw std::out_of_range("elt_index");
            }
            nmod_poly_set_coeff_ui(array_ + array_index, elt_index, in);
        }

        inline void set_zero()
        {
            _fq_nmod_vec_zero(array_, size_, field_->ctx_);
        }

        inline void set_zero(std::size_t index)
        {
            if(index > size_)
            {
                throw std::out_of_range("index");
            }
            fq_nmod_zero(array_ + index, field_->ctx_);
        }

        inline void set_random(oc::PRNG &prng)
        {
            auto field_degree = field_->d_;
            for(std::size_t index = 0; index < size_; index++)
            {
                for(unsigned i = 0; i < field_degree; i++)
                {
                    nmod_poly_set_coeff_ui(array_ + index, i, prng.get<mp_limb_t>()); 
                }
            }
        }

        inline void set_random_nonzero(oc::PRNG &prng)
        {
            auto field_degree = field_->d_;
            for(std::size_t index = 0; index < size_; index++)
            {
                do
                {
                    for(unsigned i = 0; i < field_degree; i++)
                    {
                        nmod_poly_set_coeff_ui(array_ + index, i, prng.get<mp_limb_t>()); 
                    }
                } while(fq_nmod_is_zero(array_ + index, field_->ctx_));
            }
        }

        inline bool is_zero() const
        {
            return _fq_nmod_vec_is_zero(array_, size_, field_->ctx_);
        }

        inline void set(const FFieldArray &in) 
        {
            _fq_nmod_vec_set(array_, in.array_, size_, field_->ctx_);
        }

        inline bool equals(const FFieldArray &in) const
        {
            return _fq_nmod_vec_equal(array_, in.array_, size_, field_->ctx_);
        }

        inline std::shared_ptr<FField> field() const
        {
            return field_;
        }

        inline void add(FFieldArray &out, const FFieldArray &in) const
        {
            _fq_nmod_vec_add(out.array_, array_, in.array_, size_, field_->ctx_);
        }

        inline void sub(FFieldArray &out, const FFieldArray &in) const
        {
            _fq_nmod_vec_sub(out.array_, array_, in.array_, size_, field_->ctx_);
        }

        inline void mul(FFieldArray &out, const FFieldArray &in) const
        {
            auto ptr = array_;
            auto out_ptr = out.array_;
            auto in_ptr = in.array_;
            for(std::size_t i = 0; i < size_; i++, ptr++, out_ptr++, in_ptr++)
            {
                fq_nmod_mul(out_ptr, ptr, in_ptr, field_->ctx_);
            }
        }

        inline void div(FFieldArray &out, const FFieldArray &in) const
        {
            auto ptr = array_;
            auto out_ptr = out.array_;
            auto in_ptr = in.array_;
            for(std::size_t i = 0; i < size_; i++, ptr++, out_ptr++, in_ptr++)
            {
                fq_nmod_div(out_ptr, ptr, in_ptr, field_->ctx_);
            }
        }

        inline void inv(FFieldArray &out) const
        {
            auto ptr = array_;
            auto out_ptr = out.array_;
            for(std::size_t i = 0; i < size_; i++, ptr++, out_ptr++)
            {
                fq_nmod_inv(out_ptr, ptr, field_->ctx_);
            }
        }

        inline void neg(FFieldArray &out) const
        {
            auto ptr = array_;
            auto out_ptr = out.array_;
            for(std::size_t i = 0; i < size_; i++, ptr++, out_ptr++)
            {
                fq_nmod_neg(out_ptr, ptr, field_->ctx_);
            }
        }

        inline FFieldElt dot(const FFieldArray &in) const
        {
            FFieldElt result(field_);
            _fq_nmod_vec_dot(result.elt_, array_, in.array_, size_, field_->ctx_);
            return result;
        }

        inline FFieldArray operator +(const FFieldArray &in) const
        {
            FFieldArray result(field_, size_);
            add(result, in);
            return result;
        }

        inline FFieldArray operator -(const FFieldArray &in) const
        {
            FFieldArray result(field_, size_);
            sub(result, in);
            return result;
        }

        inline FFieldArray operator *(const FFieldArray &in) const
        {
            FFieldArray result(field_, size_);
            mul(result, in);
            return result;
        }

        inline FFieldArray operator /(const FFieldArray &in) const
        {
            FFieldArray result(field_, size_);
            div(result, in);
            return result;
        }

        inline FFieldArray operator -() const
        {
            FFieldArray result(field_, size_);
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

    private:
        std::shared_ptr<FField> field_;
        std::size_t size_;
        _ffield_array_t array_;
    };
}
