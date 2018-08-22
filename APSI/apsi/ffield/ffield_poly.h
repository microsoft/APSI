#pragma once

// STD
#include <ostream>
#include <algorithm>

// APSI
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_elt.h"
#include "apsi/ffield/ffield_array.h"
#include "apsi/tools/prng.h"

// FLINT
#include "fq_nmod_poly.h"


namespace apsi
{
    class FFieldPoly
    {
        friend class FFieldBatchEncoder;
        friend class FFieldFastBatchEncoder;

    public:
        FFieldPoly(std::shared_ptr<FField> field, std::size_t capacity = 0) :
            field_(std::move(field))
        {
            // Allocate enough space
            if(capacity > 0)
            {
                fq_nmod_poly_init2(poly_, capacity, field_->ctx_);
            }
            else
            {
                fq_nmod_poly_init(poly_, field_->ctx_);
            }
        }

        ~FFieldPoly()
        {
            fq_nmod_poly_clear(poly_, field_->ctx_);
        }

        FFieldPoly(const FFieldPoly &copy) :
            FFieldPoly(copy.field_, copy.poly_->length)
        {
            set(copy);
        }

        inline std::size_t degree() const
        {
            return fq_nmod_poly_degree(poly_, field_->ctx_);
        }

        inline std::size_t length() const
        {
            return fq_nmod_poly_length(poly_, field_->ctx_);
        }

        inline FFieldElt get(std::size_t index) const
        {
            _ffield_elt_t coeff;
            fq_nmod_init2(coeff, field_->ctx_);
            fq_nmod_poly_get_coeff(coeff, poly_, index, field_->ctx_);
            auto result = FFieldElt(field_, coeff);
            fq_nmod_clear(coeff, field_->ctx_);
            return result;
        }

        inline void set(std::size_t index, const FFieldElt &in)
        {
            fq_nmod_poly_set_coeff(poly_, index, in.elt_, field_->ctx_);
        }

        inline void set(std::size_t index, const seal::BigPoly &in)
        {
#ifndef NDEBUG
            if(static_cast<unsigned>(in.coeff_count()) > field_->d_)
            {
                throw std::invalid_argument("input too large");
            }
#endif
            _ffield_elt_t coeff;
            fq_nmod_init2(coeff, field_->ctx_);
            bigpoly_to_nmod_poly(in, coeff);
            fq_nmod_poly_set_coeff(poly_, index, coeff, field_->ctx_);
            fq_nmod_clear(coeff, field_->ctx_);
        }

        inline void set(std::size_t index, std::string in)
        {
            set(index, seal::BigPoly(in));
        }

        inline _ffield_elt_coeff_t get_coeff_of(std::size_t poly_index, std::size_t elt_index) 
        {
            _ffield_elt_t coeff;
            fq_nmod_init2(coeff, field_->ctx_);
            fq_nmod_poly_get_coeff(coeff, poly_, poly_index, field_->ctx_);
            auto result = nmod_poly_get_coeff_ui(coeff, elt_index);
            fq_nmod_clear(coeff, field_->ctx_);;
            return result;
        }

        inline void set_coeff_of(std::size_t poly_index, std::size_t elt_index, _ffield_elt_coeff_t in) 
        {
#ifndef NDEBUG
            if(elt_index >= field_->d_)
            {
                throw std::out_of_range("elt_index");
            }
#endif
            _ffield_elt_t coeff;
            fq_nmod_init2(coeff, field_->ctx_);
            fq_nmod_poly_get_coeff(coeff, poly_, poly_index, field_->ctx_);
            nmod_poly_set_coeff_ui(coeff, elt_index, in);
            fq_nmod_poly_set_coeff(poly_, poly_index, coeff, field_->ctx_); 
            fq_nmod_clear(coeff, field_->ctx_);
        }

        inline void set_zero()
        {
            fq_nmod_poly_zero(poly_, field_->ctx_);
        }

        inline void set_zero(std::size_t index)
        {
            _ffield_elt_t zero;
            fq_nmod_init(zero, field_->ctx_);
            fq_nmod_poly_set_coeff(poly_, index, zero, field_->ctx_);
            fq_nmod_clear(zero, field_->ctx_);
        }

        inline void set_one()
        {
            fq_nmod_poly_one(poly_, field_->ctx_);
        }

        inline void set_random(std::size_t degree, apsi::tools::DPRNG &prng)
        {
            _ffield_elt_t coeff;
            fq_nmod_init2(coeff, field_->ctx_);
            auto field_degree = field_->d_;
            for(std::size_t index = 0; index < degree + 1; index++)
            {
                for(unsigned i = 0; i < field_degree; i++)
                {
                    nmod_poly_set_coeff_ui(coeff, i, prng.get<mp_limb_t>()); 
                }
                fq_nmod_poly_set_coeff(poly_, index, coeff, field_->ctx_); 
            }
            fq_nmod_clear(coeff, field_->ctx_);
        }

        inline void set_random_monic(std::size_t degree, apsi::tools::DPRNG &prng)
        {
            _ffield_elt_t coeff;
            fq_nmod_init2(coeff, field_->ctx_);
            auto field_degree = field_->d_;

            // Set all but leading coefficient to random
            for(std::size_t index = 0; index < degree; index++)
            {
                for(unsigned i = 0; i < field_degree; i++)
                {
                    nmod_poly_set_coeff_ui(coeff, i, prng.get<mp_limb_t>()); 
                }
                fq_nmod_poly_set_coeff(poly_, index, coeff, field_->ctx_); 
            }

            // Set leading coefficient to 1
            fq_nmod_one(coeff, field_->ctx_);             
            fq_nmod_poly_set_coeff(poly_, degree, coeff, field_->ctx_); 
            fq_nmod_clear(coeff, field_->ctx_);
        }

        inline bool is_zero() const
        {
            return fq_nmod_poly_is_zero(poly_, field_->ctx_);
        }

        inline bool is_one() const
        {
            return fq_nmod_poly_is_one(poly_, field_->ctx_);
        }

        inline bool is_irreducible() const
        {
            return fq_nmod_poly_is_irreducible(poly_, field_->ctx_);
        }

        inline void set(const FFieldPoly &in) 
        {
            fq_nmod_poly_set(poly_, in.poly_, field_->ctx_);
        }

        inline bool equals(const FFieldPoly &in) const
        {
            return fq_nmod_poly_equal(poly_, in.poly_, field_->ctx_);
        }

        inline std::shared_ptr<FField> field() const
        {
            return field_;
        }

        inline void add(FFieldPoly &out, const FFieldPoly &in) const
        {
            fq_nmod_poly_add(out.poly_, poly_, in.poly_, field_->ctx_);
        }

        inline void sub(FFieldPoly &out, const FFieldPoly &in) const
        {
            fq_nmod_poly_sub(out.poly_, poly_, in.poly_, field_->ctx_);
        }

        inline void mul(FFieldPoly &out, const FFieldPoly &in) const
        {
            fq_nmod_poly_mul(out.poly_, poly_, in.poly_, field_->ctx_);
        }

        inline void sq(FFieldPoly &out) const
        {
            fq_nmod_poly_sqr(out.poly_, poly_, field_->ctx_);
        }
        
        inline void neg(FFieldPoly &out) const
        {
            fq_nmod_poly_neg(out.poly_, poly_, field_->ctx_);
        }

        inline void eval(FFieldElt &out, const FFieldElt &in) const
        {
            fq_nmod_poly_evaluate_fq_nmod(out.elt_, poly_, in.elt_, field_->ctx_);
        }

        inline void eval(FFieldArray &out, const FFieldArray &in) const
        {
            fq_nmod_poly_evaluate_fq_nmod_vec_fast(out.array_, poly_, in.array_, in.size_, field_->ctx_);
        }

        inline FFieldPoly operator +(const FFieldPoly &in) const
        {
            FFieldPoly result(field_);
            add(result, in);
            return result;
        }

        inline FFieldPoly operator -(const FFieldPoly &in) const
        {
            FFieldPoly result(field_);
            sub(result, in);
            return result;
        }

        inline FFieldPoly operator *(const FFieldPoly &in) const
        {
            FFieldPoly result(field_);
            mul(result, in);
            return result;
        }

        inline FFieldPoly operator -() const
        {
            FFieldPoly result(field_);
            neg(result);
            return result;
        }

        inline FFieldElt operator()(const FFieldElt &in) const
        {
            FFieldElt result(field_);
            eval(result, in);
            return result;
        }

        inline FFieldArray operator()(const FFieldArray &in) const
        {
            FFieldArray result(field_, in.size_);
            eval(result, in);
            return result;
        }

        inline void operator +=(const FFieldPoly &in)
        {
           add(*this, in); 
        }

        inline void operator -=(const FFieldPoly &in)
        {
           sub(*this, in); 
        }

        inline void operator *=(const FFieldPoly &in)
        {
           mul(*this, in); 
        }

        inline void operator =(const FFieldPoly &in)
        {
            set(in);
        }

        inline bool operator ==(const FFieldPoly &compare) const
        {
            return equals(compare);
        }

        inline bool operator !=(const FFieldPoly &compare) const 
        {
            return !operator ==(compare);
        }

    private:
       std::shared_ptr<FField> field_;
       _ffield_poly_t poly_; 
    };
}
