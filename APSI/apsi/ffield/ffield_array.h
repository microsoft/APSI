#pragma once

// STD
#include <memory>
#include <vector>

// APSI
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_elt.h"

// CryptoTools
#include "cryptoTools/Crypto/PRNG.h"

// GSL
#include <gsl/span>

namespace apsi
{
    class FFieldArray
    {
        friend class FFieldPoly;
        friend class FFieldCRTBuilder;
        friend class FFieldFastCRTBuilder;
        friend class FFieldNTT;

    public:
        FFieldArray(std::shared_ptr<FField> field, std::size_t size) : 
            size_(size),
            fields_(size_, field)
        {
            // Initialize array
            array_ = new _ffield_array_elt_t[size_];
            for(std::size_t i = 0; i < size_; i++)
            {
                fq_nmod_init2(array_ + i, field->ctx_);
            }
        } 

        FFieldArray(gsl::span<const std::shared_ptr<FField> > fields) : 
            size_(fields.size())
        {
            // Initialize fields
            fields_.reserve(size_);
            for(std::size_t i = 0; i < size_; i++)
            {
                fields_.emplace_back(fields[i]);
            }

            // Initialize array
            array_ = new _ffield_array_elt_t[size_];
            for(std::size_t i = 0; i < size_; i++)
            {
                fq_nmod_init2(array_ + i, fields_[i]->ctx_);
            }
        } 

        FFieldArray(const std::vector<std::shared_ptr<FField> > &fields) : 
            FFieldArray(gsl::span<const std::shared_ptr<FField> >(fields.data(), fields.size()))
        {
        }

        ~FFieldArray()
        {
            for(std::size_t i = 0; i < size_; i++)
            {
                fq_nmod_clear(array_ + i, fields_[i]->ctx_);
            }

            delete[] array_;
            array_ = nullptr;

            fields_.clear();
        }

        FFieldArray(const FFieldArray &copy) :
            FFieldArray(gsl::span<const std::shared_ptr<FField> >(copy.fields_.data(), copy.size_))
        {
            set(copy);
        }

        inline std::size_t size() const
        {
            return size_;
        }

        inline FFieldElt get(std::size_t index) const
        {
#ifndef NDEBUG
            if(index > size_)
            {
                throw std::out_of_range("index");
            }
#endif
            return FFieldElt(fields_[index], array_ + index);
        }

        inline void set(std::size_t index, const FFieldElt &in)
        {
#ifndef NDEBUG
            if(index > size_)
            {
                throw std::out_of_range("index");
            }
            if(fields_[index] != in.field_)
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            fq_nmod_set(array_ + index, in.elt_, fields_[index]->ctx_);
        }

        inline void set(std::size_t dest_index, std::size_t src_index, const FFieldArray &in)
        {
#ifndef NDEBUG
            if(dest_index > size_)
            {
                throw std::out_of_range("dest_index");
            }
            if(src_index > in.size_)
            {
                throw std::out_of_range("src_index");
            }
            if(fields_[dest_index] != in.fields_[src_index])
            {
                throw std::invalid_argument("field mismatch");
            }
#endif
            fq_nmod_set(array_ + dest_index, in.array_ + src_index, fields_[dest_index]->ctx_);
        }

        inline void set(std::size_t index, const seal::BigPoly &in)
        {
#ifndef NDEBUG
            if(index > size_)
            {
                throw std::out_of_range("index");
            }
            if(static_cast<unsigned>(in.coeff_count()) > fields_[index]->d_)
            {
                throw std::invalid_argument("input too large");
            }
#endif
            bigpoly_to_nmod_poly(in, array_ + index);
        }

        inline void set(std::size_t index, std::string in)
        {
            set(index, seal::BigPoly(in));
        }

        inline _ffield_elt_coeff_t get_coeff_of(std::size_t array_index, std::size_t elt_index) const
        {
            return nmod_poly_get_coeff_ui(array_ + array_index, elt_index);
        }

        inline void set_coeff_of(std::size_t array_index, std::size_t elt_index, _ffield_elt_coeff_t in) 
        {
#ifndef NDEBUG
            if(array_index > size_)
            {
                throw std::out_of_range("array_index");
            }
            if(elt_index >= fields_[array_index]->d_)
            {
                throw std::out_of_range("elt_index");
            }
#endif
            nmod_poly_set_coeff_ui(array_ + array_index, elt_index, in);
        }

        inline void set_zero()
        {
            for(std::size_t i = 0; i < size_; i++)
            {
                fq_nmod_zero(array_ + i, fields_[i]->ctx_);
            }
        }

        inline void set_zero(std::size_t index)
        {
#ifndef NDEBUG
            if(index > size_)
            {
                throw std::out_of_range("index");
            }
#endif
            fq_nmod_zero(array_ + index, fields_[index]->ctx_);
        }

        inline void set_random(oc::PRNG &prng)
        {
            for(std::size_t index = 0; index < size_; index++)
            {
                auto field_degree = fields_[index]->d_;
                for(unsigned i = 0; i < field_degree; i++)
                {
                    nmod_poly_set_coeff_ui(array_ + index, i, prng.get<mp_limb_t>()); 
                }
            }
        }

        inline void set_random_nonzero(oc::PRNG &prng)
        {
            for(std::size_t index = 0; index < size_; index++)
            {
                auto field_degree = fields_[index]->d_;
                do
                {
                    for(unsigned i = 0; i < field_degree; i++)
                    {
                        nmod_poly_set_coeff_ui(array_ + index, i, prng.get<mp_limb_t>()); 
                    }
                } while(fq_nmod_is_zero(array_ + index, fields_[index]->ctx_));
            }
        }

        inline bool is_zero() const
        {
            for(std::size_t i = 0; i < size_; i++)
            {
                if(fq_nmod_is_zero(array_ + i, fields_[i]->ctx_))
                {
                    return false;
                }
            }
            return true;
        }

        inline bool is_zero(std::size_t index) const
        {
            return nmod_poly_is_zero(array_ + index);
        }

        inline void set(const FFieldArray &in) 
        {
#ifndef NDEBUG
            if(in.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            for(std::size_t i = 0; i < size_; i++)
            {
                if(fields_[i] != in.fields_[i])
                {
                    throw std::invalid_argument("field mismatch");
                }
            }
#endif
            for(std::size_t i = 0; i < size_; i++)
            {
                fq_nmod_set(array_ + i, in.array_ + i, fields_[i]->ctx_);
            }
        }

        inline bool equals(const FFieldArray &in) const
        {
#ifndef NDEBUG
            if(in.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            for(std::size_t i = 0; i < size_; i++)
            {
                if(fields_[i] != in.fields_[i])
                {
                    throw std::invalid_argument("field mismatch");
                }
            }
#endif
            for(std::size_t i = 0; i < size_; i++)
            {
                if(!fq_nmod_equal(array_ + i, in.array_ + i, fields_[i]->ctx_))
                {
                    return false;
                }
            }
            return true;
        }

        inline std::shared_ptr<FField> field(std::size_t index) const
        {
            return fields_[index];
        }

        inline const std::vector<std::shared_ptr<FField> > &fields() const
        {
            return fields_;
        }

        inline void add(FFieldArray &out, const FFieldArray &in) const
        {
#ifndef NDEBUG
            if(in.size_ != size_ || out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            for(std::size_t i = 0; i < size_; i++)
            {
                if(fields_[i] != in.fields_[i] || fields_[i] != out.fields_[i])
                {
                    throw std::invalid_argument("field mismatch");
                }
            }
#endif
            for(std::size_t i = 0; i < size_; i++)
            {
                fq_nmod_add(out.array_ + i, array_ + i, in.array_ + i, fields_[i]->ctx_);
            }
        }

        inline void sub(FFieldArray &out, const FFieldArray &in) const
        {
#ifndef NDEBUG
            if(in.size_ != size_ || out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            for(std::size_t i = 0; i < size_; i++)
            {
                if(fields_[i] != in.fields_[i] || fields_[i] != out.fields_[i])
                {
                    throw std::invalid_argument("field mismatch");
                }
            }
#endif
            for(std::size_t i = 0; i < size_; i++)
            {
                fq_nmod_sub(out.array_ + i, array_ + i, in.array_ + i, fields_[i]->ctx_);
            }
        }

        inline void mul(FFieldArray &out, const FFieldArray &in) const
        {
#ifndef NDEBUG
            if(in.size_ != size_ || out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            for(std::size_t i = 0; i < size_; i++)
            {
                if(fields_[i] != in.fields_[i] || fields_[i] != out.fields_[i])
                {
                    throw std::invalid_argument("field mismatch");
                }
            }
#endif
            for(std::size_t i = 0; i < size_; i++)
            {
                fq_nmod_mul(out.array_ + i, array_ + i, in.array_ + i, fields_[i]->ctx_);
            }
        }

        inline void div(FFieldArray &out, const FFieldArray &in) const
        {
#ifndef NDEBUG
            if(in.size_ != size_ || out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            for(std::size_t i = 0; i < size_; i++)
            {
                if(fields_[i] != in.fields_[i] || fields_[i] != out.fields_[i])
                {
                    throw std::invalid_argument("field mismatch");
                }
            }
#endif
            for(std::size_t i = 0; i < size_; i++)
            {
                fq_nmod_div(out.array_ + i, array_ + i, in.array_ + i, fields_[i]->ctx_);
            }
        }

        inline void inv(FFieldArray &out) const
        {
#ifndef NDEBUG
            if(out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            for(std::size_t i = 0; i < size_; i++)
            {
                if(fields_[i] != out.fields_[i])
                {
                    throw std::invalid_argument("field mismatch");
                }
            }
#endif
            for(std::size_t i = 0; i < size_; i++)
            {
                fq_nmod_inv(out.array_ + i, array_ + i, fields_[i]->ctx_);
            }
        }

        inline void inv()
        {
            for(std::size_t i = 0; i < size_; i++)
            {
                fq_nmod_inv(array_ + i, array_ + i, fields_[i]->ctx_);
            }
        }

        inline void neg(FFieldArray &out) const
        {
#ifndef NDEBUG
            if(out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            for(std::size_t i = 0; i < size_; i++)
            {
                if(fields_[i] != out.fields_[i])
                {
                    throw std::invalid_argument("field mismatch");
                }
            }
#endif
            for(std::size_t i = 0; i < size_; i++)
            {
                fq_nmod_neg(out.array_ + i, array_ + i, fields_[i]->ctx_);
            }
        }
        
        inline void neg()
        {
            for(std::size_t i = 0; i < size_; i++)
            {
                fq_nmod_neg(array_ + i, array_ + i, fields_[i]->ctx_);
            }
        }

        inline void sq(FFieldArray &out) const
        {
#ifndef NDEBUG
            if(out.size_ != size_)
            {
                throw std::out_of_range("size mismatch");
            }
            for(std::size_t i = 0; i < size_; i++)
            {
                if(fields_[i] != out.fields_[i])
                {
                    throw std::invalid_argument("field mismatch");
                }
            }
#endif
            for(std::size_t i = 0; i < size_; i++)
            {
                fq_nmod_sqr(out.array_ + i, array_ + i, fields_[i]->ctx_);
            }
        }

        inline void sq() 
        {
            for(std::size_t i = 0; i < size_; i++)
            {
                fq_nmod_sqr(array_ + i, array_ + i, fields_[i]->ctx_);
            }
        }

        inline FFieldArray operator +(const FFieldArray &in) const
        {
            FFieldArray result(fields_);
            add(result, in);
            return result;
        }

        inline FFieldArray operator -(const FFieldArray &in) const
        {
            FFieldArray result(fields_);
            sub(result, in);
            return result;
        }

        inline FFieldArray operator *(const FFieldArray &in) const
        {
            FFieldArray result(fields_);
            mul(result, in);
            return result;
        }

        inline FFieldArray operator /(const FFieldArray &in) const
        {
            FFieldArray result(fields_);
            div(result, in);
            return result;
        }

        inline FFieldArray operator -() const
        {
            FFieldArray result(fields_);
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

        inline _ffield_array_elt_t *data()
        {
            return array_;
        }

        inline const _ffield_array_elt_t *data() const
        {
            return array_;
        }

    private:
        std::size_t size_;
        std::vector<std::shared_ptr<FField> > fields_;
        _ffield_array_t array_;
    };
}
