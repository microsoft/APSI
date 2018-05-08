#pragma once

// STD
#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>
#include <ostream>
#include <random>

// FLINT
#include "fmpz.h"
#include "fq_nmod.h"
#include "fq_nmod_vec.h"
#include "fq_nmod_poly.h"

// SEAL
#include "seal/bigpoly.h"

// CryptoTools
#include "cryptoTools/Common/MatrixView.h"

// Require mp_limb_t equal to std::uint64
static_assert(std::is_same<mp_limb_t, std::uint64_t>::value, "mp_limb_t != std::uint64_t");

namespace apsi
{
    using _ch_t = mp_limb_t;
    using _bigint_t = fmpz_t;
    using _ffield_modulus_t = nmod_poly_t;
    using _ffield_ctx_t = fq_nmod_ctx_t;
    using _ffield_elt_coeff_t = mp_limb_t; 
    using _ffield_elt_t = fq_nmod_t;
    using _ffield_elt_ptr_t = fq_nmod_struct *;
    using _ffield_elt_const_ptr_t = const fq_nmod_struct *;
    using _ffield_array_t = fq_nmod_struct *;
    using _ffield_array_const_t = const fq_nmod_struct *;
    using _ffield_array_elt_t = fq_nmod_struct;
    using _ffield_poly_t = fq_nmod_poly_t;
    using _ffield_poly_coeff_t = nmod_poly_struct;
    using _ffield_poly_array_t = fq_nmod_poly_struct *;
    using _ffield_poly_array_elt_t = fq_nmod_poly_struct;
    using _ffield_poly_factor_t = nmod_poly_factor_t;
   
    // Symbol to use in internal representation of field elements
    const char field_elt_var[]{ 'Y' };

    inline void nmod_poly_to_bigpoly(const nmod_poly_t in, seal::BigPoly &out)
    {
        out.set_zero();
        auto coeff_count = in->length;
        auto coeff_bit_count = n_sizeinbase(in->mod.n, 2);
        out.resize(coeff_count, coeff_bit_count);
        auto *poly_ptr = out.pointer();
        for(unsigned i = 0; i < coeff_count; i++, poly_ptr++)
        {
            *poly_ptr = nmod_poly_get_coeff_ui(in, i);
        }
    }

    inline void bigpoly_to_nmod_poly(const seal::BigPoly &in, nmod_poly_t out)
    {
        nmod_poly_zero(out);
        unsigned coeff_count = in.coeff_count();
        auto *poly_ptr = in.pointer();
        for(unsigned i = 0; i < coeff_count; i++, poly_ptr++)
        {
            nmod_poly_set_coeff_ui(out, i, *poly_ptr);
        }
    }

    inline void fmpz_to_biguint(const fmpz_t in, seal::BigUInt &out)
    {
        out.resize(fmpz_sizeinbase(in, 2));
        out.set_zero();
        fmpz_t in_copy;
        fmpz_init(in_copy);
        fmpz_set(in_copy, in);
        fmpz_t word_size;
        fmpz_init_set_ui(word_size, 1);
        fmpz_mul2_uiui(word_size, word_size, 1ULL << 32, 1ULL << 32);
        fmpz_t lw;
        fmpz_init(lw);
        auto out_ptr = out.pointer();
        while(!fmpz_is_zero(in_copy))
        {
            fmpz_mod(lw, in_copy, word_size);
            fmpz_sub(in_copy, in_copy, lw);
            fmpz_divexact(in_copy, in_copy, word_size);
            *out_ptr++ = fmpz_get_ui(lw);
        }
        fmpz_clear(in_copy);
        fmpz_clear(word_size);
        fmpz_clear(lw);
    }

    inline void biguint_to_fmpz(const seal::BigUInt &in, fmpz_t out)
    {
        unsigned word_count = in.uint64_count();
        if(word_count == 0)
        {
            fmpz_zero(out);
            return;
        }
        fmpz_set_ui(out, *in.pointer());
        auto *word_ptr = in.pointer() + 1;
        for(unsigned i = 1; i < word_count; i++, word_ptr++)
        {
            fmpz_mul2_uiui(out, out, 1ULL << 32, 1ULL << 32);
            fmpz_add_ui(out, out, *word_ptr);
        }
    }

    class FFieldElt;

    class FField : public std::enable_shared_from_this<FField>
    {
        friend class FFieldElt;
        friend class FFieldArray;
        friend class FFieldPoly;
        friend class FFieldCRTBuilder;
        friend class FFieldNTT;
        friend class FFieldFastCRTBuilder;

    public:
        FField(const FField &) = delete;
        FField(FField &&) = delete;

        ~FField()
        {
            if(frob_populated_)
            {
                _fq_nmod_vec_clear(frob_table_backing_, d_ * d_, ctx_);
            }

            // Last thing to clear up is the context
            fq_nmod_ctx_clear(ctx_);
        }
        
        static std::shared_ptr<FField> Acquire(std::uint64_t ch, unsigned d)
        {
            return std::shared_ptr<FField>{ new FField(ch, d) };
        }

        static std::shared_ptr<FField> Acquire(std::uint64_t ch, const _ffield_modulus_t field_poly)
        {
            return std::shared_ptr<FField>{ new FField(ch, field_poly) };
        }

        static std::shared_ptr<FField> Acquire(std::uint64_t ch, const seal::BigPoly &field_poly)
        {
            return std::shared_ptr<FField>{ new FField(ch, field_poly) };
        }

        static std::shared_ptr<FField> Acquire(std::uint64_t ch, std::string field_poly)
        {
            return std::shared_ptr<FField>{ new FField(ch, field_poly) };
        }

        inline std::uint64_t ch() const
        {
            return ch_;
        }

        inline seal::BigPoly field_poly() const
        {
            seal::BigPoly result;

            // Set the bigpoly
            nmod_poly_to_bigpoly(ctx_->modulus, result);
            return result;
        }

        inline unsigned d() const
        {
            return d_;
        }

        inline bool operator ==(const FField &compare) const
        {
            return (this == &compare) || 
                ((ch_ == compare.ch_) &&
                 nmod_poly_equal(ctx_->modulus, compare.ctx_->modulus));
        }

        inline bool operator !=(const FField &compare) const
        {
            return !operator ==(compare);
        }

        FFieldElt zero();

        FFieldElt one();

        inline _ffield_ctx_t &ctx()
        {
            return ctx_;
        }

        inline const _ffield_ctx_t &ctx() const
        {
            return ctx_;
        }

        inline bool fast_frob_enabled() const
        {
            return frob_populated_;
        }

    private:
        explicit FField(std::uint64_t ch, unsigned d); 
        explicit FField(std::uint64_t ch, const _ffield_modulus_t modulus); 
        FField(std::uint64_t ch, seal::BigPoly modulus); 
        FField(std::uint64_t ch, std::string modulus);
        
        void populate_frob_table();

        unsigned d_;
        _ch_t ch_;
        bool frob_populated_;
        _ffield_array_t frob_table_backing_;
        oc::MatrixView<_ffield_array_elt_t> frob_table_;
        _ffield_ctx_t ctx_;
    };
}
