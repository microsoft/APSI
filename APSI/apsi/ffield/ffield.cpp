#include <stdexcept>
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_elt.h"
#include "cryptoTools/Crypto/PRNG.h"

using namespace seal;
using namespace std;
using namespace oc;

namespace apsi
{
    FField::FField(uint64_t ch, unsigned d) : 
        d_(d) 
    {
        fmpz_init_set_ui(ch_, ch);
        fq_nmod_ctx_init(ctx_, ch_, d_, field_elt_var);

        // Set the bigpoly
        nmod_poly_to_bigpoly(ctx_->modulus, modulus_);

        // Pre-compute action of Frobenius on monomials for quick evaluation 
        frob_table_backing_ = _fq_nmod_vec_init(d_ * d_, ctx_);
        frob_table_ = MatrixView<_ffield_array_elt_t>(frob_table_backing_, d_, d_);
        populate_frob_table();
    }

    FField::FField(uint64_t ch, BigPoly modulus) :
        modulus_(modulus) 
    {
        // We only support word-size coefficients
        if(modulus.coeff_uint64_count() > 1)
        {
            throw invalid_argument("modulus coefficients too large"); 
        }

        // Check that we have a prime modulus
        if(!n_is_probabprime(ch))
        {
            throw invalid_argument("ch is not prime");
        }
        fmpz_init_set_ui(ch_, ch);

        // Create the modulus
        _ffield_modulus_t flint_modulus;
        nmod_poly_init(flint_modulus, ch);

        // Set the value; also checks that coeffs are not too big
        bigpoly_to_nmod_poly(modulus, flint_modulus); 
        
        // Check that modulus is monic
        if(nmod_poly_get_coeff_ui(flint_modulus, flint_modulus->length - 1) != 1ULL)
        {
            throw invalid_argument("modulus is not monic");
        }

        // Check irreducibility of modulus
        if(!nmod_poly_is_irreducible(flint_modulus))
        {
            throw invalid_argument("modulus is not irreducible");
        }
       
        // All is good so create the field context
        fq_nmod_ctx_init_modulus(ctx_, flint_modulus, field_elt_var);

        // Set the degree
        d_ = fq_nmod_ctx_degree(ctx_);

        // Pre-compute action of Frobenius on monomials for quick evaluation 
        frob_table_backing_ = _fq_nmod_vec_init(d_ * d_, ctx_);
        frob_table_ = MatrixView<_ffield_array_elt_t>(frob_table_backing_, d_, d_);
        populate_frob_table();

        // Clear up locals
        nmod_poly_clear(flint_modulus);
    }

    FField::FField(uint64_t ch, const _ffield_modulus_t modulus) 
    {
        // Check that we have a prime modulus
        if(!n_is_probabprime(ch))
        {
            throw invalid_argument("ch is not prime");
        }
        fmpz_init_set_ui(ch_, ch);
       
        // Check that modulus is monic
        if(nmod_poly_get_coeff_ui(modulus, modulus->length - 1) != 1ULL)
        {
            throw invalid_argument("modulus is not monic");
        }

        // Check irreducibility of modulus
        if(!nmod_poly_is_irreducible(modulus))
        {
            throw invalid_argument("modulus is not irreducible");
        }
       
        // All is good so create the field context
        fq_nmod_ctx_init_modulus(ctx_, modulus, field_elt_var);

        // Set the degree
        d_ = fq_nmod_ctx_degree(ctx_);

        // Pre-compute action of Frobenius on monomials for quick evaluation 
        frob_table_backing_ = _fq_nmod_vec_init(d_ * d_, ctx_);
        frob_table_ = MatrixView<_ffield_array_elt_t>(frob_table_backing_, d_, d_);
        populate_frob_table();
    }

    FField::FField(uint64_t ch, string modulus) :
        FField(ch, BigPoly(modulus))
    {
    }

    FFieldElt FField::zero()
    {
        return FFieldElt(shared_from_this());
    }

    FFieldElt FField::one()
    {
        FFieldElt one(shared_from_this());
        one.set_one();
        return one;
    }

    void FField::populate_frob_table()
    {
        _ffield_elt_t power_of_x;
        fq_nmod_init(power_of_x, ctx_);
        for(unsigned col = 0; col < d_; col++)
        {
            // Column signals power of x
            fq_nmod_zero(power_of_x, ctx_);
            nmod_poly_set_coeff_ui(power_of_x, col, 1);

            // Row signals power of Frobenius
            for(unsigned row = 0; row < d_; row++)
            {
                fq_nmod_frobenius(&frob_table_(row, col), power_of_x, row, ctx_);
            }
        }

        // Clear up locals
        fq_nmod_clear(power_of_x, ctx_);
    }
}
