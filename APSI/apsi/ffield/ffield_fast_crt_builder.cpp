#include "apsi/ffield/ffield_fast_crt_builder.h"
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace gsl;

namespace apsi
{
    FFieldFastCRTBuilder::~FFieldFastCRTBuilder()
    {
        nmod_poly_factor_clear(factorization_);

        // Clear punctured_products_
        for(uint64_t i = 0; i < slot_count_; i++)
        {
            nmod_poly_clear(inv_punct_prod_ + i);
        }
        delete[] inv_punct_prod_;
        
        // Clear modulus_tree_
        for(uint64_t i = 0; i < 2 * slot_count_ - 1; i++)
        {
            nmod_poly_clear(modulus_tree_ + i);
        }
        delete[] modulus_tree_;

        // Clear result_tree_
        for(uint64_t i = 0; i < 2 * slot_count_ - 1; i++)
        {
            nmod_poly_clear(result_tree_ + i);
        }
        delete[] result_tree_;

        // Clear temp_poly_
        nmod_poly_clear(temp_poly_);
    }

    FFieldFastCRTBuilder::FFieldFastCRTBuilder(std::uint64_t ch, std::uint64_t d, unsigned log_n) :
        ch_(ch),
        d_(d),
        log_n_(log_n),
        n_(1ULL << log_n),
        m_(2 * n_),
        slot_count_(n_ / d_)
    {
        // Check that degree of extension field is a power of 2 and divides n_
        if(n_ % d_)
        {
            throw invalid_argument("invalid field extension degree");
        } 

        // Check that an appropriate multiplicative subgroup exists in the 
        // extension field
        fmpz_t mult_grp_size;
        fmpz_init_set_ui(mult_grp_size, ch_);
        fmpz_pow_ui(mult_grp_size, mult_grp_size, d_);
        fmpz_sub_ui(mult_grp_size, mult_grp_size, 1);
        if(!fmpz_divisible_si(mult_grp_size, m_))
        {
            throw invalid_argument("no appropriate root of unity in field");
        }

        // Create x^n + 1
        nmod_poly_t cyclotomic_poly;
        nmod_poly_init(cyclotomic_poly, ch_);
        nmod_poly_set_coeff_ui(cyclotomic_poly, 0, 1);
        nmod_poly_set_coeff_ui(cyclotomic_poly, n_, 1);

        // Create factorization
        nmod_poly_factor_init(factorization_);
        nmod_poly_factor_equal_deg(factorization_, cyclotomic_poly, d_);

        // Create extension fields
        fields_.clear();
        for(uint64_t i = 0; i < slot_count_; i++)
        {
            fields_.emplace_back(FField::Acquire(ch_, factorization_->p + i));
        }

        // Compute punctured products of field polynomials
        inv_punct_prod_ = new nmod_poly_struct[slot_count_];
        for(uint64_t i = 0; i < slot_count_; i++)
        {
            nmod_poly_init2(inv_punct_prod_ + i, ch_, n_); 
        }
        for(uint64_t i = 0; i < slot_count_; i++)
        {
            nmod_poly_div(inv_punct_prod_ + i, cyclotomic_poly, factorization_->p + i);
            nmod_poly_invmod(inv_punct_prod_ + i, inv_punct_prod_ + i, factorization_->p + i);
        }

        // Compute modulus_tree_
        modulus_tree_ = new nmod_poly_struct[2 * slot_count_ - 1];
        for(uint64_t i = 0; i < 2 * slot_count_ - 1; i++)
        {
            nmod_poly_init(modulus_tree_ + i, ch_);
        }
        build_modulus_tree(0);

        // Initialize result_tree_
        result_tree_ = new nmod_poly_struct[2 * slot_count_ - 1];
        for(uint64_t i = 0; i < 2 * slot_count_ - 1; i++)
        {
            nmod_poly_init(result_tree_ + i, ch_);
        }

        // Initialize temp_poly_
        nmod_poly_init(temp_poly_, ch_);

        // Clear locals
        fmpz_clear(mult_grp_size);
        nmod_poly_clear(cyclotomic_poly);
    }

    void FFieldFastCRTBuilder::build_modulus_tree(uint64_t node)
    {
        // Is this a leaf node?
        if(node >= slot_count_ - 1)
        {
            nmod_poly_set(modulus_tree_ + node, factorization_->p + node - slot_count_ + 1);
        }
        else
        {
            auto child1 = 2 * node + 1;
            auto child2 = 2 * node + 2;
            build_modulus_tree(child1);
            build_modulus_tree(child2);
            nmod_poly_mul(modulus_tree_ + node, modulus_tree_ + child1, modulus_tree_ + child2);
        }
    }

    void FFieldFastCRTBuilder::interpolate(uint64_t node)
    {
        // Do nothing for leaf nodes; they are already there.
        if(node >= slot_count_ - 1)
        {
            return;
        }
        else
        {
            auto child1 = 2 * node + 1;
            auto child2 = 2 * node + 2;
            interpolate(child1);
            interpolate(child2);
            nmod_poly_mul(temp_poly_, result_tree_ + child1, modulus_tree_ + child2);
            nmod_poly_mul(result_tree_ + node, result_tree_ + child2, modulus_tree_ + child1);
            nmod_poly_add(result_tree_ + node, result_tree_ + node, temp_poly_);
        }
    }

    void FFieldFastCRTBuilder::compose(Plaintext &destination, span<const FFieldElt> values)
    {
        if(values.size() != slot_count_)
        {
            throw invalid_argument("values has incorrect size");
        }
#ifndef NDEBUG
        // Test that fields are all matching
        for(uint64_t i = 0; i < slot_count_; i++)
        {
            if(values[i].field_ != fields_[i])
            {
                throw invalid_argument("field mismatch");
            }
        }
#endif
        auto result_tree_ptr = result_tree_ + slot_count_ -  1;
        auto values_ptr = values.data();
        auto inv_punct_prod_ptr = inv_punct_prod_;
        for(uint64_t i = 0; i < slot_count_; i++, result_tree_ptr++, values_ptr++, inv_punct_prod_ptr++)
        {
            nmod_poly_mul(result_tree_ptr, values_ptr->elt_, inv_punct_prod_ptr);
        }
        interpolate(0);

        // Copy result to destination
        uint64_t coeff_count = result_tree_[0].length;
        destination.resize(coeff_count);
        memcpy(destination.pointer(), result_tree_->coeffs, 8 * coeff_count);
    }

    void FFieldFastCRTBuilder::decompose(span<FFieldElt> destination, const Plaintext &plain) const
    {
        if(destination.size() != slot_count_)
        {
            throw invalid_argument("destination has incorrect size");
        }
#ifndef NDEBUG
        // Test that fields are all matching
        for(uint64_t i = 0; i < slot_count_; i++)
        {
            if(destination[i].field_ != fields_[i])
            {
                throw invalid_argument("field mismatch");
            }
        }
#endif
        uint64_t plain_coeff_count = plain.coeff_count();
        uint64_t max_coeff_count = n_ + 1;
        if (plain_coeff_count > max_coeff_count || (plain_coeff_count == max_coeff_count && (plain[n_] != 0)))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
#ifndef NDEBUG
        if (static_cast<uint64_t>(plain.significant_coeff_count()) >= max_coeff_count || !are_poly_coefficients_less_than(plain.pointer(),
            plain_coeff_count, 1, &ch_, 1))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
#endif
        // First copy over input to result_tree_[0]
        auto plain_ptr = plain.pointer();
        for(uint64_t i = 0; i < plain_coeff_count; i++, plain_ptr++)
        {
            nmod_poly_set_coeff_ui(result_tree_, i, *plain_ptr);
        }

        // Then reduce modulo different factors
        auto destination_ptr = destination.data();
        auto modulus_poly_ptr = factorization_->p;
        for(uint64_t i = 0; i < slot_count_; i++, destination_ptr++, modulus_poly_ptr++)
        {
            nmod_poly_rem(destination_ptr->elt_, result_tree_, modulus_poly_ptr);
        }
    }
}
