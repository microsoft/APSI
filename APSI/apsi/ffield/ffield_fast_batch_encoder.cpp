#include "apsi/ffield/ffield_fast_batch_encoder.h"
#include "seal/util/common.h"
#include <iostream>

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace gsl;

namespace apsi
{
    FFieldFastBatchEncoder::~FFieldFastBatchEncoder()
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
    }

    FFieldFastBatchEncoder::FFieldFastBatchEncoder(std::uint64_t ch, std::uint64_t d, unsigned log_n) :
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
        build_modulus_tree();

        // Clear locals
        fmpz_clear(mult_grp_size);
        nmod_poly_clear(cyclotomic_poly);
    }

    void FFieldFastBatchEncoder::build_modulus_tree()
    {
        for(uint64_t node = 2 * slot_count_ - 2; node >= slot_count_ - 1; node--)
        {
            // Is this a leaf node?
            nmod_poly_set(modulus_tree_ + node, factorization_->p + node - slot_count_ + 1);
        }

        for(int64_t node = slot_count_ - 2; node >= 0; node--)
        {
            auto child1 = 2 * node + 1;
            auto child2 = 2 * node + 2;
            nmod_poly_mul(modulus_tree_ + node, modulus_tree_ + child1, modulus_tree_ + child2);
        }
    }

    void FFieldFastBatchEncoder::interpolate(nmod_poly_struct *result_tree) const
    {
        // Initialize temp_poly
        nmod_poly_t temp_poly;
        nmod_poly_init(temp_poly, ch_);

        for(int64_t node = slot_count_ - 2; node >= 0; node--)
        {
            auto child1 = 2 * node + 1;
            auto child2 = 2 * node + 2;

            nmod_poly_mul(temp_poly, result_tree + child1, modulus_tree_ + child2);
            nmod_poly_mul(result_tree + node, result_tree + child2, modulus_tree_ + child1);
            nmod_poly_add(result_tree + node, result_tree + node, temp_poly);
        }

        // Reduce mod x^n + 1
        nmod_poly_rem(result_tree, result_tree, modulus_tree_);
    }

    void FFieldFastBatchEncoder::reduce(nmod_poly_struct *result_tree, nmod_poly_struct *destination) const
    {
        for(uint64_t node = 0; node < slot_count_ - 1; node++)
        {
            auto child1 = 2 * node + 1;
            auto child2 = 2 * node + 2;

            // Compute reductions down the tree
            nmod_poly_rem(result_tree + child1, result_tree + node, modulus_tree_ + child1);
            nmod_poly_rem(result_tree + child2, result_tree + node, modulus_tree_ + child2);
        }

        for(uint64_t node = slot_count_ - 1; node < 2 * slot_count_ - 1; node++)
        {
            // Do nothing for leaf nodes; they are already there.
            nmod_poly_set(destination + (node - slot_count_ + 1), result_tree + node);
        }
    }

    void FFieldFastBatchEncoder::compose(const FFieldArray &values, Plaintext &destination) const
    {
        if(values.size() != slot_count_)
        {
            throw invalid_argument("values has incorrect size");
        }
#ifndef NDEBUG
        // Test that fields are all matching
        for(uint64_t i = 0; i < slot_count_; i++)
        {
            if(values.fields_[i] != fields_[i])
            {
                throw invalid_argument("field mismatch");
            }
        }
#endif
        // Initialize result_tree
        auto result_tree = new nmod_poly_struct[2 * slot_count_ - 1];
        for(uint64_t i = 0; i < 2 * slot_count_ - 1; i++)
        {
            nmod_poly_init(result_tree + i, ch_);
        }

        auto result_tree_ptr = result_tree + slot_count_ -  1;
        auto values_ptr = values.data();
        auto inv_punct_prod_ptr = inv_punct_prod_;
        for(uint64_t i = 0; i < slot_count_; i++, result_tree_ptr++, values_ptr++, inv_punct_prod_ptr++)
        {
            nmod_poly_mul(result_tree_ptr, values_ptr, inv_punct_prod_ptr);
        }
        interpolate(result_tree);

        // Copy result to destination
        uint64_t coeff_count = result_tree[0].length;
        destination.resize(static_cast<Plaintext::size_type>(coeff_count));
        memcpy(destination.data(), result_tree->coeffs, 8 * coeff_count);

        // Clear result_tree
        for(uint64_t i = 0; i < 2 * slot_count_ - 1; i++)
        {
            nmod_poly_clear(result_tree + i);
        }
        delete[] result_tree;
    }

    void FFieldFastBatchEncoder::decompose(const Plaintext &plain, FFieldArray &destination) const
    {
        if(destination.size() != slot_count_)
        {
            throw invalid_argument("destination has incorrect size");
        }
#ifndef NDEBUG
        // Test that fields are all matching
        for(uint64_t i = 0; i < slot_count_; i++)
        {
            if(destination.fields_[i] != fields_[i])
            {
                throw invalid_argument("field mismatch");
            }
        }
#endif
        uint64_t plain_coeff_count = plain.coeff_count();
        uint64_t max_coeff_count = n_ + 1;
        if (plain_coeff_count > max_coeff_count || (plain_coeff_count == max_coeff_count && (plain[static_cast<Plaintext::size_type>(n_)] != 0)))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
#ifndef NDEBUG
        if (static_cast<uint64_t>(plain.significant_coeff_count()) >= max_coeff_count || !are_poly_coefficients_less_than(plain.data(),
            static_cast<int>(plain_coeff_count), 1, &ch_, 1))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
#endif
        // Initialize result_tree
        auto result_tree = new nmod_poly_struct[2 * slot_count_ - 1];
        for(uint64_t i = 0; i < 2 * slot_count_ - 1; i++)
        {
            nmod_poly_init(result_tree + i, ch_);
        }

        // First copy over input to result_tree[0]
        nmod_poly_realloc(result_tree, plain_coeff_count);
        auto plain_ptr = plain.data();
        for(uint64_t i = 0; i < plain_coeff_count; i++, plain_ptr++)
        {
            nmod_poly_set_coeff_ui(result_tree, i, *plain_ptr);
        }

        // Now reduce
        reduce(result_tree, destination.array_);

        // Clear result_tree
        for(uint64_t i = 0; i < 2 * slot_count_ - 1; i++)
        {
            nmod_poly_clear(result_tree + i);
        }
        delete[] result_tree;
    }
}
