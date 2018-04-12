#include "apsi/ffield/ffield_ntt.h"
#include "seal/util/common.h"
#include "seal/util/numth.h"

using namespace std;
using namespace oc;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    FFieldNTT::FFieldNTT(shared_ptr<FField> field, unsigned log_degree, PRNG &prng) :
        field_(move(field)),
        zeta_(field_),
        log_n_(log_degree),
        n_(1ULL << log_degree),
        m_(2 * n_),
        zeta_powers_(field_, n_),
        inv_zeta_powers_(field_, n_),
        reversed_idx_(n_)
    {
        // Check that degree of extension field is a power of 2 and divides n_
        if(n_ % field_->d_)
        {
            throw invalid_argument("invalid field extension degree");
        } 
        slot_count_ = n_ / field_->d_;

        // Check that multiplicative group of field_ contains appropriate subgroup
        fmpz_t mult_grp_size;
        fmpz_init(mult_grp_size);
        fq_nmod_ctx_order(mult_grp_size, field_->ctx_);
        fmpz_sub_ui(mult_grp_size, mult_grp_size, 1);
        if(!fmpz_divisible_si(mult_grp_size, m_))
        {
            throw invalid_argument("no appropriate root of unity in field");
        }
        
        // Compute quotient group size
        fmpz_t quotient_size;
        fmpz_init(quotient_size);
        fmpz_divexact_ui(quotient_size, mult_grp_size, m_);

        // Find a primitive m_-th root of unity zeta_
        uint32_t fail_ctr = 0;
        while(!is_primitive_root(zeta_) && fail_ctr++ < 100)
        {
            // Set zeta to random
            zeta_.set_random_nonzero(prng);

            // Exponentiate away the quotient group
            zeta_.pow(zeta_, quotient_size);
        }

        // First need to compute the reverse index array
        populate_reverse_idx_array();

        // Now populate the zeta powers array
        populate_zeta_powers(zeta_, zeta_powers_);

        // Next the inverse powers 
        populate_zeta_powers(inv_primitive_root(zeta_), inv_zeta_powers_);

        // Compute the inverse of n_
        if(!try_mod_inverse(n_, field_->ch(), inv_n_)) 
        {
            throw invalid_argument("unsuitable characteristic");
        }

        // Clean up locals
        fmpz_clear(mult_grp_size);
        fmpz_clear(quotient_size);
    }

    FFieldNTT::FFieldNTT(shared_ptr<FField> field, unsigned log_degree, FFieldElt zeta) :
        field_(move(field)),
        zeta_(zeta),
        log_n_(log_degree),
        n_(1ULL << log_degree),
        m_(2 * n_),
        zeta_powers_(field_, n_),
        inv_zeta_powers_(field_, n_), 
        reversed_idx_(n_)
    {
        // Check that degree of extension field is a power of 2 and divides n_
        if(n_ % field_->d_)
        {
            throw invalid_argument("invalid field extension degree");
        } 
        slot_count_ = n_ / field_->d_;

        // Check that multiplicative group of field_ contains appropriate subgroup
        fmpz_t mult_grp_size;
        fmpz_init(mult_grp_size);
        fq_nmod_ctx_order(mult_grp_size, field_->ctx_);
        fmpz_sub_ui(mult_grp_size, mult_grp_size, 1);
        if(!fmpz_divisible_si(mult_grp_size, m_))
        {
            throw invalid_argument("no appropriate root of unity in field");
        }
        
        // Find a primitive m_-th root of unity zeta_
        if(!is_primitive_root(zeta_))
        {
            throw invalid_argument("invalid primitive root");
        }

        // First need to compute the reverse index array
        populate_reverse_idx_array();

        // Now populate the zeta powers array
        populate_zeta_powers(zeta_, zeta_powers_);

        // Next the inverse powers 
        populate_zeta_powers(inv_primitive_root(zeta_), inv_zeta_powers_);

        // Compute the inverse of n_
        if(!try_mod_inverse(n_, field_->ch(), inv_n_)) 
        {
            throw invalid_argument("unsuitable characteristic");
        }

        // Clean up locals
        fmpz_clear(mult_grp_size);
    }

    void FFieldNTT::populate_reverse_idx_array()
    {
        reversed_idx_[0] = 0;
        for(uint32_t i = 1; i < n_; i++)
        {
            reversed_idx_[i] = reverse_bits(i, log_n_);
        }
    }

    bool FFieldNTT::is_primitive_root(FFieldElt zeta) const
    {
        FFieldElt one(field_);
        one.set_one();
        zeta ^= (n_ / 2);
        return !(zeta + one).is_zero() && ((zeta^2) + one).is_zero();
    }

    void FFieldNTT::populate_zeta_powers(const FFieldElt &zeta, FFieldArray &zeta_powers)
    {
        // Populate zeta_powers with primitive roots
        fq_nmod_one(zeta_powers.array_, field_->ctx_);
        for(uint64_t i = 1; i < n_; i++)
        {
            zeta_powers.set(i, zeta^reversed_idx_[i]);
        }
    }

    void FFieldNTT::negacyclic_ntt(FFieldArray &sequence) const
    {
        if(sequence.size_ != n_)
        {
            throw invalid_argument("invalid array size");
        }

        uint64_t t = n_;
        FFieldElt temp(field_);
        
        for(uint64_t m = 1; m < n_; m <<= 1)
        {
            t >>= 1;
            for(uint64_t i = 0; i < m; i++)
            {
                uint64_t j1 = 2 * i * t;
                uint64_t j2 = j1 + t - 1;
                auto S_ptr = zeta_powers_.array_ + m + i;
                for(uint64_t j = j1; j <= j2; j++)
                {
                    // U = sequence[j]
                    // V = sequence[j + t] * S
                    // sequence[j] = U + V
                    // sequence[j + t] = U - V
                    fq_nmod_mul(temp.elt_, S_ptr, sequence.array_ + j + t, field_->ctx_);
                    fq_nmod_sub(sequence.array_ + j + t, sequence.array_ + j, temp.elt_, field_->ctx_);
                    fq_nmod_add(sequence.array_ + j, sequence.array_ + j, temp.elt_, field_->ctx_);
                }
            }
        }
    } 

    void FFieldNTT::inverse_negacyclic_ntt(FFieldArray &sequence) const
    {
        if(sequence.size_ != n_)
        {
            throw invalid_argument("invalid array size");
        }

        uint64_t t = 1;
        FFieldElt temp(field_);
        
        for(uint64_t m = n_; m > 1; m >>= 1)
        {
            uint64_t j1 = 0;
            uint64_t h = m >> 1;
            for(uint64_t i = 0; i < h; i++)
            {
                uint64_t j2 = j1 + t - 1;
                auto S_ptr = inv_zeta_powers_.array_ + h + i;
                for(uint64_t j = j1; j <= j2; j++)
                {
                    // U = sequence[j]
                    // V = sequence[j + t]
                    // sequence[j] = U + V
                    // sequence[j + t] = (U - V) * S
                    fq_nmod_sub(temp.elt_, sequence.array_ + j, sequence.array_ + j + t, field_->ctx_);
                    fq_nmod_add(sequence.array_ + j, sequence.array_ + j, sequence.array_ + j + t, field_->ctx_);
                    fq_nmod_mul(sequence.array_ + j + t, S_ptr, temp.elt_, field_->ctx_);
                }
                j1 += (t << 1);
            }
            t <<= 1;
        }

        for(uint64_t j = 0; j < n_; j++)
        {
            fq_nmod_mul_ui(sequence.array_ + j, sequence.array_ + j, inv_n_, field_->ctx_);
        }
    }
}
