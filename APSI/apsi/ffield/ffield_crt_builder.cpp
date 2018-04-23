#include "apsi/ffield/ffield_crt_builder.h"
#include "seal/util/common.h"

using namespace std;
using namespace oc;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    FFieldCRTBuilder::FFieldCRTBuilder(shared_ptr<FField> field, unsigned log_degree, oc::PRNG &prng) :
        field_(move(field)),
        ntt_ctx_(field_, log_degree, prng)
    {
        compute_cosets();
    }

    FFieldCRTBuilder::FFieldCRTBuilder(shared_ptr<FField> field, unsigned log_degree, FFieldElt zeta) :
        field_(move(field)),
        ntt_ctx_(field_, log_degree, zeta)
    {
        compute_cosets();
    }

    void FFieldCRTBuilder::bit_reversal_permutation(FFieldArray &input) const
    {
        for(uint32_t i = 0; i < ntt_ctx_.n_; i++)
        {
            uint32_t reversed_i = reverse_bits(i, ntt_ctx_.log_n_);
            if(i < reversed_i)
            {
                fq_nmod_swap(input.array_ + i, input.array_ + reversed_i, field_->ctx_);
            }
        }
    }

    void FFieldCRTBuilder::compute_cosets()
    {
        index_map_.clear();
        cosets_.resize(ntt_ctx_.n_);
        for(uint64_t i = 0; i < ntt_ctx_.n_; i++)
        {
            cosets_[i].odd = 2 * i + 1;
            cosets_[i].rep = 2 * i + 1;
            cosets_[i].hop = 0;
        }

        uint64_t reduced_ch = field_->ch() % ntt_ctx_.m_;
        uint64_t index = 0;
        for(size_t i = 0; i < ntt_ctx_.n_; i++)
        {
            if(cosets_[i].rep < 2 * i + 1)
            {
                continue;
            }

            index_map_[2 * i + 1] = index++;
            uint64_t k = (((reduced_ch * (2 * i + 1)) % ntt_ctx_.m_) - 1) / 2;
            uint64_t hop = 1;
            while(cosets_[k].rep != 2 * i + 1) 
            {
                cosets_[k].rep = 2 * i + 1;
                cosets_[k].hop = hop;
                k = (((reduced_ch * (2 * k + 1)) % ntt_ctx_.m_) - 1) / 2;
                hop++;
            }
        }
    }

    void FFieldCRTBuilder::expand(FFieldArray &out, const FFieldArray &in) const
    {
        // Manually inlining Frobenius for better performance
        FFieldElt temp(field_);
        for(uint64_t i = 0; i < ntt_ctx_.n_; i++)
        {
            uint64_t reduced_pow = cosets_[i].rep;
            uint64_t frob_index = cosets_[i].hop;

            // Out element
            auto out_elt_ptr = out.array_ + i;
            fq_nmod_zero(out_elt_ptr, field_->ctx_);

            // In element
            auto in_elt_ptr = in.array_ + index_map_.at(reduced_pow);
            auto in_elt_length = in_elt_ptr->length;

            // Apply Frobenius and write to out_elt_ptr
            for(unsigned j = 0; j < in_elt_length; j++)
            {
                fq_nmod_mul_ui(temp.elt_, &field_->frob_table_(frob_index, j), in_elt_ptr->coeffs[j], field_->ctx_);
                fq_nmod_add(out_elt_ptr, out_elt_ptr, temp.elt_, field_->ctx_);
            }
        }
    }

    void FFieldCRTBuilder::expand(FFieldArray &out, const FFieldPoly &in) const
    {
        // Manually inlining Frobenius for better performance
        FFieldElt temp(field_);
        for(uint64_t i = 0; i < ntt_ctx_.n_; i++)
        {
            uint64_t reduced_pow = cosets_[i].rep;
            uint64_t frob_index = cosets_[i].hop;

            // Out element
            auto out_elt_ptr = out.array_ + i;
            fq_nmod_zero(out_elt_ptr, field_->ctx_);

            // In element
            auto in_elt_ptr = in.poly_->coeffs + index_map_.at(reduced_pow);
            auto in_elt_length = in_elt_ptr->length;

            // Apply Frobenius and write to out_elt_ptr
            for(unsigned j = 0; j < in_elt_length; j++)
            {
                fq_nmod_mul_ui(temp.elt_, &field_->frob_table_(frob_index, j), nmod_poly_get_coeff_ui(in_elt_ptr, j), field_->ctx_);
                fq_nmod_add(out_elt_ptr, out_elt_ptr, temp.elt_, field_->ctx_);
            }
        }
    }

    void FFieldCRTBuilder::contract(FFieldArray &out, const FFieldArray &in) const
    {
        for(uint64_t i = 0; i < ntt_ctx_.n_; i++)
        {
            if(cosets_[i].rep == (2 * i + 1))
            {
                fq_nmod_set(out.array_ + index_map_.at(2 * i + 1), in.array_ + i, field_->ctx_);
            }
        }
    }

    void FFieldCRTBuilder::contract(FFieldPoly &out, const FFieldArray &in) const
    {
        out.set_zero();
        for(uint64_t i = 0; i < ntt_ctx_.n_; i++)
        {
            if(cosets_[i].rep == (2 * i + 1))
            {
                fq_nmod_poly_set_coeff(out.poly_, index_map_.at(2 * i + 1), in.array_ + i, field_->ctx_);
            }
        }
    }

    void FFieldCRTBuilder::compose(Plaintext &destination, const FFieldArray &values) const
    {
        if(values.size_ != ntt_ctx_.slot_count_)
        {
            throw invalid_argument("invalid array size");
        }

        FFieldArray expanded(field_, ntt_ctx_.n_);
        expand(expanded, values);
        bit_reversal_permutation(expanded);
        ntt_ctx_.inverse_negacyclic_ntt(expanded);
        
        // Copy result to destination
        destination.resize(ntt_ctx_.n_);
        auto destination_ptr = destination.pointer();
        for(uint64_t i = 0; i < ntt_ctx_.n_; i++, destination_ptr++)
        {
            // We are guaranteed that every array element is in base field
            *destination_ptr = nmod_poly_get_coeff_ui(expanded.array_ + i, 0);
        }
    }

    void FFieldCRTBuilder::compose(seal::Plaintext &destination, const FFieldPoly &values) const
    {
        if(values.length() > ntt_ctx_.slot_count())
        {
            throw invalid_argument("invalid array size");
        }

        FFieldArray expanded(field_, ntt_ctx_.n_);
        expand(expanded, values);
        bit_reversal_permutation(expanded);
        ntt_ctx_.inverse_negacyclic_ntt(expanded);
        
        // Copy result to destination
        destination.resize(ntt_ctx_.n_);
        auto destination_ptr = destination.pointer();
        for(uint64_t i = 0; i < ntt_ctx_.n_; i++, destination_ptr++)
        {
            // We are guaranteed that every array element is in base field
            *destination_ptr = nmod_poly_get_coeff_ui(expanded.array_ + i, 0);
        }
    }

    void FFieldCRTBuilder::decompose(FFieldArray &destination, const Plaintext &plain) const
    {
        if (destination.size_ != ntt_ctx_.slot_count_)
        {
            throw invalid_argument("invalid array size");
        }
        uint64_t plain_coeff_count = plain.coeff_count();
        uint64_t max_coeff_count = ntt_ctx_.n_ + 1;
        if (plain_coeff_count > max_coeff_count || (plain_coeff_count == max_coeff_count && (plain[ntt_ctx_.n_] != 0)))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
#ifndef NDEBUG
        auto c = field_->ch();
        if (plain.significant_coeff_count() >= max_coeff_count || !are_poly_coefficients_less_than(plain.pointer(),
            plain_coeff_count, 1, &c, 1))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
#endif
        FFieldArray expanded(field_, ntt_ctx_.n_);
        auto plain_ptr = plain.pointer();
        for (uint64_t i = 0; i < plain_coeff_count; i++, plain_ptr++)
        {
            fq_nmod_set_ui(expanded.array_ + i, *plain_ptr, field_->ctx_);
        }
        for (uint64_t i = plain_coeff_count; i < ntt_ctx_.n_; i++)
        {
            fq_nmod_zero(expanded.array_ + i, field_->ctx_);
        }
        ntt_ctx_.negacyclic_ntt(expanded);
        bit_reversal_permutation(expanded);
        contract(destination, expanded);
    }

    void FFieldCRTBuilder::decompose(FFieldPoly &destination, const seal::Plaintext &plain) const
    {
        uint64_t plain_coeff_count = plain.coeff_count();
        if(plain_coeff_count != ntt_ctx_.n_)
        {
            throw invalid_argument("plain has unexpected coefficient count");
        }

        FFieldArray expanded(field_, ntt_ctx_.n_);
        auto plain_ptr = plain.pointer();
        for(uint64_t i = 0; i < ntt_ctx_.n_; i++, plain_ptr++)
        {
            fq_nmod_set_ui(expanded.array_ + i, *plain_ptr, field_->ctx_);
        }
        ntt_ctx_.negacyclic_ntt(expanded);
        bit_reversal_permutation(expanded);
        contract(destination, expanded);
    }
}
