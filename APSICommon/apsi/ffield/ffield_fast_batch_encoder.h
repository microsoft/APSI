#pragma once

// STD
#include <memory>
#include <vector>

// APSI 
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_elt.h"
#include "apsi/ffield/ffield_array.h"

// SEAL
#include "seal/plaintext.h"

namespace apsi
{
    class FFieldFastBatchEncoder
    {
    public:
        FFieldFastBatchEncoder(std::uint64_t ch, std::uint64_t d, unsigned log_n);

        ~FFieldFastBatchEncoder();

        inline std::uint64_t ch() const
        {
            return ch_;
        }

        inline std::uint64_t d() const
        {
            return d_;
        }

        inline std::uint64_t n() const
        {
            return n_;
        }

        inline std::uint64_t m() const
        {
            return m_;
        }

        inline unsigned log_n() const
        {
            return log_n_;
        }

        inline std::uint64_t slot_count() const
        {
            return slot_count_;
        }

        inline std::shared_ptr<FField> field(std::size_t index) const
        {
            return fields_[index];
        }

        inline const std::vector<std::shared_ptr<FField> > &fields() const
        {
            return fields_;
        }

        inline FFieldArray create_array() const
        {
            return FFieldArray(fields_);
        }

        void compose(const FFieldArray &values, seal::Plaintext &destination) const;
        void decompose(const seal::Plaintext &plain, FFieldArray &destination) const;

    private:
        void build_modulus_tree();
        void interpolate(nmod_poly_struct *result_tree) const;
        void reduce(nmod_poly_struct *result_tree, nmod_poly_struct *destination) const;

        const std::uint64_t ch_;
        const std::uint64_t d_;
        const unsigned log_n_;
        const std::uint64_t n_;
        const std::uint64_t m_;
        const std::uint64_t slot_count_;
        _ffield_poly_factor_t factorization_;
        std::vector<std::shared_ptr<FField> > fields_;
        nmod_poly_struct *inv_punct_prod_;
        nmod_poly_struct *modulus_tree_;
    };
}
