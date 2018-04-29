#pragma once

// STD
#include <memory>
#include <vector>

// APSI 
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_elt.h"
#include "apsi/ffield/ffield_poly.h"

// SEAL
#include "seal/plaintext.h"

// GSL
#include <gsl/span>

namespace apsi
{
    class FFieldFastCRTBuilder
    {
    public:
        FFieldFastCRTBuilder(std::uint64_t ch, std::uint64_t d, unsigned log_n);

        ~FFieldFastCRTBuilder();

        inline std::uint64_t ch() const
        {
            return ch_;
        }

        inline std::uint64_t degree() const
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

        inline FFieldArray create_array() const
        {
            return FFieldArray(fields_);
        }

        void compose(gsl::span<const FFieldElt> values, seal::Plaintext &destination);
        void decompose(const seal::Plaintext &plain, gsl::span<FFieldElt> destination) const;
        void compose(const FFieldArray &values, seal::Plaintext &destination);
        void decompose(const seal::Plaintext &plain, FFieldArray &destination) const;

    private:
        void build_modulus_tree(std::uint64_t node);
        void interpolate(std::uint64_t node);

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
        nmod_poly_struct *result_tree_;
        nmod_poly_t temp_poly_;
    };
}
