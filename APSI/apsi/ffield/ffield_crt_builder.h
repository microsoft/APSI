#pragma once

// STD
#include <vector>
#include <map>
#include <memory>

// APSI 
#include "apsi/ffield/ffield_ntt.h"

// SEAL
#include "seal/plaintext.h"

namespace apsi
{
    class FFieldCRTBuilder
    {
    public:
        FFieldCRTBuilder(std::shared_ptr<FField> field, unsigned log_degree, oc::PRNG &prng);

        FFieldCRTBuilder(std::shared_ptr<FField> field, unsigned log_degree, FFieldElt zeta);

        inline FFieldElt zeta() const
        {
            return ntt_ctx_.zeta();
        }

        inline std::uint64_t n() const
        {
            return ntt_ctx_.n_;
        }

        inline std::uint64_t m() const
        {
            return ntt_ctx_.m_;
        }

        inline unsigned log_n() const
        {
            return ntt_ctx_.log_n_;
        }

        inline std::uint64_t slot_count() const
        {
            return ntt_ctx_.slot_count_;
        }

        void compose(seal::Plaintext &destination, const FFieldArray &values) const;

        void decompose(FFieldArray &destination, const seal::Plaintext &plain) const;

    private:
        struct coset_element
        {
            // The odd power a
            std::uint64_t odd;

            // Representative b of the equivalence class
            std::uint64_t rep;

            // 'j' in a = b*t^j
            std::uint64_t hop;
        };

        void bit_reversal_permutation(FFieldArray &input) const;
        void compute_cosets();
        void expand(FFieldArray &out, const FFieldArray &in) const;
        void contract(FFieldArray &out, const FFieldArray &in) const;

        std::shared_ptr<FField> field_;
        std::vector<coset_element> cosets_;

        // Mapping from equivalence class representative to data index
        std::map<std::uint64_t, std::uint64_t> index_map_;

        FFieldNTT ntt_ctx_;
    };
}
