#pragma once

// STD
#include <memory>
#include <vector>

// APSI
#include "apsi/ffield/ffield_elt.h"
#include "apsi/ffield/ffield_array.h"
#include "apsi/tools/prng.h"


namespace apsi
{
    class FFieldNTT
    {
        friend class FFieldBatchEncoder;

    public:
        FFieldNTT(std::shared_ptr<FField> field, unsigned log_degree, apsi::tools::PRNG &prng);

        FFieldNTT(std::shared_ptr<FField> field, unsigned log_degree, FFieldElt zeta);

        void negacyclic_ntt(FFieldArray &sequence) const;

        void inverse_negacyclic_ntt(FFieldArray &sequence) const;

        inline FFieldElt zeta() const
        {
            return zeta_;
        }

        inline unsigned log_n() const
        {
            return log_n_;
        }

        inline std::uint64_t n() const
        {
            return n_;
        }

        inline std::uint64_t m() const
        {
            return m_;
        }

        inline std::uint64_t slot_count() const
        {
            return slot_count_;
        }

    private:
        bool is_primitive_root(FFieldElt zeta) const;
        void populate_reverse_idx_array();
        void populate_zeta_powers(const FFieldElt &zeta, FFieldArray &zeta_powers);
        inline FFieldElt inv_primitive_root(const FFieldElt &in)
        {
            return in^(m_ - 1);
        }

        std::shared_ptr<FField> field_;
        FFieldElt zeta_;
        unsigned log_n_;
        std::uint64_t n_;
        std::uint64_t m_;
        std::uint64_t slot_count_;
        FFieldArray zeta_powers_;
        FFieldArray inv_zeta_powers_;
        std::vector<std::uint32_t> reversed_idx_;
        _ffield_elt_coeff_t inv_n_;

        // Mapping from equivalence class representative to data index
        std::map<std::uint64_t, std::uint64_t> index_map_;
    };
}
