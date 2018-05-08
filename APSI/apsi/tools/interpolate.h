#pragma once

// STD
#include <utility>
#include <vector>

// SEAL
#include "seal/plaintext.h"

// APSI
#include "apsi/ffield/ffield_array.h"
#include "apsi/ffield/ffield_poly.h"

// CryptoTools
#include "cryptoTools/Common/Defines.h"

namespace apsi
{
    // compute the coefficients of the polynomial which intercepts 
    // the provided extension field points (input).
    void ffield_newton_interpolate_poly(
        const FFieldArray &points, const FFieldArray &values,
        FFieldArray& result);

    std::vector<FFieldArray> get_div_diff_temp(const std::shared_ptr<FField>& field, int size);


    // void exfield_newton_interpolate_poly(
    //     const std::vector<std::pair<seal::util::ExFieldElement, seal::util::ExFieldElement> > &input,
    //     std::vector<seal::util::ExFieldElement> &result);

    // // compute the coefficients of the polynomial which intercepts 
    // // the provided extension field points (input).
    // void plaintext_newton_interpolate_poly(
    //     const std::vector<std::pair<seal::Plaintext, seal::Plaintext> > &input,
    //     std::vector<seal::Plaintext> &result,
    //     const std::uint64_t *poly_modulus,
    //     const seal::SmallModulus &plain_modulus,
    //     seal::util::MemoryPool &pool,
    //     bool print = false);

    void u64_newton_interpolate_poly(
        oc::span<std::pair<std::uint64_t, std::uint64_t> > input,
        oc::span<std::uint64_t> result,
        const seal::SmallModulus &plain_modulus);
}
