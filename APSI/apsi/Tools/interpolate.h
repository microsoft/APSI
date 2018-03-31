#pragma once
#include "seal//util/exfield.h"
#include "seal/plaintext.h"


namespace apsi
{
    // compute the coefficients of the polynomial which intercepts 
    // the provided extension field points (input).
    void exfield_newton_interpolate_poly(
        const std::vector<std::pair<seal::util::ExFieldElement, seal::util::ExFieldElement>>& input,
        std::vector<seal::util::ExFieldElement>& result);

    // compute the coefficients of the polynomial which intercepts 
    // the provided extension field points (input).
    void plaintext_newton_interpolate_poly(
        const std::vector<std::pair<seal::Plaintext, seal::Plaintext>>& input,
        std::vector<seal::Plaintext>& result,
        const uint64_t* poly_modulus,
        const seal::SmallModulus &plain_modulus,
        seal::util::MemoryPool &pool,
        bool print = false);
}