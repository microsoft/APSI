// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <gsl/span>
#include <seal/plaintext.h>
#include <utility>
#include <vector>
#include "apsi/ffield/ffield_array.h"

namespace apsi
{
    /**
    Multiplies the given polynomial P with the monomial x - a, where a is given. Polynomial coefficients are expected
    to be in degree-ascending order, i.e., polyn[0] is the constant term.
    */
    void polyn_mul_monic_monomial_inplace(std::vector<uint64_t> &polyn, uint64_t a, const seal::Modulus &mod);

    /**
    Returns the Newton interpolation of the given points and values. Specifically, this function returns the
    coefficients of a polynomial P in degree-ascending, where P(pointᵢ) == valueᵢ for all i.
    */
    std::vector<uint64_t> newton_interpolate_polyn(
        const std::vector<uint64_t> &points,
        const std::vector<uint64_t> &values,
        const seal::Modulus &mod
    );

    /**
    Given a set of distinct field elements a₁, ..., aₛ, returns the coefficients of the unique monic polynomial P with
    roots a₁, ..., aₛ. Concretely, P = (x-a₁)*...*(x-aₛ).
    The returned coefficients are in degree-ascending order. That is, polyn[0] is the constant term.
    */
    std::vector<uint64_t> polyn_with_roots(std::vector<uint64_t> &roots, const seal::Modulus &mod);
} // namespace apsi
