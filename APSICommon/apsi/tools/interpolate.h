// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <utility>
#include <vector>

// GSL
#include <gsl/span>

// SEAL
#include "seal/plaintext.h"

// APSI
#include "apsi/ffield/ffield_array.h"


namespace apsi
{
    // compute the coefficients of the polynomial which intercepts 
    // the provided extension field points (input).
    void ffield_newton_interpolate_poly(
        const FFieldArray &points, const FFieldArray &values,
        FFieldArray& result);

    std::vector<FFieldArray> get_div_diff_temp(FField field, std::size_t size);

    void u64_newton_interpolate_poly(
        gsl::span<std::pair<u64, u64> > input,
        gsl::span<u64> result,
        const seal::SmallModulus &plain_modulus);
}
