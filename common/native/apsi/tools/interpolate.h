// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <utility>
#include <vector>
#include <gsl/span>
#include <seal/plaintext.h>
#include "apsi/ffield/ffield_array.h"

namespace apsi
{
    // compute the coefficients of the polynomial which intercepts 
    // the provided extension field points (input).
    void ffield_newton_interpolate_poly(
        const FFieldArray &points, const FFieldArray &values,
        FFieldArray& result);
} // namespace apsi
