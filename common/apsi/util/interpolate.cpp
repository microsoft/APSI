// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cstddef>
#include <stdexcept>

// APSI
#include "apsi/config.h"
#include "apsi/util/interpolate.h"

// SEAL
#include "seal/util/uintarithsmallmod.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi::util {
    namespace {
        /**
        Interpolates each of the given value vectors at the given points, which must be distinct,
        and returns the interpolation polynomials in degree-ascending order. If roots_polyn is not
        null, it is set to the monic polynomial with the given points as roots.

        The polynomials are built one point at a time. Let M be the product of (x - b) over the
        points b added so far, and P a polynomial interpolating the values at those points.
        Adding a point a with value v keeps the earlier values, since M vanishes at the earlier
        points, and gives P(a) = v:

            P <- P + (v - P(a)) / M(a) * M,
            M <- M * (x - a).

        Each point costs O(k) operations per polynomial and a single modular inversion that is
        shared by all of them, whereas a table of divided differences needs an inversion for
        every entry. The result is the unique polynomial of degree less than the number of points
        that takes the given values, so it is identical to the Newton interpolation.
        */
        vector<vector<uint64_t>> interpolate_incrementally(
            const vector<uint64_t> &points,
            const vector<gsl::span<const uint64_t>> &values,
            const Modulus &mod,
            vector<uint64_t> *roots_polyn)
        {
            const size_t size = points.size();
            const size_t count = values.size();

            // Coefficient i of the interpolation polynomial j is at coeffs[i * count + j], so the
            // work on all polynomials for a given coefficient is in contiguous memory
            vector<uint64_t> coeffs(size * count, 0);

            // Start with M = 1 = 1 + 0x + 0x^2 + ..., with room for its final degree
            vector<uint64_t> roots(size + 1, 0);
            roots[0] = 1;

            vector<uint64_t> evals(count);
            vector<MultiplyUIntModOperand> scales(count);
            for (size_t k = 0; k < size; k++) {
                MultiplyUIntModOperand point{};
                point.set(points[k], mod);

                // Evaluate M, which has degree k, and the interpolation polynomials, which have
                // degree less than k, at the new point with Horner's method. The evaluations do not
                // depend on each other, so the processor can overlap them.
                uint64_t roots_eval = roots[k];
                fill(evals.begin(), evals.end(), uint64_t{ 0 });
                for (size_t i = k; i-- > 0;) {
                    roots_eval = multiply_add_uint_mod(roots_eval, point, roots[i], mod);
                    const uint64_t *row = coeffs.data() + i * count;
                    for (size_t j = 0; j < count; j++) {
                        evals[j] = multiply_add_uint_mod(evals[j], point, row[j], mod);
                    }
                }

                // M(a) is the product of a - b over the earlier points b, so it is zero exactly
                // when the new point repeats an earlier one
                uint64_t inv_roots_eval = 0;
                if (!try_invert_uint_mod(roots_eval, mod, inv_roots_eval)) {
                    throw logic_error("tried to interpolate at repeated points");
                }

                // The multiple of M each interpolation polynomial gains: (v - P(a)) / M(a)
                for (size_t j = 0; j < count; j++) {
                    uint64_t scale = multiply_uint_mod(
                        sub_uint_mod(values[j][k], evals[j], mod), inv_roots_eval, mod);
                    scales[j].set(scale, mod);
                }

                // Let P += scale * M for every interpolation polynomial and M *= (x - a), in one
                // pass from the top coefficient down. Each coefficient of M is read before it is
                // updated, and M is updated exactly as in polyn_mul_monic_monomial_inplace.
                MultiplyUIntModOperand neg_point{};
                neg_point.set(negate_uint_mod(points[k], mod), mod);
                roots[k + 1] = roots[k];
                for (size_t i = k; i > 0; i--) {
                    const uint64_t roots_coeff = roots[i];
                    uint64_t *row = coeffs.data() + i * count;
                    for (size_t j = 0; j < count; j++) {
                        row[j] = multiply_add_uint_mod(roots_coeff, scales[j], row[j], mod);
                    }
                    roots[i] = multiply_add_uint_mod(roots_coeff, neg_point, roots[i - 1], mod);
                }

                // Do the constant coefficients manually, since the loop above needs roots[i - 1]
                for (size_t j = 0; j < count; j++) {
                    coeffs[j] = multiply_add_uint_mod(roots[0], scales[j], coeffs[j], mod);
                }
                roots[0] = multiply_uint_mod(roots[0], neg_point, mod);
            }

            // Transpose the coefficients into one vector per interpolation polynomial
            vector<vector<uint64_t>> result(count, vector<uint64_t>(size));
            for (size_t i = 0; i < size; i++) {
                for (size_t j = 0; j < count; j++) {
                    result[j][i] = coeffs[i * count + j];
                }
            }

            if (roots_polyn) {
                *roots_polyn = std::move(roots);
            }

            return result;
        }
    } // namespace

    /**
    Multiplies the given polynomial P with the monomial x - a, where a is given. Polynomial
    coefficients are expected to be in degree-ascending order, i.e., polyn[0] is the constant
    term.
    */
    void polyn_mul_monic_monomial_inplace(vector<uint64_t> &polyn, uint64_t a, const Modulus &mod)
    {
        /**
        Do the multiplication coefficient-wise. If P = [c₀, ..., cᵣ], then
        P' = (x-a)*P
        = x*P - a*P
        =   [   0,   c₀,   c₁, ..., cᵣ₋₁, cᵣ]
            - [a*c₀, a*c₁, a*c₂, ..., a*cᵣ,  0]

        In other words, polyn'[i] = polyn[i-1] - a*polyn[i]

        Extend the vector, since every multiplication introduces a new nonzero coefficient
        */
        polyn.push_back(0);

        MultiplyUIntModOperand neg_a{};
        neg_a.set(negate_uint_mod(a, mod), mod);

        // We don't have to make an intermediate copy of the coefficients if we proceed from
        // right to left
        for (size_t i = polyn.size() - 1; i > 0; i--) {
            // Let cᵢ = cᵢ₋₁ - a*cᵢ
            polyn[i] = multiply_add_uint_mod(polyn[i], neg_a, polyn[i - 1], mod);
        }

        // Do the new c₀ manually, since it doesn't fit the above formula (i-1 goes out of
        // bounds)
        polyn[0] = multiply_uint_mod(polyn[0], neg_a, mod);
    }

    /**
    Given a set of distinct field elements a₁, ..., aₛ, returns the coefficients of the unique
    monic polynoimial P with roots a₁, ..., aₛ. Concretely, P = (x-a₁)*...*(x-aₛ). The returned
    coefficients are in degree-ascending order. That is, polyn[0] is the constant term.
    */
    vector<uint64_t> polyn_with_roots(const vector<uint64_t> &roots, const Modulus &mod)
    {
        if (mod.is_zero()) {
            throw invalid_argument("mod cannot be zero");
        }

        // Start with P = 1 = 1 + 0x + 0x^2 + ...
        vector<uint64_t> polyn;
        polyn.reserve(roots.size() + 1);
        polyn.push_back(1);

        // For every root a, let P *= (x - a)
        for (uint64_t root : roots) {
            polyn_mul_monic_monomial_inplace(polyn, root, mod);
        }

        return polyn;
    }

    /**
    Returns the Newton interpolation of the given points and values. Specifically, this function
    returns the coefficients of a polynomial P in degree-ascending order, where P(pointᵢ) valueᵢ
    for all i.
    */
    vector<uint64_t> newton_interpolate_polyn(
        const vector<uint64_t> &points, const vector<uint64_t> &values, const Modulus &mod)
    {
        if (points.size() != values.size()) {
            throw invalid_argument(
                "number of values does not match the number of interpolation points");
        }
        if (!mod.is_prime()) {
            throw invalid_argument("mod must be prime");
        }

        bool all_zeros = all_of(values.cbegin(), values.cend(), [](auto a) { return a == 0; });
        if (all_zeros) {
            // Return a vector of all zeros
            return vector<uint64_t>(max<size_t>(points.size(), 1));
        }

        vector<gsl::span<const uint64_t>> values_list{ gsl::span<const uint64_t>(values) };
        return std::move(interpolate_incrementally(points, values_list, mod, nullptr)[0]);
    }

    /**
    Returns the polynomials newton_interpolate_polyn(points, valuesⱼ, mod) for every j. If
    roots_polyn is not null, it is set to polyn_with_roots(points, mod). The results are identical
    to calling those functions separately, but sharing the work between the polynomials makes
    this much faster.
    */
    vector<vector<uint64_t>> newton_interpolate_polyns(
        const vector<uint64_t> &points,
        const vector<gsl::span<const uint64_t>> &values,
        const Modulus &mod,
        vector<uint64_t> *roots_polyn)
    {
        for (const auto &curr_values : values) {
            if (points.size() != curr_values.size()) {
                throw invalid_argument(
                    "number of values does not match the number of interpolation points");
            }
        }
        if (!values.empty() && !mod.is_prime()) {
            throw invalid_argument("mod must be prime");
        }

        // As in newton_interpolate_polyn, all-zero values give an all-zero polynomial without
        // interpolation, so only the other value vectors are interpolated
        vector<size_t> nonzero_indices;
        vector<gsl::span<const uint64_t>> nonzero_values;
        for (size_t j = 0; j < values.size(); j++) {
            if (any_of(values[j].begin(), values[j].end(), [](auto a) { return a != 0; })) {
                nonzero_indices.push_back(j);
                nonzero_values.push_back(values[j]);
            }
        }

        vector<vector<uint64_t>> result(values.size());
        if (nonzero_values.empty()) {
            if (roots_polyn) {
                *roots_polyn = polyn_with_roots(points, mod);
            }
        } else {
            auto polyns = interpolate_incrementally(points, nonzero_values, mod, roots_polyn);
            for (size_t j = 0; j < nonzero_indices.size(); j++) {
                result[nonzero_indices[j]] = std::move(polyns[j]);
            }
        }

        // An all-zero value vector gives the zero polynomial, with as many coefficients as an
        // interpolated one, and one when there are no points
        for (auto &polyn : result) {
            if (polyn.empty()) {
                polyn.resize(max<size_t>(points.size(), 1));
            }
        }

        return result;
    }
} // namespace apsi::util
