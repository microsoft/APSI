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

namespace apsi {
    namespace util {
        /**
        Multiplies the given polynomial P with the monomial x - a, where a is given. Polynomial
        coefficients are expected to be in degree-ascending order, i.e., polyn[0] is the constant
        term.
        */
        void polyn_mul_monic_monomial_inplace(
            vector<uint64_t> &polyn, uint64_t a, const Modulus &mod)
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

            MultiplyUIntModOperand neg_a;
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

            auto size = points.size();

            bool all_zeros = all_of(values.cbegin(), values.cend(), [](auto a) { return a == 0; });
            if (all_zeros) {
                // Return a vector of all zeros
                return vector<uint64_t>(max<size_t>(size, 1));
            }

            vector<vector<uint64_t>> divided_differences;
            divided_differences.reserve(size);
            for (size_t i = 0; i < size; i++) {
                vector<uint64_t> inner;
                inner.reserve(size - i);
                inner.push_back(values[i]);
                divided_differences.push_back(std::move(inner));
            }

            /**
            Make a table of divided differences so that DD[i][j] is [yᵢ, yᵢ₊₁, ..., yᵢ₊ⱼ]
            Here's an example:

                    | j=0 |    j=1   |         j=2         |    ...
                ----------------------------------------------
                    |     |          |  y₂ - y₁   y₁ - y₀  |
                    |     |  y₁ - y₀ |  ------- - -------  |
                i=0 |  y₀ |  ------- |  x₂ - x₁   x₁ - x₀  |    ...
                    |     |  x₁ - x₀ | ------------------- |
                    |     |          |       x₂ - x₀       |
                ----------------------------------------------
                    |     |          |  y₃ - y₂   y₂ - y₁  |
                    |     |  y₂ - y₁ |  ------- - -------  |
                i=1 |  y₁ |  ------- |  x₃ - x₂   x₂ - x₁  |    ...
                    |     |  x₂ - x₁ | ------------------- |
                    |     |          |       x₃ - x₁       |
                ----------------------------------------------
                ... | ... |    ...   |         ...         |
            */
            for (size_t j = 1; j < size; j++) {
                for (size_t i = 0; i < size - j; i++) {
                    // numerator = DD[i + 1][j - 1] - DD[i][j - 1]
                    uint64_t numerator = sub_uint_mod(
                        divided_differences[i + 1][j - 1], divided_differences[i][j - 1], mod);

                    // denominator = points[i + j] - points[i]
                    uint64_t denominator = sub_uint_mod(points[i + j], points[i], mod);
                    if (!denominator) {
                        throw logic_error("tried to interpolate at repeated points");
                    }

                    // DD[i][j] = numerator / denominator
                    uint64_t inv_denominator =
                        exponentiate_uint_mod(denominator, mod.value() - 2, mod);

                    // Push as divided_differences[i][j]
                    divided_differences[i].push_back(
                        multiply_uint_mod(numerator, inv_denominator, mod));
                }
            }

            /**
            The Newton interpolation polynomial is
            [y₀] + [y₀, y₁](x-x₀) + [y₀, y₁, y₂](x-x₀)(x-x₁) + ... + [y₀, y₁, ...,
            yᵣ](x-x₀)(x-x₁)...(x-xᵣ) = [y₀] + (x-x₀) * ([y₀, y₁] + ... (x-xᵣ₋₃) * ([y₀, y₁, ...,
            yᵣ₋₂] + (x-xᵣ₋₂) * ( [y₀, y₁, ..., yᵣ₋₁]
                    + (x-xᵣ₋₁) * [y₀, y₁, ..., yᵣ]
                    )
                )
                ...)
            We use Horner's method, i.e., we start with the innermost term and repeatedly
            add-and-multiply
            */

            // Start with P = 0
            vector<uint64_t> result;
            result.reserve(size);
            result.push_back(0);

            // Do Horner's method for all inner terms
            for (size_t i = size - 1; i > 0; i--) {
                // P += [y₀, ..., yᵢ]
                result[0] = add_uint_mod(result[0], divided_differences[0][i], mod);
                // P *= (x - xᵢ₋₁)
                polyn_mul_monic_monomial_inplace(result, points[i - 1], mod);
            }

            // Add the last constant term [y₀]
            result[0] = add_uint_mod(result[0], divided_differences[0][0], mod);

            return result;
        }
    } // namespace util
} // namespace apsi
