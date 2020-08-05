// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <stdexcept>

// APSI
#include "apsi/util/interpolate.h"

// SEAL
#include "seal/util/uintarithsmallmod.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    namespace util
    {
        /**
        Multiplies the given polynomial P with the monomial x - a, where a is given. Polynomial coefficients are expected
        to be in degree-ascending order, i.e., polyn[0] is the constant term.
        */
        void polyn_mul_monic_monomial_inplace(vector<uint64_t> &polyn, uint64_t a, const seal::Modulus &mod)
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

            uint64_t neg_a = negate_uint_mod(a, mod);
            // We don't have to make an intermediate copy of the coefficients if we proceed from right to left
            for (size_t i = polyn.size()-1; i > 0; i--)
            {
                // Let cᵢ = cᵢ₋₁ - a*cᵢ
                polyn[i] = multiply_add_uint_mod(polyn[i-1], neg_a, polyn[i], mod);
            }

            // Do the new c₀ manually, since it doesn't fit the above formula (i-1 goes out of bounds)
            polyn[0] = multiply_uint_mod(polyn[0], neg_a, mod);
        }

        /**
        Returns the Newton interpolation of the given points and values. Specifically, this function returns the
        coefficients of a polynomial P in degree-ascending, where P(pointᵢ) valueᵢ for all i.
        */
        vector<uint64_t> newton_interpolate_polyn(
            const vector<uint64_t> &points,
            const vector<uint64_t> &values,
            const seal::Modulus &mod
        ) {
#ifdef APSI_DEBUG
            if (points.size() != values.size())
            {
                throw invalid_argument("incompatible array sizes");
            }

            /**
            Sanity check. Nobody should be using this function with all-0 labels. The Newton polynomial for all-0 points is
            the 0 polynomial, and that's almost certainly not the desired output.
            */
            bool all_zeros = true;
            for (val : values)
            {
                if (val != 0)
                {
                    all_zeros = false;
                }
            }

            if (all_zeros)
            {
                throw invalid_argument(
                    "Newton polynomial of all zeros is the zero polynomial. You probably mean to use polyn_with_roots"
                );
            }
#endif
            auto size = points.size();

            vector<vector<uint64_t> > divided_differences;
            divided_differences.reserve(size);
            for (size_t i = 0; i < size; i++)
            {
                divided_differences.push_back( vector{values[i]} );
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
            for (size_t j = 1; j < size; j++)
            {
                for (size_t i = 0; i < size - j; i++)
                {
                    // numerator = DD[i + 1][j - 1] - DD[i][j - 1]
                    uint64_t numerator = sub_uint_mod(
                        divided_differences[i + 1][j - 1],
                        divided_differences[i][j - 1],
                        mod
                    );

                    // denominator = points[i + j] - points[i]
                    uint64_t denominator = sub_uint_mod(points[i + j], points[i], mod);

                    // DD[i][j] = numerator / denominator
                    uint64_t inv_denominator;
                    if (!try_invert_uint_mod(denominator, mod, inv_denominator))
                    {
                        throw logic_error("tried to interpolate with repeated values");
                    }
                    divided_differences[i][j] = multiply_uint_mod(numerator, inv_denominator, mod);
                }
            }

            /**
            The Newton interpolation polynomial is
            [y₀] + [y₀, y₁](x-x₀) + [y₀, y₁, y₂](x-x₀)(x-x₁) + ... + [y₀, y₁, ..., yᵣ](x-x₀)(x-x₁)...(x-xᵣ)
            = [y₀] +
                (x-x₀) * ([y₀, y₁] + ...
                (x-xᵣ₋₃) * ([y₀, y₁, ..., yᵣ₋₂] +
                    (x-xᵣ₋₂) * (
                    [y₀, y₁, ..., yᵣ₋₁]
                    + (x-xᵣ₋₁) * [y₀, y₁, ..., yᵣ]
                    )
                )
                ...)
            We use Horner's method, i.e., we start with the innermost term and repeatedly add-and-multiply
            */

            // Start with P = 0
            vector<uint64_t> result;
            result.reserve(size+1);
            result.push_back(0);

            // Do Horner's method for all inner terms
            for (size_t i = size-1; i > 0; i--)
            {
                // P += [y₀, ..., yᵢ]
                result[0] = add_uint_mod(result[0], divided_differences[0][i], mod);
                // P *= (x - xᵢ₋₁)
                polyn_mul_monic_monomial_inplace(result, points[i-1], mod);
            }

            // Add the last constant term [y₀]
            result[0] = add_uint_mod(result[0], divided_differences[0][0], mod);

            return result;
        }


        /**
        Given a set of distinct field elements a₁, ..., aₛ, returns the coefficients of the unique monic polynoimial P with
        roots a₁, ..., aₛ. Concretely, P = (x-a₁)*...*(x-aₛ).
        The returned coefficients are in degree-ascending order. That is, polyn[0] is the constant term.
        */
        vector<uint64_t> polyn_with_roots(vector<uint64_t> &roots, const seal::Modulus &mod)
        {
            // Start with P = 1 = 1 + 0x + 0x^2 + ...
            vector<uint64_t> polyn;
            polyn.reserve(roots.size()+1);
            polyn.push_back(1);

            // For every root a, let P *= (x - a)
            for (const uint64_t &root : roots)
            {
                polyn_mul_monic_monomial_inplace(polyn, root, mod);
            }

            return polyn;
        }
    }
} // namespace apsi
