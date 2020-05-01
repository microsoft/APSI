// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "apsi/tools/interpolate.h"
#include <seal/util/uintarithsmallmod.h>
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_array.h"

using namespace std;
using namespace seal;

namespace apsi
{
    void ffield_newton_interpolate_poly(const FFieldArray &points, const FFieldArray &values, FFieldArray &result)
    {
#ifdef APSI_DEBUG
        if (points.size() != values.size() || result.size() != points.size())
        {
            throw invalid_argument("incompatible array sizes");
        }
        if (points.field() != values.field() || result.field() != points.field())
        {
            throw invalid_argument("incompatible fields");
        }
#endif
        auto size = points.size();
        auto field = points.field();

        FFieldElt numerator(field);
        FFieldElt denominator(field);

        vector<FFieldArray> divided_differences;
        divided_differences.reserve(size);
        for (size_t i = 0; i < size; i++)
        {
            divided_differences.emplace_back(size - i, field);
            divided_differences[i].set(0, i, values);
        }

        const Modulus &ch = field.ch();

        for (size_t j = 1; j < size; j++)
        {
            for (size_t i = 0; i < size - j; i++)
            {
                // numerator = DD[i + 1][j - 1] - DD[i][j - 1]
                transform(
                    divided_differences[i + 1].data(j - 1), divided_differences[i + 1].data(j),
                    divided_differences[i].data(j - 1), numerator.data(),
                    [ch](auto a, auto b) { return util::sub_uint_uint_mod(a, b, ch); });

                // denominator = points[i + j] - points[i]
                transform(
                    points.data(i + j), points.data(i + j + 1), points.data(i), denominator.data(),
                    [ch](auto a, auto b) { return util::sub_uint_uint_mod(a, b, ch); });

                // DD[i][j] = numerator / denominator
                transform(
                    numerator.data(), numerator.data() + field.d(), denominator.data(), divided_differences[i].data(j),
                    [ch](auto a, auto b) {
                        _ffield_elt_coeff_t inv;
                        if (!util::try_invert_uint_mod(b, ch, inv))
                        {
                            if (a == 0)
                            {
                                // could return any element
                                return _ffield_elt_coeff_t(0);
                            }
                            else
                            {
                                throw logic_error("division by zero");
                            }
                        }
                        return util::multiply_uint_uint_mod(a, inv, ch);
                    });
            }
        }

        // Horner's method
        // We reuse numerator

        // result[0] = DD[0][size-1];
        result.set(0, size - 1, divided_differences[0]);
        for (size_t i = 1; i < size; i++)
        {
            for (int j = static_cast<int>(i) - 1; j >= 0; j--)
            {
                // result[j+1] = result[j]
                result.set(j + 1, j, result);
            }

            result.set_zero(0);

            for (size_t j = 0; j < i; j++)
            {
                // numerator = points[size - 1 - i] * result[j + 1]
                transform(
                    points.data(size - 1 - i), points.data(size - i), result.data(j + 1), numerator.data(),
                    [ch](auto a, auto b) { return util::multiply_uint_uint_mod(a, b, ch); });

                // result[j] -= numerator
                transform(result.data(j), result.data(j + 1), numerator.data(), result.data(j), [ch](auto a, auto b) {
                    return util::sub_uint_uint_mod(a, b, ch);
                });
            }

            transform(
                result.data(), result.data(1), divided_differences[0].data(size - 1 - i), result.data(),
                [ch](auto a, auto b) { return util::add_uint_uint_mod(a, b, ch); });
        }
    }
} // namespace apsi
