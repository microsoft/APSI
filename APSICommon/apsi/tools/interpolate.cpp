// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <mutex>
#include <seal/util/uintarithsmallmod.h>
#include <seal/util/numth.h>
#include "apsi/tools/interpolate.h"
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_array.h"

using namespace std;
using namespace seal;

namespace apsi
{
    void ffield_newton_interpolate_poly(
    const FFieldArray &points,
    const FFieldArray &values,
    FFieldArray& result)
    {
#ifndef NDEBUG
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
#ifndef NDEBUG
            if (divided_differences[i].size() != size - i)
                throw runtime_error("");
#endif
            divided_differences[i].set(0, i, values);
        }

        const SmallModulus &ch = field.ch();

        for (size_t j = 1; j < size; j++)
        {
            for (size_t i = 0; i < size - j; i++)
            {
                // numerator = DD[i + 1][j - 1] - DD[i][j - 1]
                transform(
                    divided_differences[i + 1].data(j - 1),
                    divided_differences[i + 1].data(j),
                    divided_differences[i].data(j - 1), numerator.data(),
                    [ch](auto a, auto b) { return util::sub_uint_uint_mod(a, b, ch); });

                // denominator = points[i + j] - points[i]
                transform(
                    points.data(i + j),
                    points.data(i + j + 1),
                    points.data(i),
                    denominator.data(),
                    [ch](auto a, auto b) { return util::sub_uint_uint_mod(a, b, ch); });

                // DD[i][j] = numerator / denominator
                transform(
                    numerator.data(),
                    numerator.data() + field.d(),
                    denominator.data(),
                    divided_differences[i].data(j),
                    [ch](auto a, auto b) {
                        _ffield_elt_coeff_t inv;
                        if (!util::try_invert_uint_mod(b, ch, inv)) {
                            if (a == 0) {
                                // could return any element 
                                return _ffield_elt_coeff_t(0);
                            }
                            else {
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
        result.set(0, size-1, divided_differences[0]);
        for (size_t i = 1; i < size; i++)
        {
            for (int j = static_cast<int>(i) - 1; j >= 0; j--)
            {
                // result[j+1] = result[j] ? 
                result.set(j + 1, j, result);
            }

            result.set_zero(0);

            for (size_t j = 0; j < i; j++)
            {
                // numerator = points[size - 1 - i] * result[j + 1]
                transform(
                    points.data(size - 1 - i),
                    points.data(size - i),
                    result.data(j + 1),
                    numerator.data(),
                    [ch](auto a, auto b) { return util::multiply_uint_uint_mod(a, b, ch); });

                // result[j] -= numerator
                transform(
                    result.data(j),
                    result.data(j + 1),
                    numerator.data(),
                    result.data(j),
                    [ch](auto a, auto b) { return util::sub_uint_uint_mod(a, b, ch); });
            }

            transform(result.data(), result.data(1), divided_differences[0].data(size-1-i), result.data(), [ch](auto a, auto b) { return util::add_uint_uint_mod(a, b, ch); });
        }
    }

    vector<FFieldArray> get_div_diff_temp(FField field, size_t size)
    {
        vector<FFieldArray> divided_differences;
        divided_differences.reserve(size);

        for (size_t i = 0; i < size; ++i)
        {
            divided_differences.emplace_back(size - i, field);
        }

        return divided_differences;
    }

    void u64_newton_interpolate_poly(
        gsl::span<pair<u64, u64> > input,
        gsl::span<u64> result,
        const SmallModulus &plain_modulus)
    {
        int size = static_cast<int>(input.size());
        vector<vector<u64>> divided_differences(size);
        u64 numerator;
        u64 denominator;
        u64 inverse = 0;

        for (int i = 0; i < size; i++) {
            divided_differences[i].resize(size - i);
            divided_differences[i][0] = input[i].second;
        }

        for (int j = 1; j < size; j++) {
            for (int i = 0; i < size - j; i++) {
                numerator = util::sub_uint_uint_mod(divided_differences[i + 1][j - 1], divided_differences[i][j - 1], plain_modulus);
                denominator = util::sub_uint_uint_mod(input[i + j].first, input[i].first, plain_modulus);
                util::try_invert_uint_mod(denominator, plain_modulus, inverse);
                divided_differences[i][j] = util::multiply_uint_uint_mod(numerator, inverse, plain_modulus);
            }
        }

        // Horner's method 
        if (result.size() != size)
            throw runtime_error("bad size");

        result[0] = divided_differences[0][size - 1];
        for (int i = 1; i < size; i++) {
            // shift first 
            for (int j = i - 1; j >= 0; j--) {
                result[j + 1] = result[j];
            }
            result[0] = 0;
            for (int j = 0; j < i; j++) {
                result[j] = util::sub_uint_uint_mod(result[j], util::multiply_uint_uint_mod(input[size - 1 - i].first, result[j + 1], plain_modulus), plain_modulus);
            }
            result[0] = util::add_uint_uint_mod(result[0], divided_differences[0][size - 1 - i], plain_modulus);
        }
    }
} // namespace apsi
