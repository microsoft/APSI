// STD
#include <mutex>

// APSI
#include "apsi/tools/interpolate.h"
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_array.h"

// SEAL
#include <seal/util/uintarithsmallmod.h>
#include <seal/util/numth.h>

using namespace std;
using namespace seal;
using namespace seal::util;

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
                throw std::runtime_error("");
#endif
            divided_differences[i].set(0, i, values);
        }

        const seal::SmallModulus &ch = field.ch();

        for (size_t j = 1; j < size; j++)
        {
            for (size_t i = 0; i < size - j; i++)
            {
                // numerator = DD[i + 1][j - 1] - DD[i][j - 1]
                std::transform(
                    divided_differences[i + 1].data(j - 1),
                    divided_differences[i + 1].data(j),
                    divided_differences[i].data(j - 1), numerator.data(),
                    [ch](auto a, auto b) { return seal::util::sub_uint_uint_mod(a, b, ch); });

                // denominator = points[i + j] - points[i]
                std::transform(
                    points.data(i + j),
                    points.data(i + j + 1),
                    points.data(i),
                    denominator.data(),
                    [ch](auto a, auto b) { return seal::util::sub_uint_uint_mod(a, b, ch); });

                // DD[i][j] = numerator / denominator
                std::transform(
                    numerator.data(),
                    numerator.data() + field.d(),
                    denominator.data(),
                    divided_differences[i].data(j),
                    [ch](auto a, auto b) {
                        _ffield_elt_coeff_t inv;
                        if (!seal::util::try_invert_uint_mod(b, ch, inv)) {
                            if (a == 0) {
                                // could return any element 
                                return _ffield_elt_coeff_t(0);
                            }
                            else {
                                //Log::debug("Interpolation error: two points with same x coordinate but different y coordinates ");
                                throw std::logic_error("division by zero");
                            }
                        }
                        return seal::util::multiply_uint_uint_mod(a, inv, ch);
                    });
            }
        }

        // Horner's method
        // We reuse numerator
        result.set(0, size-1, divided_differences[0]);
        for (size_t i = 1; i < size; i++)
        {
            for (int j = i - 1; j >= 0; j--)
            {
                result.set(j + 1, j, result);
            }

            result.set_zero(0);

            for (size_t j = 0; j < i; j++)
            {
                // numerator = points[size - 1 - i] * result[j + 1]
                std::transform(
                    points.data(size - 1 - i),
                    points.data(size - i),
                    result.data(j + 1),
                    numerator.data(),
                    [ch](auto a, auto b) { return seal::util::multiply_uint_uint_mod(a, b, ch); });

                // result[j] -= numerator
                std::transform(
                    result.data(j),
                    result.data(j + 1),
                    numerator.data(),
                    result.data(j),
                    [ch](auto a, auto b) { return seal::util::sub_uint_uint_mod(a, b, ch); });
            }

            std::transform(result.data(), result.data(1), divided_differences[0].data(size-1-i), result.data(), [ch](auto a, auto b) { return seal::util::add_uint_uint_mod(a, b, ch); });

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
        gsl::span<pair<uint64_t, uint64_t> > input,
        gsl::span<uint64_t> result,
        const seal::SmallModulus &plain_modulus)
    {
        int size = static_cast<int>(input.size());
        vector<vector<uint64_t>> divided_differences(size);
        uint64_t numerator;
        uint64_t denominator;
        uint64_t inverse = 0;

        for (int i = 0; i < size; i++) {
            divided_differences[i].resize(size - i);
            divided_differences[i][0] = input[i].second;
        }

        for (int j = 1; j < size; j++) {
            for (int i = 0; i < size - j; i++) {
                numerator = sub_uint_uint_mod(divided_differences[i + 1][j - 1], divided_differences[i][j - 1], plain_modulus);
                denominator = sub_uint_uint_mod(input[i + j].first, input[i].first, plain_modulus);
                try_invert_uint_mod(denominator, plain_modulus, inverse);
                divided_differences[i][j] = multiply_uint_uint_mod(numerator, inverse, plain_modulus);
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
                result[j] = sub_uint_uint_mod(result[j], multiply_uint_uint_mod(input[size - 1 - i].first, result[j + 1], plain_modulus), plain_modulus);
            }
            result[0] = add_uint_uint_mod(result[0], divided_differences[0][size - 1 - i], plain_modulus);
        }
    }
}
