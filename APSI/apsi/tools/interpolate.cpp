#include "seal/util/polyarithsmallmod.h"
#include "apsi/tools/interpolate.h"
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_array.h"
#include <mutex>

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace oc;

namespace apsi
{

    std::mutex mtx;

    void ffield_newton_interpolate_poly(
        const FFieldArray &points,
        const FFieldArray &values,
        FFieldArray& result)
    {
        //std::lock_guard<std::mutex> lock(mtx);

#ifndef NDEBUG
        if (points.size() != values.size() || result.size() != points.size())
        {
            throw invalid_argument("incompatible array sizes");
        }
        if (points.field(0) != values.field(0) || result.field(0) != points.field(0))
        {
            throw invalid_argument("incompatible fields");
        }
#endif
        auto size = points.size();

        // The fields should all be the same
        auto field = points.field(0);
        //auto field = FField::Acquire(points.field(0)->ch(), points.field(0)->d());
        //vector<FFieldArray> divided_differences;
        //for(size_t i = 0; i < points.size(); i++)
        //{
        //    divided_differences.emplace_back(field, points.size() - i);
        //}
        
        FFieldElt numerator(field);
        FFieldElt denominator(field);

        vector<FFieldArray> divided_differences;
        divided_differences.reserve(size);
        for (size_t i = 0; i < size; i++)
        {
            divided_differences.emplace_back(field, size - i);
#ifndef NDEBUG
            if (divided_differences[i].size() != size - i)
                throw std::runtime_error("");
#endif
            divided_differences[i].set(0, i, values);
        }

        for (size_t j = 1; j < size; j++)
        {
            for (size_t i = 0; i < size - j; i++)
            {
                fq_nmod_sub(numerator.data(), divided_differences[i + 1].data() + (j - 1), divided_differences[i].data() + (j - 1), field->ctx());
                // numerator = divided_differences[i + 1].get(j - 1) - divided_differences[i].get(j - 1);
                fq_nmod_sub(denominator.data(), points.data() + (i + j), points.data() + i, field->ctx());
                // denominator = points.get(i + j) - points.get(i);
                // divided_differences[i].set(j, numerator / denominator);

                fq_nmod_div(divided_differences[i].data() + j, numerator.data(), denominator.data(), field->ctx());
            }
        }

        // Horner's method
        // We reuse numerator
        result.set(0, size-1, divided_differences[0]);
        for (size_t i = 1; i < size; i++)
        {
            for (int64_t j = i - 1; j >= 0; j--)
            {
                result.set(j + 1, j, result);
            }
            result.set_zero(0);
            for (size_t j = 0; j < i; j++)
            {
                fq_nmod_mul(numerator.data(), points.data() + (size - 1 - i), result.data() + (j + 1), field->ctx());
                fq_nmod_sub(result.data() + j, result.data() + j, numerator.data(), field->ctx());
                // temp = points.get(size - 1 - i) * result.get(j + 1);
                // result.set(j, result.get(j) - points.get(size - 1 - i) * result.get(j + 1));
            }
            fq_nmod_add(result.data(), result.data(), divided_differences[0].data() + (size - 1 - i), field->ctx());
            // result.set(0, result.get(0) + divided_differences[0].get(size - 1 - i));
        }
    }

    vector<FFieldArray> get_div_diff_temp(const std::shared_ptr<FField>& field, int size)
    {
        vector<FFieldArray> divided_differences;
        divided_differences.reserve(size);

        for (int i = 0; i < size; ++i)
        {
            divided_differences.emplace_back(field, size - i);
        }

        return divided_differences;
    }

    void u64_newton_interpolate_poly(
        oc::span<pair<uint64_t, uint64_t> > input,
        oc::span<uint64_t> result,
        const seal::SmallModulus &plain_modulus)
    {
        int size = input.size();
        vector<vector<uint64_t>> divided_differences(size);
        uint64_t numerator;
        uint64_t denominator;
        uint64_t inverse;
        // Plaintext quotient(coeff_count);

        for (int i = 0; i < size; i++) {
            divided_differences[i].resize(size - i);
            divided_differences[i][0] = input[i].second;
        }
        for (int j = 1; j < size; j++) {
            for (int i = 0; i < size - j; i++) {
                {
                    numerator = sub_uint_uint_mod(divided_differences[i + 1][j - 1], divided_differences[i][j - 1], plain_modulus);
                    denominator = sub_uint_uint_mod(input[i + j].first, input[i].first, plain_modulus);
                    // dd[(i, j)] = (dd[(i + 1, j - 1)] - dd[(i, j - 1)]) / (xvec[i + j] - xvec[i])
                    // multiply numerator with inverted denominator .... . FIXME: this should be multiplication modulo....
                    // FIXME (mod t)
                    try_invert_uint_mod(denominator, plain_modulus, inverse);
                    divided_differences[i][j] = multiply_uint_uint_mod(numerator, inverse, plain_modulus);

                }
            }

        }

        // Horner's method 
        if (result.size() != size)
            throw runtime_error("bad size");

        result[0] = divided_differences[0][size - 1];
        for (int i = 1; i < size; i++) {

            // first, multiply by (x - x_{n-i})


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
