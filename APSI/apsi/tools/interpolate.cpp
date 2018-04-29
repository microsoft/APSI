#include "seal/util/polyarithsmallmod.h"
#include "apsi/tools/interpolate.h"
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_array.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace oc;

namespace apsi
{
    void print_ptxt(seal::Plaintext &ptxt, int coeff_count = 0) {
        if (coeff_count == 0) {
            coeff_count = ptxt.coeff_count();
        }
        for (int j = 0; j < coeff_count; j++) {
            cout << ptxt.pointer()[j] << ", ";
        }
        cout << endl;
    }

    void ffield_newton_interpolate_poly(
        const FFieldArray &points, const FFieldArray &values,
        FFieldArray& result)
    {
#ifndef NDEBUG
        if(points.size() != values.size() || result.size() != points.size())
        {   
            throw invalid_argument("incompatible array sizes");
        }
        if(points.field() != values.field() || result.field() != points.field())
        {
           throw invalid_argument("incompatible fields"); 
        } 
#endif
        auto size = points.size();

        // The fields should all be the same
        auto field = points.field(0);

        FFieldElt numerator(field);
        FFieldElt denominator(field);

        vector<FFieldArray> divided_differences;
        for(size_t i = 0; i < size; i++)
        {
            divided_differences.emplace_back(field, size - i);
            divided_differences[i].set(0, i, values);
        }

        for(size_t j = 1; j < size; j++)
        {
            for(size_t i = 0; i < size - j; i++)
            {
                if (field == nullptr)
                    throw std::runtime_error("");

                fq_nmod_sub(numerator.data(), divided_differences[i + 1].data() + (j - 1), divided_differences[i].data() + (j - 1), field->ctx());
                // numerator = divided_differences[i + 1].get(j - 1) - divided_differences[i].get(j - 1);
                fq_nmod_sub(denominator.data(), points.data() + (i + j), points.data() + i, field->ctx());
                // denominator = points.get(i + j) - points.get(i);
                // divided_differences[i].set(j, numerator / denominator);
                fq_nmod_div(divided_differences[i].data() + j, numerator.data(), denominator.data(), field->ctx());
            }
        }

        // Horner's method
        FFieldElt temp(field);
        result.set(0, divided_differences[0].get(size - 1));
        for(size_t i = 1; i < size; i++)
        {
            for(int64_t j = i - 1; j >= 0; j--)
            {
                result.set(j + 1, j, result);
            }
            result.set_zero(0);
            for (size_t j = 0; j < i; j++) 
            {
                fq_nmod_mul(temp.data(), points.data() + (size - 1 - i), result.data() + (j + 1), field->ctx());
                fq_nmod_sub(result.data() + j, result.data() + j, temp.data(), field->ctx());
                // temp = points.get(size - 1 - i) * result.get(j + 1);
                // result.set(j, result.get(j) - points.get(size - 1 - i) * result.get(j + 1));
            }
            fq_nmod_add(result.data(), result.data(), divided_differences[0].data() + (size - 1 - i), field->ctx());
            // result.set(0, result.get(0) + divided_differences[0].get(size - 1 - i));
        }
    }

    void ffield_newton_interpolate_poly(
        const FFieldArray &points, const FFieldArray &values,
        FFieldPoly& result)
    {
#ifndef NDEBUG
        if(points.size() != values.size())
        {   
            throw invalid_argument("incompatible array sizes");
        }
        if(points.field() != values.field() || result.field() != points.field())
        {
           throw invalid_argument("incompatible fields"); 
        } 
#endif
        result.set_zero();

        auto size = points.size();

        // The fields SHOULD all be the same
        auto field = points.field(0);

        FFieldElt numerator(field);
        FFieldElt denominator(field);

        vector<FFieldArray> divided_differences;
        for(size_t i = 0; i < size; i++)
        {
            divided_differences.emplace_back(field, size - i);
            divided_differences[i].set(0, values.get(i));
        }

        for(size_t j = 0; j < size; j++)
        {
            for(size_t i = 0; i < size - j; i++)
            {
                numerator = divided_differences[i + 1].get(j - 1) - divided_differences[i].get(j - 1);
                denominator = points.get(i + j) - points.get(i);
                divided_differences[i].set(j, numerator / denominator);
            }
        }

        // Horner's method
        result.set(0, divided_differences[0].get(size - 1));
        auto zero = field->zero(); 
        for(size_t i = 1; i < size; i++)
        {
            for(int64_t j = i - 1; j >= 0; j--)
            {
                result.set(j + 1, result.get(j));
            }
            result.set(0, zero);
            for (size_t j = 0; j < i; j++) 
            {
                result.set(j, result.get(j) - points.get(size - 1 - i) * result.get(j + 1));
            }
            result.set(0, result.get(0) + divided_differences[0].get(size - 1 - i));
        }
    }

    // void exfield_newton_interpolate_poly(
    //     const vector<pair<seal::util::ExFieldElement, seal::util::ExFieldElement>>& input,
    //     vector<seal::util::ExFieldElement>& result)
    // {
    //     int size = input.size();
    //     vector<vector<ExFieldElement>> divided_differences(size);
    //     ExFieldElement numerator;
    //     ExFieldElement denominator;
    //     // Plaintext quotient(coeff_count);
    //
    //     for (int i = 0; i < size; i++) {
    //         divided_differences[i].resize(size - i);
    //         divided_differences[i][0] = input[i].second;
    //     }
    //     for (int j = 1; j < size; j++) {
    //         for (int i = 0; i < size - j; i++) {
    //             {
    //                 numerator = divided_differences[i + 1][j - 1] - divided_differences[i][j - 1];
    //                 denominator = input[i + j].first - input[i].first;
    //                 // dd[(i, j)] = (dd[(i + 1, j - 1)] - dd[(i, j - 1)]) / (xvec[i + j] - xvec[i])
    //                 // multiply numerator with inverted denominator .... . FIXME: this should be multiplication modulo....
    //                 //divided_differences[i][j] =  numerator / denominator; 
    //             }
    //         }
    //
    //     }
    //
    //     // Horner's method 
    //     result.resize(size);
    //     result[0] = divided_differences[0][size - 1];
    //     for (int i = 1; i < size; i++) {
    //
    //         // first, multiply by (x - x_{n-i})
    //
    //
    //         // shift first 
    //         for (int j = i - 1; j >= 0; j--) {
    //             result[j + 1] = result[j];
    //         }
    //         result[0] = ExFieldElement();
    //         for (int j = 0; j < i; j++) {
    //             result[j] = result[j] - input[size - 1 - i].first * result[j + 1];
    //         }
    //         result[0] = result[0] + divided_differences[0][size - 1 - i];
    //
    //         //for (int i = 0; i < result.size(); i++) {
    //         //        cout << "current result [ " << i << " ] =";
    //         //        print_ptxt(result[i], 1);
    //         //}
    //     }
    // }

    // // Performs a Newton Interpolation
    // void plaintext_newton_interpolate_poly(
    //     const vector<pair<seal::Plaintext, seal::Plaintext>>& input,
    //     vector<seal::Plaintext>& result,
    //     const uint64_t* poly_modulus,
    //     const seal::SmallModulus &plain_modulus,
    //     seal::util::MemoryPool &pool,
    //     bool print)
    // {
    //     using vector;
    //     using seal::Plaintext;
    //
    //     int size = input.size();
    //     int coeff_count = input[0].first.coeff_count();
    //     vector<vector<Plaintext>> divided_differences(size);
    //     Plaintext numerator(coeff_count);
    //     Plaintext denominator(coeff_count);
    //     Plaintext inverted_denominator(coeff_count);
    //     // Plaintext quotient(coeff_count);
    //
    //     for (int i = 0; i < size; i++) {
    //         divided_differences[i].resize(size - i);
    //         for (int j = 0; j < size - i; j++) {
    //             divided_differences[i][j] = Plaintext(coeff_count);
    //         }
    //         divided_differences[i][0] = input[i].second;
    //     }
    //     for (int j = 1; j < size; j++) {
    //         for (int i = 0; i < size - j; i++) {
    //             {
    //                 seal::util::sub_poly_poly_coeffmod(divided_differences[i + 1][j - 1].pointer(), divided_differences[i][j - 1].pointer(),
    //                     coeff_count, plain_modulus, numerator.pointer());
    //
    //                 seal::util::sub_poly_poly_coeffmod(input[i + j].first.pointer(), input[i].first.pointer(),
    //                     coeff_count, plain_modulus, denominator.pointer());
    //
    //                 // dd[(i, j)] = (dd[(i + 1, j - 1)] - dd[(i, j - 1)]) / (xvec[i + j] - xvec[i])
    //
    //                 seal::util::try_invert_poly_coeffmod(denominator.pointer(), poly_modulus, coeff_count, plain_modulus, inverted_denominator.pointer(), pool);
    //
    //                 // multiply numerator with inverted denominator .... . FIXME: this should be multiplication modulo....
    //                 seal::util::multiply_poly_poly_coeffmod(numerator.pointer(), coeff_count,
    //                     inverted_denominator.pointer(), coeff_count,
    //                     plain_modulus, coeff_count, divided_differences[i][j].pointer());
    //             }
    //         }
    //
    //     }
    //
    //     // Horner's method 
    //     seal::util::Pointer result_ptr(allocate_zero_poly(size, coeff_count, pool)); // correct allocation.  First one being 1, and the others being zero.
    //
    //     result.resize(0);
    //     result.reserve(size);
    //     int offset = 0;
    //     for (int i = 0; i < size; i++) {
    //         result.emplace_back(coeff_count, result_ptr.get() + offset);
    //         offset += coeff_count;
    //     }
    //     result[0] = divided_differences[0][size - 1];
    //
    //
    //
    //     // vector<Plaintext> normalized_dd;
    //     if (print)
    //     {
    //         for (int i = 0; i < divided_differences.size(); i++) {
    //             for (int j = 0; j < divided_differences[i].size(); j++) {
    //                 cout << "dd [ " << i << ", " << j << "] =";
    //                 print_ptxt(divided_differences[i][j]);
    //             }
    //         }
    //
    //         Plaintext temp_inv(coeff_count);
    //         seal::util::try_invert_poly_coeffmod(divided_differences[0][size - 1].pointer(), poly_modulus, coeff_count, plain_modulus, temp_inv.pointer(), pool);
    //
    //         cout << "inverse of last divided difference";
    //         for (int j = 0; j < coeff_count; j++) {
    //             cout << temp_inv.pointer()[j] << ", ";
    //         }
    //         cout << endl;
    //     }
    //
    //
    //     // we should normalize the coefficients...
    //     Plaintext temp(coeff_count);
    //     for (int i = 1; i < size; i++) {
    //
    //         // first, multiply by (x - x_{n-i})
    //
    //
    //         // shift first 
    //         for (int j = i - 1; j >= 0; j--) {
    //             result[j + 1] = result[j];
    //         }
    //         result[0].set_zero();
    //         for (int j = 0; j < i; j++) {
    //             // result[j] -= x[size-1-i] * result[j+1];
    //             seal::util::multiply_poly_poly_coeffmod(result[j + 1].pointer(), coeff_count,
    //                 input[size - 1 - i].first.pointer(), coeff_count,
    //                 plain_modulus, coeff_count, temp.pointer());
    //             seal::util::sub_poly_poly_coeffmod(result[j].pointer(), temp.pointer(),
    //                 coeff_count, plain_modulus, result[j].pointer());
    //             // result[j] = arith.sub(arith.multiply(input[size - i - 1].first(), result[j - 1]);
    //         }
    //
    //         // Then, add dd[0][i] to the constant coefficient.
    //         //      result[0] = arith.add(result[0], normalized_dd[size-1-i]);
    //
    //         seal::util::add_poly_poly_coeffmod(result[0].pointer(), divided_differences[0][size - 1 - i].pointer(),
    //             coeff_count, plain_modulus, result[0].pointer());
    //
    //
    //         if (print)
    //         {
    //             for (int i = 0; i < result.size(); i++) {
    //                 cout << "current result [ " << i << " ] =";
    //                 print_ptxt(result[i], 1);
    //             }
    //         }
    //     }
    // }

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
