// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"

#include "apsi/apsidefines.h"
#include "apsi/tools/interpolate.h"
#include <seal/context.h>
#include <seal/util/mempool.h>
#include <seal/smallmodulus.h>
#include <random>

using namespace apsi;
using namespace std;

namespace APSITests
{
    string toString(seal::Plaintext &ptxt, size_t coeff_count = 0) {
        if (coeff_count == 0) {
            coeff_count = ptxt.coeff_count();
        }

        stringstream ss;
        ss << "(";
        for (size_t j = 0; j < coeff_count; j++) {
            ss << ptxt.data()[j];

            if (j != coeff_count - 1)
                ss << ", ";
        }
        ss << ")";

        return ss.str();
    }

    // return poly(x) 
    u64 u64_poly_eval(
        const vector<u64>& poly,
        const u64& x,
        const seal::SmallModulus& mod)
    {
        //cout << "f(" << x << ") = ";
        u64 result = 0, xx = 1;

        for (size_t i = 0; i < poly.size(); ++i)
        {
            result = (result + poly[i] * xx) % mod.value();
            xx = (xx * x) % mod.value();
        }
        return result;
    }

    TEST(InterpolateTests, basic_ffield_interpolate_test)
    {
        seal::EncryptionParameters parms(seal::scheme_type::BFV);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(1024));
        parms.set_plain_modulus(40961);

        auto context = seal::SEALContext::Create(parms);

        int degree = 2; 
        auto plain_modulus = context->first_context_data()->parms().plain_modulus();
        u64 numPoints = min<u64>(3, plain_modulus.value() / degree);
        int numTrials = 10;

        FField field(parms.plain_modulus(), degree); 
        FFieldArray points(static_cast<size_t>(numPoints), field);
        FFieldArray values(static_cast<size_t>(numPoints), field);
        FFieldArray result(static_cast<size_t>(numPoints), field);

        for (size_t j = 0; j < points.size(); j++) {
            for (int k = 0; k < degree; k++) {
                // random points 
                points.set_coeff_of(j, k, (j * degree + k) % plain_modulus.value());
                values.set_coeff_of(j, k, (j * degree + k) % plain_modulus.value());
            }
        }

        ffield_newton_interpolate_poly(points, values, result);

        // Check the result: interpolating (x,x) should result in polynomial coeffs (0,1,0,...,0)
        // vector<u64> tempresult(points.size());
        for (int k = 0; k < degree; k++) {
            for (size_t j = 0; j < points.size(); ++j)
            {
                if (j != 1 && result.get_coeff_of(j, k) != 0) {
                    FAIL();
                }
                if (j == 1 && result.get_coeff_of(j, k) != 1) {
                    FAIL();
                }
            }
        }

        // Next: interpolate zero 
        for (size_t j = 0; j < points.size(); j++) {
            for (int k = 0; k < degree; k++) {
                // random points 
                points.set_coeff_of(j, k, (j * degree + k) % plain_modulus.value());
                values.set_coeff_of(j, k, 0);
            }
        }

        // interpolate zero poly
        ffield_newton_interpolate_poly(points, values, result);

        // Check the result: interpolating (x,0) should result in zero polynomial.
        // vector<u64> tempresult(points.size());
        for (int k = 0; k < degree; k++) {
            for (size_t j = 0; j < points.size(); ++j)
            {
                if (result.get_coeff_of(j, k) != 0) {
                    FAIL();
                }
            }
        }
    }

    TEST(InterpolateTests, ffield_interpolate_test)
    {
        int degree = 2;
        seal::SmallModulus plain_modulus(40961);
        u64 numPoints = min<u64>(3, plain_modulus.value() / degree);
        int numTrials = 10;

        FField field(plain_modulus, degree);
        FFieldArray points(static_cast<size_t>(numPoints), field);
        FFieldArray values(static_cast<size_t>(numPoints), field);
        FFieldArray result(static_cast<size_t>(numPoints), field);

        random_device rd;

        for (int i = 0; i < numTrials; ++i)
        {
            for (size_t j = 0; j < points.size(); j++) {
                for (int k = 0; k < degree; k++) {
                    // random points 
                    points.set_coeff_of(j, k, rd() % plain_modulus.value());
                    values.set_coeff_of(j, k, (j * degree + k) % plain_modulus.value());
                }
            }

            ffield_newton_interpolate_poly(points, values, result);

            // Check the result
            vector<u64> tempresult(points.size());
            for (int k = 0; k < degree; k++) {
                for (size_t j = 0; j < points.size(); ++j)
                {
                    tempresult[j] = result.get_coeff_of(j, k);
                }
                for (size_t j = 0; j < points.size(); ++j) {
                    u64 x = points.get_coeff_of(j, k);
                    u64 y = values.get_coeff_of(j, k);

                    auto yy = u64_poly_eval(tempresult, x, plain_modulus);
                    if (yy != y)
                    {
                        cout << " poly(x[" << i << "]) = " << yy
                            << "  != \n"
                            << "y[" << i << "] = " << y << endl;
                        FAIL();
                    }
                }
            }
        }
    }
}
