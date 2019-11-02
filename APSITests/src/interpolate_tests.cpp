// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"

#include "apsi/tools/interpolate.h"
#include "seal/context.h"
#include "seal/util/mempool.h"

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
    uint64_t uint64_t_poly_eval(
        const vector<uint64_t>& poly,
        const uint64_t& x,
        const seal::SmallModulus& mod)
    {
        //cout << "f(" << x << ") = ";
        uint64_t result = 0, xx = 1;

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
        uint64_t numPoints = min<uint64_t>(3,  plain_modulus.value() / degree);
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
        // vector<uint64_t> tempresult(points.size());
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
        // vector<uint64_t> tempresult(points.size());
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
        seal::EncryptionParameters parms(seal::scheme_type::BFV);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(1024));
        parms.set_plain_modulus(40961);

        auto context = seal::SEALContext::Create(parms);

        int degree = 2;
        auto plain_modulus = context->first_context_data()->parms().plain_modulus();
        uint64_t numPoints = min<uint64_t>(3, plain_modulus.value() / degree);
        int numTrials = 10;

        FField field(parms.plain_modulus(), degree);
        FFieldArray points(static_cast<size_t>(numPoints), field);
        FFieldArray values(static_cast<size_t>(numPoints), field);
        FFieldArray result(static_cast<size_t>(numPoints), field);

        for (int i = 0; i < numTrials; ++i)
        {

            //vector<pair<uint64_t, uint64_t>> points(numPoints);

            for (size_t j = 0; j < points.size(); j++) {
                for (int k = 0; k < degree; k++) {
                    // random points 
                    points.set_coeff_of(j, k, (j * degree + k) % plain_modulus.value());
                    values.set_coeff_of(j, k, (j * degree + k) % plain_modulus.value());
                }
            }

            auto pool = seal::MemoryPoolHandle::Global();

            ffield_newton_interpolate_poly(points, values, result);

            // Check the result
            vector<uint64_t> tempresult(points.size());
            for (int k = 0; k < degree; k++) {
                for (size_t j = 0; j < points.size(); ++j)
                {
                    tempresult[j] = result.get_coeff_of(j, k);
                    // tempresult[j] = values.get_coeff_of(j, k);
                }
                for (size_t j = 0; j < points.size(); ++j) {
                    uint64_t x = points.get_coeff_of(j, k);
                    uint64_t y = values.get_coeff_of(j, k);
                    //auto& y = points[i].second;
                    auto yy = uint64_t_poly_eval(tempresult, x, plain_modulus);
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

    TEST(InterpolateTests, uint64_t_interpolate_test)
    {
        seal::EncryptionParameters parms(seal::scheme_type::BFV);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(1024));
        parms.set_plain_modulus(11);

        auto context = seal::SEALContext::Create(parms);

        auto plain_modulus = context->first_context_data()->parms().plain_modulus();
        uint64_t numPoints = min<uint64_t>(100, plain_modulus.value() - 1);
        int numTrials = 10;

        auto random_uint64 = []() {
            random_device rd;
            return (static_cast<uint64_t>(rd()) << 32) | static_cast<uint32_t>(rd());
        };

        for (int i = 0; i < numTrials; ++i)
        {

            vector<pair<uint64_t, uint64_t>> points(static_cast<size_t>(numPoints));

            for (size_t i = 0; i < points.size(); i++) {
                points[i].first = i;
                points[i].second = random_uint64() % plain_modulus.value();
            }

            auto pool = seal::MemoryPoolHandle::Global();
            vector<uint64_t> result(points.size());

            apsi::u64_newton_interpolate_poly(points, result, plain_modulus);

            for (size_t i = 0; i < points.size(); ++i)
            {
                auto& x = points[i].first;
                auto& y = points[i].second;
                auto yy = uint64_t_poly_eval(result, x, plain_modulus);
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
