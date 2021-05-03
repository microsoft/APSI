// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <cstdint>
#include <numeric>
#include <random>
#include <vector>

// APSI
#include "apsi/config.h"
#include "apsi/util/interpolate.h"

// SEAL
#include "seal/context.h"
#include "seal/modulus.h"
#include "seal/util/uintarithsmallmod.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi::util;
using namespace seal;
using namespace seal::util;

namespace APSITests {
    uint64_t uint64_t_poly_eval(
        const vector<uint64_t> &poly, const uint64_t &x, const seal::Modulus &mod)
    {
        // cout << "f(" << x << ") = ";
        uint64_t result = 0, x_pow = 1;

        MultiplyUIntModOperand x_mod_op;
        x_mod_op.set(x, mod);
        for (size_t i = 0; i < poly.size(); ++i) {
            result = add_uint_mod(result, multiply_uint_mod(poly[i], x_pow, mod), mod);
            x_pow = multiply_uint_mod(x_pow, x_mod_op, mod);
        }
        return result;
    }

    TEST(InterpolateTests, PolynWithRoots)
    {
        // Invalid modulus
        Modulus mod(0);
        ASSERT_THROW(auto poly = polyn_with_roots({}, mod), invalid_argument);

        // Empty set of roots produces a constant 1
        mod = 3;
        auto poly = polyn_with_roots({}, mod);
        ASSERT_EQ(1, poly.size());
        ASSERT_EQ(1, poly[0]);

        // Single root (0)
        poly = polyn_with_roots({ 0 }, mod);
        ASSERT_EQ(2, poly.size());
        ASSERT_EQ(0, poly[0]);
        ASSERT_EQ(1, poly[1]);

        // Single root (1)
        poly = polyn_with_roots({ 1 }, mod);
        ASSERT_EQ(2, poly.size());
        ASSERT_EQ(2, poly[0]);
        ASSERT_EQ(1, poly[1]);

        // Single root (-1)
        poly = polyn_with_roots({ 2 }, mod);
        ASSERT_EQ(2, poly.size());
        ASSERT_EQ(1, poly[0]);
        ASSERT_EQ(1, poly[1]);

        // Repeated root (0)
        poly = polyn_with_roots({ 0, 0 }, mod);
        ASSERT_EQ(3, poly.size());
        ASSERT_EQ(0, poly[0]);
        ASSERT_EQ(0, poly[1]);
        ASSERT_EQ(1, poly[2]);

        // Repeated root (1)
        poly = polyn_with_roots({ 1, 1 }, mod);
        ASSERT_EQ(3, poly.size());
        ASSERT_EQ(1, poly[0]);
        ASSERT_EQ(1, poly[1]);
        ASSERT_EQ(1, poly[2]);

        // Two roots
        poly = polyn_with_roots({ 0, 1 }, mod);
        ASSERT_EQ(3, poly.size());
        ASSERT_EQ(0, poly[0]);
        ASSERT_EQ(2, poly[1]);
        ASSERT_EQ(1, poly[2]);

        poly = polyn_with_roots({ 1, 0 }, mod);
        ASSERT_EQ(3, poly.size());
        ASSERT_EQ(0, poly[0]);
        ASSERT_EQ(2, poly[1]);
        ASSERT_EQ(1, poly[2]);

        // Three roots
        poly = polyn_with_roots({ 0, 1, 2 }, mod);
        ASSERT_EQ(4, poly.size());
        ASSERT_EQ(0, poly[0]);
        ASSERT_EQ(2, poly[1]);
        ASSERT_EQ(0, poly[2]);
        ASSERT_EQ(1, poly[3]);
    }

    TEST(InterpolateTests, NewtonInterpolatePolyn)
    {
        Modulus mod(3);

        ASSERT_TRUE(newton_interpolate_polyn({}, {}, mod) == vector<uint64_t>{ 0 });

        // Invalid number of points/values
        ASSERT_THROW(auto poly = newton_interpolate_polyn({ 0 }, {}, mod), invalid_argument);
        ASSERT_THROW(auto poly = newton_interpolate_polyn({}, { 0 }, mod), invalid_argument);

        // Invalid modulus (not a prime)
        mod = 0;
        ASSERT_THROW(auto poly = newton_interpolate_polyn({ 0 }, { 0 }, mod), invalid_argument);
        mod = 4;
        ASSERT_THROW(auto poly = newton_interpolate_polyn({ 0 }, { 0 }, mod), invalid_argument);

        // Reset mod to a valid value
        mod = 3;

        // Compatible repeated roots
        ASSERT_THROW(
            auto poly = newton_interpolate_polyn({ 1, 2, 1 }, { 1, 0, 1 }, mod), logic_error);

        // Incompatible repeated roots
        ASSERT_THROW(
            auto poly = newton_interpolate_polyn({ 1, 2, 1 }, { 1, 0, 2 }, mod), logic_error);

        // Single interpolation point
        auto poly = newton_interpolate_polyn({ 0 }, { 1 }, mod);
        ASSERT_EQ(1, poly.size());
        ASSERT_EQ(1, poly[0]);

        poly = newton_interpolate_polyn({ 0 }, { 2 }, mod);
        ASSERT_EQ(1, poly.size());
        ASSERT_EQ(2, poly[0]);

        // Two interpolation points
        poly = newton_interpolate_polyn({ 0, 1 }, { 0, 1 }, mod);
        ASSERT_EQ(2, poly.size());
        ASSERT_EQ(0, poly[0]);
        ASSERT_EQ(1, poly[1]);

        poly = newton_interpolate_polyn({ 0, 1 }, { 1, 0 }, mod);
        ASSERT_EQ(2, poly.size());
        ASSERT_EQ(1, poly[0]);
        ASSERT_EQ(2, poly[1]);

        poly = newton_interpolate_polyn({ 0, 1 }, { 1, 2 }, mod);
        ASSERT_EQ(2, poly.size());
        ASSERT_EQ(1, poly[0]);
        ASSERT_EQ(1, poly[1]);

        // Sample random values for each value in [0, mod)
        auto random_interp = [](Modulus modulus) {
            random_device rd;
            auto u = uniform_int_distribution<uint64_t>(0, modulus.value() - 1);
            vector<uint64_t> points(modulus.value());
            iota(points.begin(), points.end(), 0);
            vector<uint64_t> values;
            generate_n(back_inserter(values), points.size(), [&]() { return u(rd); });

            // Interpolate and check the result
            auto p = newton_interpolate_polyn(points, values, modulus);
            ASSERT_EQ(modulus.value(), p.size());
            for (auto x : points) {
                ASSERT_EQ(uint64_t_poly_eval(p, x, modulus), values[x]);
            }
        };

        random_interp(7);
        random_interp(13);
        random_interp(23);
        random_interp(101);
    }
} // namespace APSITests
