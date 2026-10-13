// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <numeric>
#include <random>
#include <unordered_set>
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
        uint64_t result = 0;
        uint64_t x_pow = 1;

        MultiplyUIntModOperand x_mod_op{};
        x_mod_op.set(x, mod);
        for (unsigned long long i : poly) {
            result = add_uint_mod(result, multiply_uint_mod(i, x_pow, mod), mod);
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
            generate_n(back_inserter(values), points.size(), [&] { return u(rd); });

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

    namespace {
        /**
        Newton interpolation with a table of divided differences, as APSI 1.x implements
        newton_interpolate_polyn: slow, but simple enough to be the reference for
        newton_interpolate_polyn and newton_interpolate_polyns, whose results must not change. The
        points must be distinct.
        */
        vector<uint64_t> divided_differences_interpolate(
            const vector<uint64_t> &points, const vector<uint64_t> &values, const Modulus &mod)
        {
            size_t size = points.size();
            if (all_of(values.cbegin(), values.cend(), [](auto a) { return a == 0; })) {
                return vector<uint64_t>(max<size_t>(size, 1));
            }

            vector<vector<uint64_t>> divided_differences(size);
            for (size_t i = 0; i < size; i++) {
                divided_differences[i].push_back(values[i]);
            }
            for (size_t j = 1; j < size; j++) {
                for (size_t i = 0; i < size - j; i++) {
                    uint64_t numerator = sub_uint_mod(
                        divided_differences[i + 1][j - 1], divided_differences[i][j - 1], mod);
                    uint64_t denominator = sub_uint_mod(points[i + j], points[i], mod);
                    uint64_t inv_denominator =
                        exponentiate_uint_mod(denominator, mod.value() - 2, mod);
                    divided_differences[i].push_back(
                        multiply_uint_mod(numerator, inv_denominator, mod));
                }
            }

            vector<uint64_t> result{ 0 };
            for (size_t i = size - 1; i > 0; i--) {
                result[0] = add_uint_mod(result[0], divided_differences[0][i], mod);
                polyn_mul_monic_monomial_inplace(result, points[i - 1], mod);
            }
            result[0] = add_uint_mod(result[0], divided_differences[0][0], mod);

            return result;
        }

        /**
        Distinct points sampled uniformly from [0, mod)
        */
        vector<uint64_t> random_points(size_t size, const Modulus &mod, mt19937_64 &rng)
        {
            uniform_int_distribution<uint64_t> u(0, mod.value() - 1);
            unordered_set<uint64_t> seen;
            vector<uint64_t> points;
            while (points.size() < size) {
                uint64_t point = u(rng);
                if (seen.insert(point).second) {
                    points.push_back(point);
                }
            }
            return points;
        }

        /**
        Values sampled uniformly from [0, mod), with about a quarter of them set to zero
        */
        vector<uint64_t> random_values(size_t size, const Modulus &mod, mt19937_64 &rng)
        {
            uniform_int_distribution<uint64_t> u(0, mod.value() - 1);
            vector<uint64_t> values(size);
            for (auto &value : values) {
                value = (rng() % 4) ? u(rng) : 0;
            }
            return values;
        }
    } // namespace

    TEST(InterpolateTests, NewtonInterpolatePolynMatchesDividedDifferences)
    {
        // The plain moduli of the parameter sets in the parameters directory other than the 256M
        // ones, and small ones
        mt19937_64 rng(1);
        for (uint64_t p : { 7, 101, 40961, 65537, 147457, 270337, 2277377, 4423681 }) {
            Modulus mod(p);
            for (size_t size : { 1, 2, 3, 5, 42, 228, 512 }) {
                if (size > p) {
                    continue;
                }
                auto points = random_points(size, mod, rng);
                auto values = random_values(size, mod, rng);
                ASSERT_EQ(
                    divided_differences_interpolate(points, values, mod),
                    newton_interpolate_polyn(points, values, mod));
            }
        }

        // The largest bins of the parameter sets other than the 256M ones
        Modulus mod(4423681);
        auto points = random_points(1304, mod, rng);
        auto values = random_values(1304, mod, rng);
        auto polyn = newton_interpolate_polyn(points, values, mod);
        ASSERT_EQ(divided_differences_interpolate(points, values, mod), polyn);
        for (size_t i = 0; i < points.size(); i++) {
            ASSERT_EQ(values[i], uint64_t_poly_eval(polyn, points[i], mod));
        }
    }

    TEST(InterpolateTests, NewtonInterpolatePolyns)
    {
        Modulus mod(65537);
        vector<uint64_t> roots;

        // No values: only the polynomial with the given roots, which may repeat
        ASSERT_TRUE(newton_interpolate_polyns({ 1, 2, 2 }, {}, mod, &roots).empty());
        ASSERT_EQ(polyn_with_roots({ 1, 2, 2 }, mod), roots);

        // No points
        vector<uint64_t> no_values;
        auto polyns = newton_interpolate_polyns({}, { no_values, no_values }, mod, &roots);
        ASSERT_EQ(2, polyns.size());
        for (const auto &polyn : polyns) {
            ASSERT_EQ(vector<uint64_t>{ 0 }, polyn);
        }
        ASSERT_EQ(vector<uint64_t>{ 1 }, roots);

        // Invalid number of values
        vector<uint64_t> two_values{ 1, 2 };
        vector<uint64_t> one_value{ 1 };
        ASSERT_THROW(
            auto result = newton_interpolate_polyns({ 0, 1 }, { two_values, one_value }, mod),
            invalid_argument);

        // Invalid modulus (not a prime)
        ASSERT_THROW(
            auto result = newton_interpolate_polyns({ 0 }, { one_value }, Modulus(4)),
            invalid_argument);

        // Repeated points are an error unless all values are zero, as in newton_interpolate_polyn
        vector<uint64_t> zeros(3, 0);
        vector<uint64_t> nonzeros{ 1, 0, 1 };
        ASSERT_THROW(
            auto result = newton_interpolate_polyns({ 1, 2, 1 }, { zeros, nonzeros }, mod),
            logic_error);
        polyns = newton_interpolate_polyns({ 1, 2, 1 }, { zeros, zeros }, mod, &roots);
        ASSERT_EQ(2, polyns.size());
        for (const auto &polyn : polyns) {
            ASSERT_EQ(zeros, polyn);
        }
        ASSERT_EQ(polyn_with_roots({ 1, 2, 1 }, mod), roots);

        // The results are identical to separate calls, including all-zero values
        mt19937_64 rng(2);
        for (uint64_t p : { 65537U, 270337U, 4423681U }) {
            mod = p;
            for (size_t size : { 1U, 7U, 228U }) {
                for (size_t count : { 1U, 3U, 23U }) {
                    auto points = random_points(size, mod, rng);
                    vector<vector<uint64_t>> values;
                    vector<gsl::span<const uint64_t>> value_spans;
                    for (size_t j = 0; j < count; j++) {
                        values.push_back(
                            (j % 3 == 1) ? vector<uint64_t>(size, 0)
                                         : random_values(size, mod, rng));
                    }
                    for (const auto &curr_values : values) {
                        value_spans.emplace_back(curr_values);
                    }

                    polyns = newton_interpolate_polyns(points, value_spans, mod, &roots);
                    ASSERT_EQ(polyn_with_roots(points, mod), roots);
                    ASSERT_EQ(count, polyns.size());
                    for (size_t j = 0; j < count; j++) {
                        ASSERT_EQ(newton_interpolate_polyn(points, values[j], mod), polyns[j]);
                    }

                    // newton_interpolate_polyn is compared with the reference in
                    // NewtonInterpolatePolynMatchesDividedDifferences, so one random and one
                    // all-zero value vector suffice here
                    for (size_t j = 0; j < min<size_t>(count, 2); j++) {
                        ASSERT_EQ(
                            divided_differences_interpolate(points, values[j], mod), polyns[j]);
                    }

                    // Without the polynomial with the given roots
                    ASSERT_EQ(polyns, newton_interpolate_polyns(points, value_spans, mod));
                }
            }
        }
    }
} // namespace APSITests
