#include "interpolate_tests.h"

#include "apsi/tools/interpolate.h"
#include "apsi/tools/prng.h"
#include "seal/context.h"
#include "seal/util/mempool.h"
#include "seal/defaultparams.h"

#include <cppunit/extensions/HelperMacros.h>

using namespace APSITests;
using namespace apsi;

CPPUNIT_TEST_SUITE_REGISTRATION(InterpolateTests);

std::string toString(seal::Plaintext &ptxt, size_t coeff_count = 0) {
    if (coeff_count == 0) {
        coeff_count = ptxt.coeff_count();
    }

    std::stringstream ss;
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
    const std::vector<u64>& poly,
    const u64& x,
    const seal::SmallModulus& mod)
{
    //std::cout << "f(" << x << ") = ";
    u64 result = 0, xx = 1;

    for (int i = 0; i < poly.size(); ++i)
    {
        result = (result + poly[i] * xx) % mod.value();
        xx = (xx * x) % mod.value();
    }
    return result;
}

void InterpolateTests::u64_interpolate_test()
{
    seal::EncryptionParameters parms(seal::scheme_type::BFV);
    parms.set_poly_modulus_degree(64);
    parms.set_coeff_modulus(seal::DefaultParams::coeff_modulus_128(1024));
    parms.set_plain_modulus(11);

    auto context = seal::SEALContext::Create(parms);

    auto plain_modulus = context->context_data()->parms().plain_modulus();
    u64 numPoints = std::min<u64>(100, plain_modulus.value() - 1);
    int numTrials = 10;

    
    apsi::tools::PRNG prng(apsi::zero_block);

    for (int i = 0; i < numTrials; ++i)
    {

        std::vector<std::pair<u64, u64>> points(numPoints);

        for (int i = 0; i < points.size(); i++) {
            points[i].first = i;
            points[i].second = prng.get<uint64_t>() % plain_modulus.value();
        }

        auto pool = seal::MemoryPoolHandle::Global();
        std::vector<u64> result(points.size());

        apsi::u64_newton_interpolate_poly(points, result, plain_modulus);

        for (int i = 0; i < points.size(); ++i)
        {
            auto& x = points[i].first;
            auto& y = points[i].second;
            auto yy = u64_poly_eval(result, x, plain_modulus);
            if (yy != y)
            {
                std::cout << " poly(x[" << i << "]) = " << yy
                    << "  != \n"
                    << "y[" << i << "] = " << y << std::endl;
                CPPUNIT_FAIL("Test failed.");
            }
        }
    }
}
