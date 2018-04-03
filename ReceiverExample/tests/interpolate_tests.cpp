#include "interpolate_tests.h"

#include "apsi/Tools/interpolate.h"
#include "seal/context.h"
#include "seal/util/mempool.h"

#include  "cryptoTools/Common/TestCollection.h"
#include  "cryptoTools/Crypto/PRNG.h"

std::string toString(seal::Plaintext &ptxt, int coeff_count = 0) {
    if (coeff_count == 0) {
        coeff_count = ptxt.coeff_count();
    }

    std::stringstream ss;
    ss << "(";
    for (int j = 0; j < coeff_count; j++) {
        ss << ptxt.pointer()[j];

        if (j != coeff_count - 1)
            ss << ", ";
    }
    ss << ")";

    return ss.str();
}




// return poly(x) 
oc::u64 u64_poly_eval(
    const std::vector<oc::u64>& poly,
    const oc::u64& x,
    const seal::SmallModulus& mod)
{
    //std::cout << "f(" << x << ") = ";
    oc::u64 result = 0, xx = 1;

    for (int i = 0; i < poly.size(); ++i)
    {
        result = (result + poly[i] * xx) % mod.value();
        xx = (xx * x) % mod.value();
    }
    return result;
}

void u64_interpolate_test()
{
    using oc::u64;

    seal::EncryptionParameters parms;
    parms.set_poly_modulus("1x^64 + 1");
    parms.set_coeff_modulus(seal::coeff_modulus_128(1024));
    parms.set_plain_modulus(11);

    seal::SEALContext context(parms);

    auto plain_modulus = context.plain_modulus();
    int numPoints = std::min<int>(100, plain_modulus.value() - 1);
    int numTrials = 10;

    
    oc::PRNG prng(oc::ZeroBlock);

    for (int i = 0; i < numTrials; ++i)
    {

        std::vector<std::pair<u64, u64>> points(numPoints);

        for (int i = 0; i < points.size(); i++) {
            points[i].first = i;
            points[i].second = prng(plain_modulus.value());

            //std::cout << "( " << points[i].first << ", " << points[i].second << ") ";
        }
        //std::cout << std::endl;
        //points[2].second[0] = 1;

        //for (int i = 0; i < points.size(); i++) {
        //        for (int j = 0; j < points[i].first.coeff_count(); j++) {

        //                cout << points[i].first.pointer()[j] << ", ";
        //        }
        //        cout << endl;
        //}
        auto pool = seal::MemoryPoolHandle::Global();
        std::vector<u64> result(points.size());

        apsi::u64_newton_interpolate_poly(points, result, plain_modulus);
        //apsi::plaintext_newton_interpolate_poly(points, result, poly_modulus.pointer(), plain_modulus, pool, true);


        // PolyCRTBuilder crtbuilder(context);

        //std::cout << "result(x) = " << std::endl;
        //for (int i = result.size() - 1; i; --i)
        //    std::cout << result[i] << " x^"<<i<<" + ";
        //std::cout << result[0] << std::endl;


        bool passed = true;
        for (int i = 0; i < points.size(); ++i)
        {
            auto& x = points[i].first;
            auto& y = points[i].second;
            //auto yy = plaintext_poly_evaluate(result, x, context);
            auto yy = u64_poly_eval(result, x, plain_modulus);
            if (yy != y)
            {
                std::cout << " poly(x[" << i << "]) = " << yy
                    << "  != \n"
                    << "y[" << i << "] = " << y << std::endl;
                passed = false;
            }
            //else
            //{

            //    std::cout << " poly(x[" << i << "]) = " << yy
            //        << "  == \n"
            //        << "y[" << i << "] = " << (y) << std::endl;
            //}
        }

        if (passed == false)
            throw oc::UnitTestFail();

    }

}
