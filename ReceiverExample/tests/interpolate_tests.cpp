#include "interpolate_tests.h"

#include "apsi/Tools/interpolate.h"
#include "seal/context.h"
#include "seal/util/mempool.h"
#include  "cryptoTools/Common/TestCollection.h"

std::string toString(seal::Plaintext &ptxt, int coeff_count = 0) {
    if (coeff_count == 0) {
        coeff_count = ptxt.coeff_count();
    }

    std::stringstream ss;
    ss << "(";
    for (int j = 0; j < coeff_count; j++) {
        ss << ptxt.pointer()[j];
        
        if(j != coeff_count -1 )
            ss << ", ";
    }
    ss << ")";

    return ss.str();
}




// return poly(x) 
seal::Plaintext plaintext_poly_evaluate(
    const std::vector<seal::Plaintext>& poly, 
    seal::Plaintext x, 
    const seal::SEALContext& context)
{

    auto plain_modulus = context.plain_modulus();
    auto coeff_count = context.poly_modulus().coeff_count();

    auto temp = x;
    auto result = poly[0];

    for (int i = 1; i < poly.size(); ++i)
    {

        // temp = poly[i] * x;
        seal::util::multiply_poly_poly_coeffmod(
            poly[i].pointer(),
            x.pointer(),
            coeff_count,
            plain_modulus,
            temp.pointer());

        // result = result + temp;
        seal::util::add_poly_poly_coeffmod(
            result.pointer(),
            temp.pointer(),
            coeff_count,
            plain_modulus,
            result.pointer());

        // x = x * x
        seal::util::multiply_poly_poly_coeffmod(
            x.pointer(),
            x.pointer(),
            coeff_count,
            plain_modulus,
            x.pointer());
    }

    return result;
}

void plaintext_interpolate_test()
{
    seal::EncryptionParameters parms;
    parms.set_poly_modulus("1x^64 + 1");
    parms.set_coeff_modulus(seal::coeff_modulus_128(1024));
    parms.set_plain_modulus(11);

    seal::SEALContext context(parms);

    auto poly_modulus = context.poly_modulus();
    auto coeff_modulus = context.total_coeff_modulus();
    auto plain_modulus = context.plain_modulus();

    int coeff_count = context.poly_modulus().coeff_count();

    std::vector<std::pair<seal::Plaintext, seal::Plaintext>> points(3);

    for (int i = 0; i < points.size(); i++) {
        points[i].first = seal::Plaintext(coeff_count);
        points[i].first.set_zero();
        points[i].second = seal::Plaintext(coeff_count);
        points[i].second.set_zero();
        points[i].first[0] = i;
        points[i].second[0] = i;
    }
    points[2].second[0] = 1;

    //for (int i = 0; i < points.size(); i++) {
    //        for (int j = 0; j < points[i].first.coeff_count(); j++) {

    //                cout << points[i].first.pointer()[j] << ", ";
    //        }
    //        cout << endl;
    //}
    auto pool = seal::MemoryPoolHandle::Global();
    std::vector<seal::Plaintext> result;
    
          
    apsi::plaintext_newton_interpolate_poly(points, result, poly_modulus.pointer(), plain_modulus, pool, true);


    // PolyCRTBuilder crtbuilder(context);
    std::cout << "result " << std::endl;
    for (int i = 0; i < result.size(); i++) {
        for (int j = 0; j < result[i].coeff_count(); j++) {

            std::cout << result[i].pointer()[j] << ", ";
        }
        std::cout << std::endl;
    }


    bool passed = true;
    for (int i =0; i < points.size(); ++i)
    {
        auto& x = points[i].first;
        auto& y = points[i].second;
        auto yy = plaintext_poly_evaluate(result, x, context);
        if (yy != y)
        {
            std::cout << " poly(x[" << i << "]) = " << toString(yy)
                << "  != \n"
                << "y[" << i << "] = " << toString(y) << std::endl;
            passed = false;
        }
        else
        {

            std::cout << " poly(x[" << i << "]) = " << toString(yy)
                << "  == \n"
                << "y[" << i << "] = " << toString(y) << std::endl;
        }
    }

    if (passed == false)
        throw oc::UnitTestFail();
}
