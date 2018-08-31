#include "utils.h" 

#include <random>
#include <array>

using namespace apsi;
using namespace apsi::tools;

block apsi::tools::sysRandomSeed()
{
    std::random_device rd;
    auto ret = std::array<unsigned int, 4> { rd(), rd(), rd(), rd() };
    return *(block*)&ret;
}

bool apsi::tools::not_equal(const block& lhs, const block& rhs)
{
    block neq = _mm_xor_si128(lhs, rhs);
    return _mm_test_all_zeros(neq, neq) == 0;
}
