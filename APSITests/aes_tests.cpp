#include "aes_tests.h"

#include <stdexcept>

#include "utils.h"
#include "apsi/apsidefines.h"
#include "apsi/tools/aes.h"
#include "apsi/tools/prng.h"

using namespace APSITests;
using namespace apsi;
using namespace apsi::tools;

void AESTests::constructor_test()
{
    AES aes;
    block key, pt;

    // Unkeyed should throw
    ASSERT_THROWS(aes.ecb_enc_block(pt));

    // Keyed does not throw
    AES aes2(key);
    CPPUNIT_ASSERT_NO_THROW(aes2.ecb_enc_block(pt));

    AESDec aesd;
    ASSERT_THROWS(aesd.ecb_dec_block(pt));

    AESDec aesd2(key);
    CPPUNIT_ASSERT_NO_THROW(aesd2.ecb_dec_block(pt));
}

void AESTests::block_test()
{
    block pt, ct, pt2;
    block seed = _mm_set1_epi64x(0LL);
    PRNG prng(seed);
    block key = prng.get<block>();

    AES aes;
    AESDec aesd;
    aes.set_key(key);
    aesd.set_key(key);

    pt = prng.get<block>();
    ct = aes.ecb_enc_block(pt);
    pt2 = aesd.ecb_dec_block(ct);

    CPPUNIT_ASSERT(0 == memcmp(&pt, &pt2, sizeof(block)));
    CPPUNIT_ASSERT(0 != memcmp(&pt, &ct, sizeof(block)));
    CPPUNIT_ASSERT(0 != memcmp(&pt2, &ct, sizeof(block)));
}
