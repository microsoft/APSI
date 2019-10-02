// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"

#include <stdexcept>

#include "utils.h"
#include "apsi/apsidefines.h"
#include "apsi/tools/aes.h"
#include "apsi/tools/prng.h"

using namespace apsi;
using namespace apsi::tools;


namespace APSITests
{
    TEST(AESTests, constructor_test)
    {
        AES aes;
        block key, pt;

        // Unkeyed should throw
        ASSERT_ANY_THROW(aes.ecb_enc_block(pt));

        // Keyed does not throw
        AES aes2(key);
        ASSERT_NO_THROW(aes2.ecb_enc_block(pt));

        AESDec aesd;
        ASSERT_ANY_THROW(aesd.ecb_dec_block(pt));

        AESDec aesd2(key);
        ASSERT_NO_THROW(aesd2.ecb_dec_block(pt));
    }

    TEST(AESTests, block_test)
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

        ASSERT_TRUE(0 == memcmp(&pt, &pt2, sizeof(block)));
        ASSERT_TRUE(0 != memcmp(&pt, &ct, sizeof(block)));
        ASSERT_TRUE(0 != memcmp(&pt2, &ct, sizeof(block)));
    }
}
