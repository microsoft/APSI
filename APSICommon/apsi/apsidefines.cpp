// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#include "apsidefines.h"

using namespace std;

namespace apsi
{
    const block zero_block    = _mm_set_epi64x(0, 0);
    const block one_block     = _mm_set_epi64x(0, 1);
    const block all_one_block = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
    const block cc_block      = _mm_set_epi64x(0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC);

    const u64 default_sender_set_size = 65536;
}
