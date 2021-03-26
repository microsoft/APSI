// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// APSI
#include "apsi/item.h"
#include "apsi/oprf/ecpoint.h"

namespace apsi {
    namespace oprf {
        using oprf_key_type = ECPoint::scalar_type;
        using oprf_key_const_type = const ECPoint::scalar_type;
        using oprf_key_span_type = ECPoint::scalar_span_type;
        using oprf_key_span_const_type = ECPoint::scalar_span_const_type;

        constexpr auto oprf_item_size = sizeof(Item);
        constexpr auto oprf_hash_size = sizeof(HashedItem);
        constexpr auto oprf_query_size = ECPoint::save_size;
        constexpr auto oprf_response_size = ECPoint::save_size;
        constexpr auto oprf_key_size = ECPoint::order_size;
    } // namespace oprf
} // namespace apsi
