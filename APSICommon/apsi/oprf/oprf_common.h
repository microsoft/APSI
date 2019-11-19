// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "apsi/oprf/ecpoint.h"
#include "apsi/item.h"

namespace apsi
{
    namespace oprf 
    {
        using oprf_item_type = Item;
        constexpr auto oprf_item_size = oprf_item_type::item_byte_count;

        using oprf_hash_type = oprf_item_type;
        constexpr auto oprf_hash_size = oprf_item_size;

        constexpr auto oprf_query_size = ECPoint::save_size;
        constexpr auto oprf_response_size = ECPoint::save_size;

        constexpr auto oprf_key_size = ECPoint::order_size;
        using oprf_key_type = ECPoint::scalar_type;
        using oprf_key_const_type = const ECPoint::scalar_type;
        using oprf_key_span_type = ECPoint::scalar_span_type;
        using oprf_key_span_const_type = ECPoint::scalar_span_const_type;
    } // namespace oprf
} // namespace apsi
