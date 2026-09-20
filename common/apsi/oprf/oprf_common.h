// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// APSI
#include "apsi/item.h"
#include "apsi/oprf/ecpoint.h"

namespace apsi::oprf {
    using oprf_key_type = ECPoint::scalar_type;
    using oprf_key_const_type = const ECPoint::scalar_type;
    using oprf_key_span_type = ECPoint::scalar_span_type;
    using oprf_key_span_const_type = ECPoint::scalar_span_const_type;

    constexpr auto oprf_item_size = sizeof(Item);
    constexpr auto oprf_hash_size = sizeof(HashedItem);
    constexpr auto oprf_query_size = ECPoint::save_size;
    constexpr auto oprf_response_size = ECPoint::save_size;
    constexpr auto oprf_key_size = ECPoint::order_size;

    /**
    An upper bound on the number of items one OPRF request may carry.

    The work is a scalar multiplication per item and is charged entirely to the sender, whose
    dispatcher serves one request at a time; without a bound, a single request sized only by the
    transport occupies it for as long as that request takes, and every other peer waits. The
    request is also cheap to produce, so the asymmetry is the whole problem.

    The value is the largest query a receiver could put to any use rather than a figure chosen for
    comfort. Items carried through the OPRF must afterwards be cuckoo-hashed into a table of
    PSIParams::TableParams::table_size bins, itself bounded by table_size_max, and a cuckoo table
    cannot be filled to capacity; so a request naming more items than that cannot lead to a query
    whatever the sender does with it. The largest parameter set in parameters/ recommends 11041
    receiver items, leaving roughly two orders of magnitude of headroom.
    */
    constexpr std::size_t oprf_query_count_max = static_cast<std::size_t>(1) << 20;

} // namespace apsi::oprf
