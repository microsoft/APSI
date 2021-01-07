// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <vector>
#include <utility>

// APSI
#include "sender/sender_utils.h"
#include "apsi/logging/log.h"

// SEAL
#include "seal/modulus.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::logging;

unique_ptr<PSIParams> build_psi_params(const CLP& cmd)
{
    PSIParams::ItemParams item_params;
    item_params.felts_per_item = cmd.felts_per_item();

    PSIParams::TableParams table_params;
    table_params.table_size = cmd.table_size();
    table_params.max_items_per_bin = cmd.max_items_per_bin();
    table_params.hash_func_count = cmd.hash_func_count();

    PSIParams::QueryParams query_params;
    query_params.query_powers = cmd.query_powers();

    PSIParams::SEALParams seal_params;
    try
    {
        seal_params.set_poly_modulus_degree(cmd.poly_modulus_degree());
        seal_params.set_coeff_modulus(
            CoeffModulus::Create(seal_params.poly_modulus_degree(), cmd.coeff_modulus_bits()));
        if (!cmd.plain_modulus().is_zero())
        {
            seal_params.set_plain_modulus(cmd.plain_modulus());
        }
        else
        {
            seal_params.set_plain_modulus(
                PlainModulus::Batching(seal_params.poly_modulus_degree(), cmd.plain_modulus_bits()));
        }
    }
    catch (const exception &ex)
    {
        APSI_LOG_ERROR("Microsoft SEAL threw an exception setting up SEALParams: " << ex.what());
        return nullptr;
    }

    unique_ptr<PSIParams> params;
    try
    {
        params = make_unique<PSIParams>(item_params, table_params, query_params, seal_params);
    }
    catch (const exception &ex)
    {
        APSI_LOG_ERROR("APSI threw an exception creating PSIParams: " << ex.what());
        return nullptr;
    }

    return move(params);
}
