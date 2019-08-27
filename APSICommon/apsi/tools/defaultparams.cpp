// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

// STD
#include <vector>

// APSI
#include "apsi/tools/defaultparams.h"
#include "apsi/psiparams.h"

// SEAL
#include "seal/defaultparams.h"
#include "seal/smallmodulus.h"

using namespace std;
using namespace apsi;
using namespace apsi::tools;
using namespace seal;

const PSIParams apsi::tools::default_psi_params(
    const apsi::u64 sender_set_size)
{
    // General PSI parameters
    PSIParams::PSIConfParams psiconf_params;
    {
        // Length of items
        psiconf_params.item_bit_count = 60;

        // Size of the Sender's DB
        psiconf_params.sender_size = sender_set_size;

        // Whether to use an OPRF
        psiconf_params.use_oprf = true;

        // Whether to use labels
        psiconf_params.use_labels = false;

        psiconf_params.sender_bin_size = 0; 

        Log::info("sender bin size default value = %i", psiconf_params.sender_bin_size);
    }

    // Cuckoo hash parameters
    PSIParams::CuckooParams cuckoo_params;
    {
        // Cuckoo hash function count
        cuckoo_params.hash_func_count = 2;

        // Set the hash function seed 
        // 0 for testing purposes. In practice, this is sampled by sender once and for all. 

        cuckoo_params.hash_func_seed = 0;

        // Set max_probe count for Cuckoo hashing
        cuckoo_params.max_probe = 100;
    }

    // Create TableParams and populate.
    PSIParams::TableParams table_params;
    {
        // Log of size of full hash table
        table_params.log_table_size = 9;

        // Number of splits to use
        // Larger means lower depth but bigger S-->R communication
        table_params.split_count =  27;

        // Negative log failure probability for simple hashing
        table_params.binning_sec_level = 40;

        // Window size parameter
        // Larger means lower depth but bigger R-->S communication
        table_params.window_size = 1;
    }

    PSIParams::SEALParams seal_params;
    {
        seal_params.encryption_params.set_poly_modulus_degree(4096);

        vector<SmallModulus> coeff_modulus;
        coeff_modulus = DefaultParams::coeff_modulus_128(seal_params.encryption_params.poly_modulus_degree());
        seal_params.encryption_params.set_coeff_modulus(coeff_modulus);
        seal_params.encryption_params.set_plain_modulus(40961);
        seal_params.decomposition_bit_count = 30;
    }

    PSIParams::ExFieldParams exfield_params;
    {
        // This must be equal to plain_modulus
        exfield_params.characteristic = seal_params.encryption_params.plain_modulus().value();
        exfield_params.degree = 8;
    }


    /*
    Creating the PSIParams class.
    */
    PSIParams params(psiconf_params, table_params, cuckoo_params, seal_params, exfield_params);
    return params;
}
