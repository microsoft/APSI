// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <vector>

// APSI
#include "senderutils.h"
#include "clp.h"
#include "apsi/psiparams.h"

// SEAL
// #include "seal/defaultparams.h"
#include "seal/smallmodulus.h"


using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::tools;
using namespace apsi::logging;


const PSIParams apsi::tools::build_psi_params(
    const CLP& cmd,
    const apsi::u64 sender_set_size)
{
    // General PSI parameters
    PSIParams::PSIConfParams psiconf_params;
    {
        // Length of items
        psiconf_params.item_bit_count = cmd.item_bit_length();

        // Size of the Sender's DB
        psiconf_params.sender_size = sender_set_size;

        // Whether to use an OPRF
        psiconf_params.use_oprf = cmd.use_oprf();

        // Whether to use labels
        psiconf_params.use_labels = cmd.use_labels();

        // Whether to use fast membership (single item query)
        psiconf_params.use_fast_membership = cmd.use_fast_memberhip();

        // Number of chunks to use
        psiconf_params.num_chunks = cmd.num_chunks();

        // Sender bin size
        psiconf_params.sender_bin_size = cmd.sender_bin_size();

        // Length of items after OPRF
        psiconf_params.item_bit_length_used_after_oprf = cmd.item_bit_length_used_after_oprf();

        Log::debug("item bit length after oprf when initializing = %i", psiconf_params.item_bit_length_used_after_oprf); 
    }

    // Cuckoo hash parameters
    PSIParams::CuckooParams cuckoo_params;
    {
        // Cuckoo hash function count
        cuckoo_params.hash_func_count = cmd.hash_func_count();

        // Set the hash function seed
        cuckoo_params.hash_func_seed = 0;

        // Set max_probe count for Cuckoo hashing
        cuckoo_params.max_probe = 100;
    }

    // Create TableParams and populate.
    PSIParams::TableParams table_params;
    {
        // Log of size of full hash table
        table_params.log_table_size = cmd.log_table_size();

        // Number of splits to use
        // Larger means lower depth but bigger S-->R communication
        table_params.split_size = cmd.split_size();

        table_params.split_count = cmd.split_count();

        // Negative log failure probability for simple hashing
        table_params.binning_sec_level = cmd.sec_level();

        // Window size parameter
        // Larger means lower depth but bigger R-->S communication
        table_params.window_size = cmd.window_size();

        // By default split_count will be adjusted after setting data
        table_params.dynamic_split_count = true;
    }

    PSIParams::SEALParams seal_params;
    {
        seal_params.encryption_params.set_poly_modulus_degree(cmd.poly_modulus());

        vector<SmallModulus> coeff_modulus;
        auto coeff_mod_bit_vector = cmd.coeff_modulus();

        if (coeff_mod_bit_vector.size() == 0)
        {
            coeff_modulus = CoeffModulus::BFVDefault(seal_params.encryption_params.poly_modulus_degree());
        }
        else
        {
            vector<int> coeff_mod_bit_vector_int(coeff_mod_bit_vector.size());
            for (int i = 0; i < coeff_mod_bit_vector.size(); i++)
            {
                coeff_mod_bit_vector_int[i] = (int)coeff_mod_bit_vector[i];
            }

            coeff_modulus = CoeffModulus::Create(seal_params.encryption_params.poly_modulus_degree(), coeff_mod_bit_vector_int);
        }

        seal_params.encryption_params.set_coeff_modulus(coeff_modulus);
        seal_params.encryption_params.set_plain_modulus(cmd.plain_modulus());

        /** Note: now this maximal supported degree for a given set of SEAL parameters is 
        hardcoded. It be better to give a formula.
        */
        if (cmd.poly_modulus() >= 4096 && cmd.plain_modulus() <= 40961)
        {
            seal_params.max_supported_degree = 4;
        }
        else
        {
            seal_params.max_supported_degree = 1; 
        }

        seal_params.max_supported_degree = 2; // for debugging
        Log::debug("setting maximal supported degree to %i", seal_params.max_supported_degree);
    }

    PSIParams::ExFieldParams exfield_params;
    {
        // This must be equal to plain_modulus
        exfield_params.characteristic = seal_params.encryption_params.plain_modulus().value();
        exfield_params.degree = cmd.exfield_degree();
    }

    /*
    Creating the PSIParams class.
    */
    PSIParams params(psiconf_params, table_params, cuckoo_params, seal_params, exfield_params);
    
    return params;
}
