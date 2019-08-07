// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

// STD
#include <vector>

// APSI
#include "senderutils.h"
#include "clp.h"
#include "apsi/psiparams.h"

// SEAL
#include "seal/defaultparams.h"
#include "seal/smallmodulus.h"


using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::tools;


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

		psiconf_params.num_chunks = cmd.num_chunks();

		psiconf_params.sender_bin_size = cmd.sender_bin_size();
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
        table_params.split_count = cmd.split_count();

        // Negative log failure probability for simple hashing
        table_params.binning_sec_level = cmd.sec_level();

        // Window size parameter
        // Larger means lower depth but bigger R-->S communication
        table_params.window_size = cmd.window_size();
    }

    PSIParams::SEALParams seal_params;
    {
        seal_params.encryption_params.set_poly_modulus_degree(cmd.poly_modulus());

        vector<SmallModulus> coeff_modulus;
        auto coeff_mod_bit_vector = cmd.coeff_modulus();

        if (coeff_mod_bit_vector.size() == 0)
        {
            coeff_modulus = DefaultParams::coeff_modulus_128(seal_params.encryption_params.poly_modulus_degree());
        }
        else
        {
            unordered_map<u64, size_t> mods_added;
            for (auto bit_size : coeff_mod_bit_vector)
            {
                switch (bit_size)
                {
                case 30:
                    coeff_modulus.emplace_back(DefaultParams::small_mods_30bit(static_cast<int>(mods_added[bit_size])));
                    mods_added[bit_size]++;
                    break;

                case 40:
                    coeff_modulus.emplace_back(DefaultParams::small_mods_40bit(static_cast<int>(mods_added[bit_size])));
                    mods_added[bit_size]++;
                    break;

                case 50:
                    coeff_modulus.emplace_back(DefaultParams::small_mods_50bit(static_cast<int>(mods_added[bit_size])));
                    mods_added[bit_size]++;
                    break;

                case 60:
                    coeff_modulus.emplace_back(DefaultParams::small_mods_60bit(static_cast<int>(mods_added[bit_size])));
                    mods_added[bit_size]++;
                    break;

                default:
                    throw invalid_argument("invalid coeff modulus bit count");
                }
            }
        }
        seal_params.encryption_params.set_coeff_modulus(coeff_modulus);
        seal_params.encryption_params.set_plain_modulus(cmd.plain_modulus());

        seal_params.decomposition_bit_count = cmd.dbc();
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
