// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

// STD
#include <sstream>

// APSI
#include "apsi/network/network_utils.h"

using namespace std;
using namespace seal;
using namespace apsi::network;

namespace apsi
{
    void get_string(string& str, const PublicKey& pub_key)
    {
        stringstream ss;
        pub_key.save(ss);
        str = ss.str();
    }

    void get_string(string& str, const RelinKeys& relin_keys)
    {
        stringstream ss;
        relin_keys.save(ss);
        str = ss.str();
    }

    void get_string(string& str, const Ciphertext& ciphertext)
    {
        stringstream ss;
        ciphertext.save(ss);
        str = ss.str();
    }

    void get_string(string& str, const SmallModulus& sm)
    {
        stringstream ss;
        sm.save(ss);
        str = ss.str();
    }

    void get_public_key(std::shared_ptr<seal::SEALContext> context, seal::PublicKey& pub_key, const std::string& str)
    {
        stringstream ss(str);
        pub_key.load(context, ss);
    }

    void get_relin_keys(std::shared_ptr<seal::SEALContext> context, seal::RelinKeys& relin_keys, const std::string& str, seed128 seeds)
    {
        stringstream ss(str);
        relin_keys.load(context, ss);

        // todo: change that 
        //std::uint64_t seed_lw, seed_hw;
        //uncompressed_stream.read(reinterpret_cast<char*>(&seed_lw), sizeof(std::uint64_t));
        //uncompressed_stream.read(reinterpret_cast<char*>(&seed_hw), sizeof(std::uint64_t));

        
        // Initialize the PRNG factory
        std::shared_ptr<UniformRandomGeneratorFactory> rg = 
            std::make_shared<FastPRNGFactory>(seeds.first, seeds.second);
        // TODO: add the random number generator
        shared_ptr<UniformRandomGenerator> random_a(rg->create());
        seal::RandomToStandardAdapter engine(random_a);

        // Read the dbc
        int decomposition_bit_count = relin_keys.decomposition_bit_count();
        
        // Find which relin elements exist in relin_keys 
        // Make a copy of encryption parameters;
        // at this point we are guaranteed that the parms_id is the same
        // as first_parms_id() for the given context.
        //auto parms(context->context_data()->parms());

        // Set the seeded PRNG
        //parms.set_random_generator(rg);

        // Create SEALContext
        // auto compression_context = SEALContext::Create(parms, false);

        // Create dummy but valid secret key
        // SecretKey sk;
        // sk.data().resize(parms.coeff_modulus().size() * parms.poly_modulus_degree());
        // sk.data().set_zero();
        // sk.parms_id() = parms.parms_id();

        // Create the seed-expanded part of the relin keys
        //KeyGenerator keygen(compression_context, sk);
        //auto exp_relin_keys = keygen.relin_keys(
        //    decomposition_bit_count); 

        // Finally we need to combine exp_relin_keys and relin_keys
        for (std::size_t i = 0; i < relin_keys.data().size(); i++)
        {
            if (relin_keys.data()[i].size())
            {
                for(std::size_t j = 0; j < relin_keys.data()[i].size(); j++)
                {
                    // auto &exp_key_ct = exp_relin_keys.data()[i][j];
                    // uniform coefficients
                   // uint64_t *eval_keys_second = relin_keys.data()[i][j].data(2 * i + 1);

                    

                    // set_poly_coeffs_uniform(context_data, eval_keys_second, random_a);
                    auto &complete_key_ct = relin_keys.data()[i][j];
                    size_t coeff_count = complete_key_ct.poly_modulus_degree(); 
                    size_t coeff_mod_count = complete_key_ct.coeff_mod_count(); 
                    for(std::size_t k = 1; k < complete_key_ct.size(); k += 2)
                    {
                        uint64_t *poly = complete_key_ct.data(k);
                        for (size_t jj = 0; jj < coeff_mod_count; jj++)
                        {   
                            // FIXME
                            uint64_t current_modulus = context->context_data()->parms().coeff_modulus()[jj].value();
                            for (size_t ii = 0; ii < coeff_count; ii++, poly++)
                            {
                                uint64_t new_coeff = (static_cast<uint64_t>(engine()) << 32) + 
                                    static_cast<uint64_t>(engine());
                                *poly = new_coeff % current_modulus; 
                            }
                        }
                        // Copy seed-expanded part to secret-dependent part
                        // util::set_poly_poly(
                        //     exp_key_ct.data(k), 
                        //     complete_key_ct.poly_modulus_degree(), 
                        //     complete_key_ct.coeff_mod_count(), 
                        //     complete_key_ct.data(k));
                    }
                }
            }
        }
    }

    void get_ciphertext(std::shared_ptr<seal::SEALContext> context, seal::Ciphertext& ciphertext, const std::string& str)
    {
        stringstream ss(str);
        ciphertext.load(context, ss);
    }

    void get_small_modulus(seal::SmallModulus& sm, const std::string& str)
    {
        stringstream ss(str);
        sm.load(ss);
    }
}
