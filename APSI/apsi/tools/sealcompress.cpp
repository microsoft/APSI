#include "apsi/tools/sealcompress.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/numth.h"
#include "seal/util/mempool.h"
#include "seal/util/polyarithsmallmod.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    CiphertextCompressor::CiphertextCompressor(
            const EncryptionParameters &parms,
            const MemoryPoolHandle &pool) :
        pool_(pool),
        parms_(parms),
        small_parms_(parms_)
    {
        auto &coeff_mod_array = parms_.coeff_modulus();
        int coeff_mod_count = coeff_mod_array.size();
        coeff_mod_prod_array_.clear();
        coeff_mod_prod_array_.reserve(coeff_mod_count - 1); 

        // Change the coefficient modulus to single modulus size
        small_parms_.set_coeff_modulus({ coeff_mod_array[0] });

        // Compute punctured modulus product
        coeff_mod_prod_ = 1;
        for (int i = 1; i < coeff_mod_count; i++)
        {
            coeff_mod_prod_ = multiply_uint_uint_mod(coeff_mod_prod_, coeff_mod_array[i].value(), coeff_mod_array[0]);
        }

        // Compute inverse of coeff_mod_prod_
        if(!try_mod_inverse(coeff_mod_prod_, coeff_mod_array[0].value(), inv_coeff_mod_prod_))
        {
            throw invalid_argument("coefficient modulus is invalid");
        }

        // Compute hat{q1} * qi^{-1} (mod q1)
        for (int i = 1; i < coeff_mod_count; i++)
        {
            uint64_t inv_qi_modq1;
            if(!try_mod_inverse(coeff_mod_array[i].value(), coeff_mod_array[0].value(), inv_qi_modq1))
            {
                throw invalid_argument("coefficient modulus is invalid");
            }
            coeff_mod_prod_array_.emplace_back(
                    multiply_uint_uint_mod(coeff_mod_prod_, inv_qi_modq1, coeff_mod_array[0]));
        }

        inv_coeff_mod_prod_array_.clear();
        inv_coeff_mod_prod_array_.reserve(coeff_mod_count - 1); 
        for(int i = 1; i < coeff_mod_count; i++)
        {
            // Compute hat{qi} (mod qi)
            uint64_t hatqi = 1;
            for(int j = 1; j < coeff_mod_count; j++)
            {
                if(j != i)
                {
                    hatqi = multiply_uint_uint_mod(hatqi, coeff_mod_array[j].value(), coeff_mod_array[i]);
                }
            }
            
            // Compute inverse mod qi
            uint64_t inv_hatqi;
            if(!try_mod_inverse(hatqi, coeff_mod_array[i].value(), inv_hatqi))
            {
                throw invalid_argument("coefficient modulus is invalid");
            }

            inv_coeff_mod_prod_array_.emplace_back(inv_hatqi);
        }
    }

    void CiphertextCompressor::mod_switch(
            const Ciphertext &encrypted, 
            Ciphertext &destination)
    {
        auto &coeff_mod_array = parms_.coeff_modulus();
        int coeff_mod_count = coeff_mod_array.size();
        int coeff_count = parms_.poly_modulus().coeff_count();
        int encrypted_size = encrypted.size();

        // Verify parameters.
        if (encrypted.hash_block() != parms_.hash_block())
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (destination.hash_block() != small_parms_.hash_block())
        {
            throw invalid_argument("destination is not valid for encryption parameters");
        }

        Pointer temp(allocate_uint(coeff_count, pool_));
        for(int index = 0; index < encrypted_size; index++)
        {
            // Set destination to (c1 mod q1, c2 mod q1)
            set_uint_uint(encrypted.pointer(index), coeff_count, destination.mutable_pointer(index));

            for(int i = 1; i < coeff_mod_count; i++)
            {
                multiply_poly_scalar_coeffmod(
                        encrypted.pointer(index) + i * coeff_count,
                        coeff_count,
                        inv_coeff_mod_prod_array_[i - 1], 
                        coeff_mod_array[i], 
                        temp.get());
                multiply_poly_scalar_coeffmod(
                        temp.get(), 
                        coeff_count, 
                        coeff_mod_prod_array_[i - 1], 
                        coeff_mod_array[0],
                        temp.get());
                negate_poly_coeffmod(
                        temp.get(),
                        coeff_count,
                        coeff_mod_array[0],
                        temp.get());
                add_poly_poly_coeffmod(
                        destination.pointer(index),
                        temp.get(),
                        coeff_count,
                        coeff_mod_array[0],
                        destination.mutable_pointer(index));
            }

            multiply_poly_scalar_coeffmod(
                    destination.pointer(index),
                    coeff_count,
                    inv_coeff_mod_prod_, 
                    coeff_mod_array[0], 
                    destination.mutable_pointer(index));
        }
    }

    void CiphertextCompressor::mod_switch(
            const SecretKey &secret_key, 
            SecretKey &destination)
    {
        int coeff_count = parms_.poly_modulus().coeff_count();

        // Verify parameters.
        if (secret_key.hash_block() != parms_.hash_block())
        {
            throw invalid_argument("secret_key is not valid for encryption parameters");
        }

        // Set destination hash block and resize appropriately
        destination.mutable_hash_block() = small_parms_.hash_block();
        destination.mutable_data().resize(coeff_count, bits_per_uint64);

        // Set destination value
        set_uint_uint(secret_key.data().pointer(), coeff_count, destination.mutable_data().pointer());
    }
}
