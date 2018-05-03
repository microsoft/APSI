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
            const seal::EncryptionParameters &parms,
            const seal::MemoryPoolHandle &pool) :
        pool_(pool),
        parms_(parms),
        small_parms_(parms)
    {
        // Change the coefficient modulus to single modulus size
        small_parms_.set_coeff_modulus({ parms_.coeff_modulus()[0] });

        auto &coeff_mod_array = parms_.coeff_modulus();
        int coeff_mod_count = coeff_mod_array.size();
        coeff_mod_prod_array_.clear();
        coeff_mod_prod_array_.reserve(coeff_mod_count - 1); 

        // Compute punctured modulus product
        uint64_t hatq1 = 1;
        for (int i = 1; i < coeff_mod_count; i++)
        {
            hatq1 = multiply_uint_uint_mod(hatq1, coeff_mod_array[i].value(), coeff_mod_array[0]);
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
                    multiply_uint_uint_mod(hatq1, inv_qi_modq1, coeff_mod_array[0]));
        }

        // Compute (hat{qi}/q1)^{-1} = (hat{q1}/qi)^{-1} (mod qi) for 2 <= i
        inv_coeff_mod_prod_array_.clear();
        inv_coeff_mod_prod_array_.reserve(coeff_mod_count - 1); 
        for(int i = 1; i < coeff_mod_count; i++)
        {
            // Compute hat{q} (mod qi)
            uint64_t hatqi = 1;
            for(int j = 0; j < coeff_mod_count; j++)
            {
                if(i != j)
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

            // Multiply q1
            inv_coeff_mod_prod_array_.emplace_back(
                    multiply_uint_uint_mod(inv_hatqi, coeff_mod_array[0].value(), coeff_mod_array[i]));
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

        // Set destination to (c1 mod q1, c2 mod q1)
        for(int index = 0; index < encrypted_size; index++)
        {
            set_poly_poly(encrypted.pointer(index), coeff_count, 1, destination.mutable_pointer(index));
        }

        Pointer temp(allocate_uint(coeff_count, pool_));
        for(int index = 0; index < encrypted_size; index++)
        {
            for(int i = 1; i < coeff_mod_count; i++)
            {
                multiply_poly_scalar_coeffmod(
                        encrypted.pointer(index) + i * coeff_count,
                        coeff_count,
                        inv_coeff_mod_prod_array_[i - 1], 
                        coeff_mod_array[i], 
                        temp.get());

                for(int j = 0; j < coeff_count; j++)
                {
                    modulo_uint_inplace(temp.get() + j, 1, coeff_mod_array[0]);
                }

                multiply_poly_scalar_coeffmod(
                        temp.get(), 
                        coeff_count, 
                        coeff_mod_prod_array_[i - 1], 
                        coeff_mod_array[0],
                        temp.get());
                negate_poly_coeffmod(
                        temp.get(),
                        coeff_count,
                        coeff_mod_prod_array_[0],
                        temp.get());
                add_poly_poly_coeffmod(
                        destination.pointer(index),
                        temp.get(),
                        coeff_count,
                        coeff_mod_array[0],
                        destination.mutable_pointer(index));
            }
        }
    }
}
