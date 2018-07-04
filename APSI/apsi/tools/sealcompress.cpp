#include <cstring>
#include "apsi/tools/sealcompress.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/numth.h"
#include "seal/util/mempool.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/uintcore.h"

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
            coeff_mod_prod_ = multiply_uint_uint_mod(
                coeff_mod_prod_, coeff_mod_array[i].value(), coeff_mod_array[0]);
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
                    hatqi = multiply_uint_uint_mod(hatqi, coeff_mod_array[j].value(), 
                        coeff_mod_array[i]);
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
            Ciphertext &destination) const
    {
        auto &coeff_mod_array = parms_.coeff_modulus();
        int coeff_mod_count = coeff_mod_array.size();
        int coeff_count = parms_.poly_modulus_degree();
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
            set_uint_uint(encrypted.data(index), coeff_count, destination.data(index));

            for(int i = 1; i < coeff_mod_count; i++)
            {
                multiply_poly_scalar_coeffmod(
                        encrypted.data(index) + i * coeff_count,
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
                        destination.data(index),
                        temp.get(),
                        coeff_count,
                        coeff_mod_array[0],
                        destination.data(index));
            }

            multiply_poly_scalar_coeffmod(
                    destination.data(index),
                    coeff_count,
                    inv_coeff_mod_prod_, 
                    coeff_mod_array[0], 
                    destination.data(index));
        }
    }

    void CiphertextCompressor::mod_switch(
            const SecretKey &secret_key, 
            SecretKey &destination) const
    {
        int coeff_count = parms_.poly_modulus_degree();

        // Verify parameters.
        if (secret_key.hash_block() != parms_.hash_block())
        {
            throw invalid_argument("secret_key is not valid for encryption parameters");
        }

        // Set destination hash block and resize appropriately
        destination.hash_block() = small_parms_.hash_block();
        destination.data().resize(coeff_count, bits_per_uint64);

        // Set destination value
        set_uint_uint(secret_key.data().data(), coeff_count, destination.data().data());
    }

    void CiphertextCompressor::compressed_save(const seal::Ciphertext &encrypted, 
        std::ostream &stream) const
    {
        int encrypted_size = encrypted.size();
        if(encrypted_size > 2)
        {
            throw invalid_argument("can only compress fully relinearized ciphertexts");
        }
        if (encrypted.hash_block() != small_parms_.hash_block())
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        
        int coeff_count = parms_.poly_modulus_degree();
        int compr_coeff_bit_count = parms_.plain_modulus().bit_count() + 
            get_significant_bit_count(coeff_count);
        int compr_coeff_byte_count = divide_round_up(compr_coeff_bit_count, bits_per_byte);
        int coeff_mod_bit_count = small_parms_.coeff_modulus()[0].bit_count();
        if(compr_coeff_bit_count >= coeff_mod_bit_count)
        {
            encrypted.save(stream);
            return;
        }

        // Write parameter hash
        stream.write(reinterpret_cast<const char*>(&encrypted.hash_block()), 
            sizeof(EncryptionParameters::hash_block_type));

        // Create compressed polynomials
        int compr_data_byte_count = compr_coeff_byte_count * encrypted_size * coeff_count;
        int compr_data_uint64_count = divide_round_up(compr_data_byte_count, bytes_per_uint64);
        Pointer compr_poly(allocate_zero_uint(compr_data_uint64_count, pool_));

        char *compr_poly_writer_head = reinterpret_cast<char*>(compr_poly.get());
        const uint64_t *encrypted_coeff_ptr = encrypted.data(); 
        int encrypted_uint64_count = encrypted_size * encrypted.poly_modulus_degree();
        int bit_shift = bits_per_uint64 - coeff_mod_bit_count;
        for(int i = 0; i < encrypted_uint64_count; i++, encrypted_coeff_ptr++)
        {
            uint64_t shifted_coeff = *encrypted_coeff_ptr << bit_shift;
            memcpy(compr_poly_writer_head, 
                    reinterpret_cast<char*>(&shifted_coeff) + bytes_per_uint64 - compr_coeff_byte_count, 
                    compr_coeff_byte_count); 
            compr_poly_writer_head += compr_coeff_byte_count;
        }

        // Write to stream
        stream.write(reinterpret_cast<const char*>(compr_poly.get()), compr_data_byte_count);
    }

    void CiphertextCompressor::compressed_load(std::istream &stream, 
        seal::Ciphertext &destination) const
    {
        int encrypted_size = destination.size();
        if(encrypted_size > 2)
        {
            throw invalid_argument("can only decompress fully relinearized ciphertexts");
        }
        if (destination.hash_block() != small_parms_.hash_block())
        {
            throw invalid_argument("destination is not valid for encryption parameters");
        }

        int coeff_count = parms_.poly_modulus_degree();
        int compr_coeff_bit_count = parms_.plain_modulus().bit_count() + 
            get_significant_bit_count(coeff_count);
        int compr_coeff_byte_count = divide_round_up(compr_coeff_bit_count, bits_per_byte);
        int coeff_mod_bit_count = small_parms_.coeff_modulus()[0].bit_count();
        if(compr_coeff_bit_count >= coeff_mod_bit_count)
        {
            destination.load(stream);
            return;
        }

        // Read parameter hash
        EncryptionParameters::hash_block_type hash_block;
        stream.read(reinterpret_cast<char*>(&hash_block), 
            sizeof(EncryptionParameters::hash_block_type));

        // If hash is correct then we assume sizes are all known and correct
        if(hash_block != destination.hash_block())
        {
            throw invalid_argument("destination is not valid for loaded ciphertext");
        }

        // Create compressed polynomials
        int compr_data_byte_count = compr_coeff_byte_count * encrypted_size * coeff_count;
        int compr_data_uint64_count = divide_round_up(compr_data_byte_count, bytes_per_uint64);
        Pointer compr_poly(allocate_zero_uint(compr_data_uint64_count, pool_));

        // Read data
        stream.read(reinterpret_cast<char*>(compr_poly.get()), compr_data_byte_count);

        // Finally parse and write to destination
        const char *compr_poly_reader_head = reinterpret_cast<const char*>(compr_poly.get());
        uint64_t *destination_coeff_ptr = destination.data(); 
        int encrypted_uint64_count = encrypted_size * destination.poly_modulus_degree();
        int bit_shift = bits_per_uint64 - coeff_mod_bit_count;
        for(int i = 0; i < encrypted_uint64_count; i++, destination_coeff_ptr++)
        {
            uint64_t shifted_coeff = 0;
            memcpy(reinterpret_cast<char*>(&shifted_coeff), compr_poly_reader_head, 
                compr_coeff_byte_count); 
            *destination_coeff_ptr = shifted_coeff << 
                (bits_per_byte * (bytes_per_uint64 - compr_coeff_byte_count) - bit_shift);
            compr_poly_reader_head += compr_coeff_byte_count;
        }
    }
}
