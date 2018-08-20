#include <memory>
#include "apsi/tools/sealcompress.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    void CiphertextCompressor::mod_switch(Ciphertext &encrypted) const
    {
        if(!seal_context_->context_data(encrypted.parms_id()))
        {
            throw invalid_argument("encrypted is not valid for the encryption parameters");
        }
        if(encrypted.is_ntt_transformed())
        {
            throw invalid_argument(" cannot be NTT transformed");
        }
        while(encrypted.parms_id() != seal_context_->last_parms_id())
        {
            evaluator_->mod_switch_to_next(encrypted, pool_);
        }
    }

    void CiphertextCompressor::compressed_save(const seal::Ciphertext &encrypted, 
        std::ostream &stream) const
    {
        int encrypted_size = encrypted.size();
        if(encrypted_size > 2)
        {
            throw invalid_argument("can only compress fully relinearized ciphertexts");
        }
        if(!seal_context_->context_data(encrypted.parms_id()))
        {
            throw invalid_argument("encrypted is not valid for the encryption parameters");
        }
        if (encrypted.parms_id() != seal_context_->last_parms_id())
        {
            throw invalid_argument("encrypted is not mod switched to lowest level");
        }
        if(encrypted.is_ntt_transformed())
        {
            throw invalid_argument(" cannot be NTT transformed");
        }

        //auto &context_data = seal_context_->context_data(seal_context_->last_parms_id()).value().get();
        auto& context_data = *seal_context_->context_data(seal_context_->last_parms_id());
        auto &parms = context_data.parms();
    
        int coeff_count = parms.poly_modulus_degree();
        int compr_coeff_bit_count = parms.plain_modulus().bit_count() + 
            get_significant_bit_count(coeff_count);
        int compr_coeff_byte_count = divide_round_up(compr_coeff_bit_count, bits_per_byte);
        int coeff_mod_bit_count = parms.coeff_modulus()[0].bit_count();
        if(compr_coeff_bit_count >= coeff_mod_bit_count)
        {
            encrypted.save(stream);
            return;
        }

        // Write parameter hash
        stream.write(reinterpret_cast<const char*>(&encrypted.parms_id()), 
            sizeof(parms_id_type));

        // Create compressed polynomials
        int compr_data_byte_count = compr_coeff_byte_count * encrypted_size * coeff_count;
        int compr_data_uint64_count = divide_round_up(compr_data_byte_count, bytes_per_uint64);
        auto compr_poly(allocate_zero_uint(compr_data_uint64_count, pool_));

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
        if(!seal_context_->context_data(destination.parms_id()))
        {
            throw invalid_argument("destination is not valid for the encryption parameters");
        }
        if (destination.parms_id() != seal_context_->last_parms_id())
        {
            throw invalid_argument("destination is not mod switched to lowest level");
        }
        if(destination.is_ntt_transformed())
        {
            throw invalid_argument("destination cannot be NTT transformed");
        }

        //auto &context_data = seal_context_->context_data(seal_context_->last_parms_id()).value().get();
        auto& context_data = *seal_context_->context_data(seal_context_->last_parms_id());
        auto &parms = context_data.parms();

        int coeff_count = parms.poly_modulus_degree();
        int compr_coeff_bit_count = parms.plain_modulus().bit_count() + 
            get_significant_bit_count(coeff_count);
        int compr_coeff_byte_count = divide_round_up(compr_coeff_bit_count, bits_per_byte);
        int coeff_mod_bit_count = parms.coeff_modulus()[0].bit_count();
        if(compr_coeff_bit_count >= coeff_mod_bit_count)
        {
            destination.load(stream);
            return;
        }

        // Read parameter hash
        parms_id_type parms_id;
        stream.read(reinterpret_cast<char*>(&parms_id), sizeof(parms_id_type));

        // If hash is correct then we assume sizes are all known and correct
        if(parms_id != destination.parms_id())
        {
            throw invalid_argument("destination is not valid for loaded ciphertext");
        }

        // Create compressed polynomials
        int compr_data_byte_count = compr_coeff_byte_count * encrypted_size * coeff_count;
        int compr_data_uint64_count = divide_round_up(compr_data_byte_count, bytes_per_uint64);
        auto compr_poly(allocate_zero_uint(compr_data_uint64_count, pool_));

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
