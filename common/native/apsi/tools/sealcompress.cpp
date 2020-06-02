// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "apsi/tools/sealcompress.h"
#include <memory>
#include "apsi/apsidefines.h"
#include "apsi/logging/log.h"

using namespace std;
using namespace seal;

namespace apsi
{
    void CiphertextCompressor::mod_switch(Ciphertext &encrypted)
    {
        if (!seal_context_->get_context_data(encrypted.parms_id()))
        {
            throw invalid_argument("encrypted is not valid for the encryption parameters");
        }
        if (encrypted.is_ntt_form())
        {
            throw invalid_argument(" cannot be NTT transformed");
        }
        while (encrypted.parms_id() != seal_context_->last_parms_id())
        {
            evaluator_.mod_switch_to_next_inplace(encrypted, pool_);
        }
    }

    void CiphertextCompressor::compressed_save(const Ciphertext &encrypted, ostream &stream)
    {
        size_t encrypted_size = encrypted.size();
        if (encrypted_size > 2)
        {
            throw invalid_argument("can only compress fully relinearized ciphertexts");
        }
        if (!seal_context_->get_context_data(encrypted.parms_id()))
        {
            throw invalid_argument("encrypted is not valid for the encryption parameters");
        }
        if (encrypted.parms_id() != seal_context_->last_parms_id())
        {
            throw invalid_argument("encrypted is not mod switched to lowest level");
        }
        if (encrypted.is_ntt_form())
        {
            throw invalid_argument(" cannot be NTT transformed");
        }

        auto &context_data = *seal_context_->get_context_data(seal_context_->last_parms_id());
        auto &parms = context_data.parms();

        size_t coeff_count = parms.poly_modulus_degree();
        int compr_coeff_bit_count = parms.plain_modulus().bit_count() + util::get_significant_bit_count(coeff_count);
        size_t compr_coeff_byte_count = static_cast<size_t>(util::divide_round_up(compr_coeff_bit_count, util::bits_per_byte));
        int coeff_mod_bit_count = parms.coeff_modulus()[0].bit_count();
        if (compr_coeff_bit_count >= coeff_mod_bit_count)
        {
            encrypted.save(stream);
            return;
        }

        // Write parameter hash
        stream.write(reinterpret_cast<const char *>(&encrypted.parms_id()), sizeof(parms_id_type));

        // Create compressed polynomials
        int compr_data_byte_count = static_cast<int>(compr_coeff_byte_count * encrypted_size * coeff_count);
        int compr_data_uint64_count =
            util::divide_round_up(compr_data_byte_count, util::bytes_per_uint64);
        auto compr_poly(util::allocate_zero_uint(static_cast<size_t>(compr_data_uint64_count), pool_));

        char *compr_poly_writer_head = reinterpret_cast<char *>(compr_poly.get());
        const u64 *encrypted_coeff_ptr = encrypted.data();
        size_t encrypted_uint64_count = encrypted_size * encrypted.poly_modulus_degree();
        logging::Log::debug(
            "COMPRESSOR: compressing %i uint64s into %i", encrypted_uint64_count, compr_data_uint64_count);

        int bit_shift = util::bits_per_uint64 - coeff_mod_bit_count;
        logging::Log::debug("bit shift =  %i", bit_shift);

        for (size_t i = 0; i < encrypted_uint64_count; i++, encrypted_coeff_ptr++)
        {
            u64 shifted_coeff = *encrypted_coeff_ptr << bit_shift;
            memcpy(
                compr_poly_writer_head,
                reinterpret_cast<char *>(&shifted_coeff) + static_cast<size_t>(util::bytes_per_uint64) - compr_coeff_byte_count,
                compr_coeff_byte_count);
            compr_poly_writer_head += compr_coeff_byte_count;
        }

        // Write to stream
        stream.write(reinterpret_cast<const char *>(compr_poly.get()), static_cast<streamsize>(compr_data_byte_count));
    }

    void CiphertextCompressor::compressed_load(istream &stream, Ciphertext &destination)
    {
        size_t encrypted_size = destination.size();

        // Resize destination if necessary. If destination is a newly created Ciphertext,
        // its size will be zero.
        if (encrypted_size == 0)
        {
            encrypted_size = 2;
            destination.resize(seal_context_, seal_context_->last_parms_id(), encrypted_size);
        }

        if (encrypted_size > 2)
        {
            throw invalid_argument("can only decompress fully relinearized ciphertexts");
        }
        if (!seal_context_->get_context_data(destination.parms_id()))
        {
            throw invalid_argument("destination is not valid for the encryption parameters");
        }
        if (destination.parms_id() != seal_context_->last_parms_id())
        {
            throw invalid_argument("destination is not mod switched to lowest level");
        }
        if (destination.is_ntt_form())
        {
            throw invalid_argument("destination cannot be NTT transformed");
        }

        auto &context_data = *seal_context_->get_context_data(seal_context_->last_parms_id());
        auto &parms = context_data.parms();

        size_t coeff_count = parms.poly_modulus_degree();
        int compr_coeff_bit_count = parms.plain_modulus().bit_count() + util::get_significant_bit_count(coeff_count);
        size_t compr_coeff_byte_count = static_cast<size_t>(util::divide_round_up(compr_coeff_bit_count, util::bits_per_byte));
        int coeff_mod_bit_count = parms.coeff_modulus()[0].bit_count();
        if (compr_coeff_bit_count >= coeff_mod_bit_count)
        {
            destination.load(seal_context_, stream);
            return;
        }

        // Read parameter hash
        parms_id_type parms_id;
        stream.read(reinterpret_cast<char *>(&parms_id), sizeof(parms_id_type));

        // If hash is correct then we assume sizes are all known and correct
        if (parms_id != destination.parms_id())
        {
            throw invalid_argument("destination is not valid for loaded ciphertext");
        }

        // Create compressed polynomials
        int compr_data_byte_count = static_cast<int>(compr_coeff_byte_count * encrypted_size * coeff_count);
        int compr_data_uint64_count =
            util::divide_round_up(compr_data_byte_count, util::bytes_per_uint64);
        auto compr_poly(util::allocate_zero_uint(static_cast<size_t>(compr_data_uint64_count), pool_));

        // Read data
        stream.read(reinterpret_cast<char *>(compr_poly.get()), compr_data_byte_count);

        // Finally parse and write to destination
        const char *compr_poly_reader_head = reinterpret_cast<const char *>(compr_poly.get());
        u64 *destination_coeff_ptr = destination.data();
        size_t encrypted_uint64_count = encrypted_size * destination.poly_modulus_degree();
        int bit_shift = util::bits_per_uint64 - coeff_mod_bit_count;
        for (size_t i = 0; i < encrypted_uint64_count; i++, destination_coeff_ptr++)
        {
            u64 shifted_coeff = 0;
            memcpy(reinterpret_cast<char *>(&shifted_coeff), compr_poly_reader_head, compr_coeff_byte_count);
            *destination_coeff_ptr =
                shifted_coeff << (util::bits_per_byte * (util::bytes_per_uint64 - static_cast<int>(compr_coeff_byte_count)) - bit_shift);
            compr_poly_reader_head += compr_coeff_byte_count;
        }
    }
} // namespace apsi
