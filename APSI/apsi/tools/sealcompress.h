#pragma once

// STD
#include <vector>
#include <iostream>

// SEAL
#include "seal/ciphertext.h"
#include "seal/secretkey.h"
#include "seal/encryptionparams.h"
#include "seal/memorypoolhandle.h"
#include "seal/util/smallntt.h"
#include "seal/util/globals.h"

namespace apsi
{
    class CiphertextCompressor
    {
    public:
        CiphertextCompressor(const seal::EncryptionParameters &parms,
                const seal::MemoryPoolHandle &pool = seal::MemoryPoolHandle::Global());

        void mod_switch(
                const seal::Ciphertext &encrypted, 
                seal::Ciphertext &destination) const;

        void mod_switch(
                const seal::SecretKey &secret_key, 
                seal::SecretKey &destination) const;

        inline seal::SecretKey mod_switch(const seal::SecretKey &secret_key)
        {
            seal::SecretKey result;
            mod_switch(secret_key, result);
            return result;
        }

        void compressed_save(const seal::Ciphertext &encrypted, std::ostream &stream) const;

        void compressed_load(std::istream &stream, seal::Ciphertext &destination) const;

        inline const seal::EncryptionParameters &parms() const
        {
            return parms_;
        }

        inline const seal::EncryptionParameters &small_parms() const
        {
            return small_parms_;
        }

    private:
        seal::MemoryPoolHandle pool_;
        seal::EncryptionParameters parms_{seal::scheme_type::BFV};
        seal::EncryptionParameters small_parms_{seal::scheme_type::BFV};

        // Product of all moduli except q1
        std::uint64_t coeff_mod_prod_;

        // Inverse of coeff_mod_prod_ mod q1
        std::uint64_t inv_coeff_mod_prod_;

        // Products q2*...*qk / qi mod q1 for i >= 2
        std::vector<std::uint64_t> coeff_mod_prod_array_;

        // Products (q2*...*qk / qi) mod qi for i >= 2
        std::vector<std::uint64_t> inv_coeff_mod_prod_array_;
    };
}
