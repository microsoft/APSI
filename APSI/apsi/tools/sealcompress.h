#pragma once

// STD
#include <vector>

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
                seal::Ciphertext &destination);

        void mod_switch(
                const seal::SecretKey &secret_key, 
                seal::SecretKey &destination);

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
        seal::EncryptionParameters parms_;
        seal::EncryptionParameters small_parms_;

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
