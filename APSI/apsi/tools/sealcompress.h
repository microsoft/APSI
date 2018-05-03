#pragma once

// STD
#include <vector>

// SEAL
#include "seal/ciphertext.h"
#include "seal/encryptionparams.h"
#include "seal/memorypoolhandle.h"

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
        std::vector<std::uint64_t> coeff_mod_prod_array_;
        std::vector<std::uint64_t> inv_coeff_mod_prod_array_;
    };
}
