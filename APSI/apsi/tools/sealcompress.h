#pragma once

// STD
#include <iostream>

// SEAL
#include "seal/secretkey.h"
#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/evaluator.h"
#include "seal/memorypoolhandle.h"

namespace apsi
{
    class CiphertextCompressor
    {
    public:
        CiphertextCompressor(std::shared_ptr<seal::SEALContext> &seal_context,
            std::shared_ptr<seal::Evaluator> &evaluator,
            const seal::MemoryPoolHandle &pool = seal::MemoryPoolHandle::Global()) :
            pool_(pool), seal_context_(seal_context), evaluator_(evaluator)
        {
        }

        void mod_switch(seal::Ciphertext &encrypted) const;

        inline void mod_switch(
            const seal::Ciphertext &encrypted, seal::Ciphertext &destination) const
        {
            destination = encrypted;
            mod_switch(destination);
        }

        void mod_switch(
                const seal::SecretKey &secret_key, seal::SecretKey &destination) const;

        void compressed_save(const seal::Ciphertext &encrypted, std::ostream &stream) const;

        void compressed_load(std::istream &stream, seal::Ciphertext &destination) const;

    private:
        seal::MemoryPoolHandle pool_;
        std::shared_ptr<seal::SEALContext> seal_context_;
        std::shared_ptr<seal::Evaluator> evaluator_;
    };
}
