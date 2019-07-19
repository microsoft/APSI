// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#pragma once

// STD
#include <iostream>

// SEAL
#include "seal/secretkey.h"
#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/evaluator.h"

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

        inline void mod_switch(const seal::Ciphertext &encrypted, seal::Ciphertext &destination) const
        {
            destination = encrypted;
            mod_switch(destination);
        }

        void compressed_save(const seal::Ciphertext &encrypted, std::ostream &stream) const;
        void compressed_load(std::istream &stream, seal::Ciphertext &destination) const;

    private:
        seal::MemoryPoolHandle pool_;
        std::shared_ptr<seal::SEALContext> seal_context_;
        std::shared_ptr<seal::Evaluator> evaluator_;
    };
}
