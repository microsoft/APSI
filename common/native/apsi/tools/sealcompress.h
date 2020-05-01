// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <iostream>
#include <memory>
#include <seal/secretkey.h>
#include <seal/ciphertext.h>
#include <seal/context.h>
#include <seal/evaluator.h>
#include <seal/memorymanager.h>

namespace apsi
{
    class CiphertextCompressor
    {
    public:
        CiphertextCompressor(std::shared_ptr<seal::SEALContext> seal_context,
            seal::MemoryPoolHandle pool = seal::MemoryPoolHandle::Global()) :
            pool_(std::move(pool)),
            seal_context_(std::move(seal_context)),
            evaluator_(seal_context_)
        {
        }

        void mod_switch(seal::Ciphertext &encrypted);

        inline void mod_switch(const seal::Ciphertext &encrypted, seal::Ciphertext &destination)
        {
            destination = encrypted;
            mod_switch(destination);
        }

        void compressed_save(const seal::Ciphertext &encrypted, std::ostream &stream);
        void compressed_load(std::istream &stream, seal::Ciphertext &destination);

    private:
        seal::MemoryPoolHandle pool_;
        std::shared_ptr<seal::SEALContext> seal_context_;
        seal::Evaluator evaluator_;
    }; // class CiphertextCompressor
} // namespace apsi
