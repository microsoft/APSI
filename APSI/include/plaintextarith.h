#pragma once

#include "seal/plaintext.h"
#include "seal/util/polymodulus.h"
#include "seal/smallmodulus.h"
#include "seal/memorypoolhandle.h"

namespace apsi
{
    void multiply(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod,
        seal::Plaintext &result, seal::MemoryPoolHandle pool = seal::MemoryPoolHandle::Global());

    inline seal::Plaintext multiply(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod, seal::MemoryPoolHandle pool = seal::MemoryPoolHandle::Global())
    {
        seal::Plaintext result;
        multiply(plaintext1, plaintext2, poly_mod, coeff_mod, result, pool);
        return result;
    }

    void add(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod,
        seal::Plaintext &result, seal::MemoryPoolHandle pool = seal::MemoryPoolHandle::Global());

    inline seal::Plaintext add(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod,
        seal::MemoryPoolHandle pool = seal::MemoryPoolHandle::Global())
    {
        seal::Plaintext result;
        add(plaintext1, plaintext2, poly_mod, coeff_mod, result, pool);
        return result;
    }

    void sub(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod,
        seal::Plaintext &result, seal::MemoryPoolHandle pool = seal::MemoryPoolHandle::Global());

    inline seal::Plaintext sub(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod,
        seal::MemoryPoolHandle pool = seal::MemoryPoolHandle::Global())
    {
        seal::Plaintext result;
        sub(plaintext1, plaintext2, poly_mod, coeff_mod, result, pool);
        return result;
    }

    
}