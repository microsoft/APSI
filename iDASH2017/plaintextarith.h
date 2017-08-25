#pragma once

#include "plaintext.h"
#include "util/polymodulus.h"
#include "smallmodulus.h"
#include "memorypoolhandle.h"

namespace idash
{
    void multiply(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod,
        seal::Plaintext &result, seal::MemoryPoolHandle pool = seal::MemoryPoolHandle::acquire_global());

    seal::Plaintext multiply(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod, seal::MemoryPoolHandle pool = seal::MemoryPoolHandle::acquire_global())
    {
        seal::Plaintext result;
        multiply(plaintext1, plaintext2, poly_mod, coeff_mod, result, pool);
        return result;
    }

    void add(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod,
        seal::Plaintext &result, seal::MemoryPoolHandle pool = seal::MemoryPoolHandle::acquire_global());

    seal::Plaintext add(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod,
        seal::MemoryPoolHandle pool = seal::MemoryPoolHandle::acquire_global())
    {
        seal::Plaintext result;
        add(plaintext1, plaintext2, poly_mod, coeff_mod, result, pool);
        return result;
    }

    void sub(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod,
        seal::Plaintext &result, seal::MemoryPoolHandle pool = seal::MemoryPoolHandle::acquire_global());

    seal::Plaintext sub(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod,
        seal::MemoryPoolHandle pool = seal::MemoryPoolHandle::acquire_global())
    {
        seal::Plaintext result;
        sub(plaintext1, plaintext2, poly_mod, coeff_mod, result, pool);
        return result;
    }

    
}