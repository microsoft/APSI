#include "plaintextarith.h"
#include "util/mempool.h"
#include "util/polycore.h"
#include "util/polyfftmultsmallmod.h"
#include "util/polyarithsmallmod.h"

using namespace seal;
using namespace seal::util;

namespace apsi
{
    ConstPointer duplicate_poly_if_needed(const Plaintext &poly, int new_coeff_count, bool force, MemoryPool &pool)
    {
        return util::duplicate_poly_if_needed(poly.pointer(), poly.coeff_count(), 1, new_coeff_count, 1, force, pool);
    }

    ConstPointer duplicate_poly_if_needed(const BigPoly &poly, bool force, MemoryPool &pool)
    {
        return util::duplicate_if_needed(poly.pointer(), poly.coeff_count() * poly.coeff_uint64_count(), force, pool);
    }

    void resize_destination_if_needed(Plaintext &destination, int coeff_count)
    {
        int dest_coeff_count = destination.coeff_count();
        if (dest_coeff_count < coeff_count)
        {
            destination.resize(coeff_count);
        }
        else if (dest_coeff_count > coeff_count)
        {
            destination.set_zero(coeff_count);
        }
    }

    void multiply(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod, seal::Plaintext &result, MemoryPoolHandle pool)
    {
        int coeff_count = poly_mod.coeff_count();
        int coeff_bit_count = coeff_mod.bit_count();
        int coeff_uint64_count = coeff_mod.uint64_count();

        // Get pointer to inputs (duplicated and resized if needed).
        ConstPointer poly1ptr = duplicate_poly_if_needed(plaintext1, coeff_count, plaintext1.pointer() == result.pointer(), pool);
        ConstPointer poly2ptr = duplicate_poly_if_needed(plaintext2, coeff_count, plaintext2.pointer() == result.pointer(), pool);

        // Verify destination size.
        resize_destination_if_needed(result, coeff_count);

        // Multiply polynomials.
        nussbaumer_multiply_poly_poly_coeffmod(poly1ptr.get(), poly2ptr.get(), poly_mod.coeff_count_power_of_two(), coeff_mod, result.pointer(), pool);
    }

    void add(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod, seal::Plaintext &result, seal::MemoryPoolHandle pool)
    {
        // Verify parameters.
        int coeff_count = poly_mod.coeff_count();
        int coeff_bit_count = coeff_mod.bit_count();
        int coeff_uint64_count = coeff_mod.uint64_count();

        // Get pointer to inputs (duplicated and resized if needed).
        ConstPointer poly1ptr = duplicate_poly_if_needed(plaintext1, coeff_count, plaintext1.pointer() == result.pointer(), pool);
        ConstPointer poly2ptr = duplicate_poly_if_needed(plaintext2, coeff_count, plaintext2.pointer() == result.pointer(), pool);

        // Verify destination size.
        resize_destination_if_needed(result, coeff_count);

        // Add polynomials.
        add_poly_poly_coeffmod(poly1ptr.get(), poly2ptr.get(), coeff_count, coeff_mod, result.pointer());
    }

    void sub(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod, seal::Plaintext &result, seal::MemoryPoolHandle pool)
    {
        // Verify parameters.
        int coeff_count = poly_mod.coeff_count();
        int coeff_bit_count = coeff_mod.bit_count();
        int coeff_uint64_count = coeff_mod.uint64_count();

        // Get pointer to inputs (duplicated and resized if needed).
        ConstPointer poly1ptr = duplicate_poly_if_needed(plaintext1, coeff_count, plaintext1.pointer() == result.pointer(), pool);
        ConstPointer poly2ptr = duplicate_poly_if_needed(plaintext2, coeff_count, plaintext2.pointer() == result.pointer(), pool);

        // Verify destination size.
        resize_destination_if_needed(result, coeff_count);

        // Add polynomials.
        sub_poly_poly_coeffmod(poly1ptr.get(), poly2ptr.get(), coeff_count, coeff_mod, result.pointer());
    }
}