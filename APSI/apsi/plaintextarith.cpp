#include "apsi/plaintextarith.h"
#include "seal/util/mempool.h"
#include "seal/util/polycore.h"
#include "seal/util/polyfftmultsmallmod.h"
#include "seal/util/polyarithsmallmod.h"

using namespace seal;
using namespace seal::util;

namespace apsi
{
    ConstPointer<std::uint64_t> duplicate_poly_if_needed(const Plaintext &poly, size_t new_coeff_count, bool force, MemoryPool &pool)
    {
        return util::duplicate_poly_if_needed(poly.data(), poly.coeff_count(), 1, new_coeff_count, 1, force, pool);
    }

    ConstPointer<std::uint64_t> duplicate_poly_if_needed(const BigPoly &poly, bool force, MemoryPool &pool)
    {
        return util::duplicate_if_needed(poly.data(), poly.coeff_count() * poly.coeff_uint64_count(), force, pool);
    }

    void resize_destination_if_needed(Plaintext &destination, size_t coeff_count)
    {
        size_t dest_coeff_count = destination.coeff_count();
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
        size_t coeff_count = poly_mod.coeff_count();
        int coeff_bit_count = coeff_mod.bit_count();
        size_t coeff_uint64_count = coeff_mod.uint64_count();

        // Get pointer to inputs (duplicated and resized if needed).
        auto poly1ptr = duplicate_poly_if_needed(plaintext1, coeff_count, plaintext1.data() == result.data(), pool);
        auto poly2ptr = duplicate_poly_if_needed(plaintext2, coeff_count, plaintext2.data() == result.data(), pool);

        // Verify destination size.
        resize_destination_if_needed(result, coeff_count);

        // Multiply polynomials.
        nussbaumer_multiply_poly_poly_coeffmod(poly1ptr.get(), poly2ptr.get(), poly_mod.coeff_count_power_of_two(), coeff_mod, result.data(), pool);
    }

    void add(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod, seal::Plaintext &result, seal::MemoryPoolHandle pool)
    {
        // Verify parameters.
        size_t coeff_count = poly_mod.coeff_count();
        int coeff_bit_count = coeff_mod.bit_count();
        size_t coeff_uint64_count = coeff_mod.uint64_count();

        // Get pointer to inputs (duplicated and resized if needed).
        auto poly1ptr = duplicate_poly_if_needed(plaintext1, coeff_count, plaintext1.data() == result.data(), pool);
        auto poly2ptr = duplicate_poly_if_needed(plaintext2, coeff_count, plaintext2.data() == result.data(), pool);

        // Verify destination size.
        resize_destination_if_needed(result, coeff_count);

        // Add polynomials.
        add_poly_poly_coeffmod(poly1ptr.get(), poly2ptr.get(), coeff_count, coeff_mod, result.data());
    }

    void sub(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2,
        const seal::util::PolyModulus &poly_mod, const seal::SmallModulus &coeff_mod, seal::Plaintext &result, seal::MemoryPoolHandle pool)
    {
        // Verify parameters.
        size_t coeff_count = poly_mod.coeff_count();
        int coeff_bit_count = coeff_mod.bit_count();
        size_t coeff_uint64_count = coeff_mod.uint64_count();

        // Get pointer to inputs (duplicated and resized if needed).
        auto poly1ptr = duplicate_poly_if_needed(plaintext1, coeff_count, plaintext1.data() == result.data(), pool);
        auto poly2ptr = duplicate_poly_if_needed(plaintext2, coeff_count, plaintext2.data() == result.data(), pool);

        // Verify destination size.
        resize_destination_if_needed(result, coeff_count);

        // Add polynomials.
        sub_poly_poly_coeffmod(poly1ptr.get(), poly2ptr.get(), coeff_count, coeff_mod, result.data());
    }
}