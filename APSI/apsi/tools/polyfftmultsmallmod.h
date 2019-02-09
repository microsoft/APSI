#pragma once

// STD
#include <cstdint>

// SEAL
#include "seal/smallmodulus.h"
#include "seal/util/pointer.h"
#include "seal/util/smallntt.h"

// APSI
#include "apsi/tools/polymodulus.h"

namespace apsi
{
    void ntt_multiply_poly_poly(const std::uint64_t *operand1,
        const std::uint64_t *operand2, const seal::util::SmallNTTTables &tables,
        std::uint64_t *result, seal::util::MemoryPool &pool);

    void ntt_multiply_poly_nttpoly(const std::uint64_t *operand1,
        const std::uint64_t *operand2, const seal::util::SmallNTTTables &tables,
        std::uint64_t *result, seal::util::MemoryPool &pool);

    void ntt_double_multiply_poly_nttpoly(const std::uint64_t *operand1,
        const std::uint64_t *operand2, const std::uint64_t *operand3,
        const seal::util::SmallNTTTables &tables, std::uint64_t *result1,
        std::uint64_t *result2, seal::util::MemoryPool &pool);

    void ntt_dot_product_bigpolyarray_nttbigpolyarray(
        const std::uint64_t *array1, const std::uint64_t *array2, std::size_t count,
        const seal::util::SmallNTTTables &tables, std::uint64_t *result, seal::util::MemoryPool &pool);

    void ntt_double_dot_product_bigpolyarray_nttbigpolyarrays(
        const std::uint64_t *array1, const std::uint64_t *array2,
        const std::uint64_t *array3, std::size_t count, const seal::util::SmallNTTTables &tables,
        std::uint64_t *result1, std::uint64_t *result2, seal::util::MemoryPool &pool);

    void nussbaumer_multiply_poly_poly_coeffmod(const std::uint64_t *operand1,
        const std::uint64_t *operand2, int coeff_count_power,
        const seal::SmallModulus &modulus, std::uint64_t *result, seal::util::MemoryPool &pool);

    void nussbaumer_dot_product_bigpolyarray_coeffmod(const std::uint64_t *array1,
        const std::uint64_t *array2, std::size_t count, const PolyModulus &poly_modulus,
        const seal::SmallModulus &modulus, std::uint64_t *result, seal::util::MemoryPool &pool);
}