#pragma once

// STD
#include <cstdint>
#include <cstddef>

namespace apsi
{
    class PolyModulus
    {
    public:
        PolyModulus() = default;

        PolyModulus(const std::uint64_t *poly, std::size_t coeff_count,
            std::size_t coeff_uint64_count);

        PolyModulus &operator =(const PolyModulus &assign) = default;

        PolyModulus(const PolyModulus &copy) = default;

        PolyModulus &operator =(PolyModulus &&assign) noexcept;

        PolyModulus(PolyModulus &&source) noexcept;

        inline const std::uint64_t *get() const
        {
            return poly_;
        }

        inline std::size_t coeff_count() const
        {
            return coeff_count_;
        }

        inline std::size_t coeff_uint64_count() const
        {
            return coeff_uint64_count_;
        }

        inline bool is_coeff_count_power_of_two() const
        {
            return coeff_count_power_of_two_ >= 0;
        }

        inline int coeff_count_power_of_two() const
        {
            return coeff_count_power_of_two_;
        }

        inline bool is_one_zero_one() const
        {
            return is_one_zero_one_;
        }

        inline bool is_fft_modulus() const
        {
            return is_one_zero_one_ && (coeff_count_power_of_two_ >= 0);
        }

    private:
        const std::uint64_t *poly_ = nullptr;

        std::size_t coeff_count_ = 0;

        std::size_t coeff_uint64_count_ = 0;

        int coeff_count_power_of_two_ = -1;

        bool is_one_zero_one_ = false;
    };
}
