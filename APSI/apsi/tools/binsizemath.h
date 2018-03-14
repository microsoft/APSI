#pragma once

#include <cstdint>

namespace apsi
{
    double get_bin_overflow_prob(std::uint64_t num_bins, std::uint64_t num_balls, 
        std::uint64_t bin_size, double epsilon = 0.0001);

    std::uint64_t get_bin_size(std::uint64_t num_bins, std::uint64_t num_balls, 
        std::uint64_t stat_sec_param);
}