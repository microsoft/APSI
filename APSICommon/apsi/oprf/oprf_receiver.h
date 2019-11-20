// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <stdexcept>
#include <seal/intarray.h>
#include <seal/memorymanager.h>
#include "apsi/oprf/oprf_common.h"

namespace apsi
{
    namespace oprf 
    {
        class OPRFReceiver
        {
        public:
            OPRFReceiver(const OPRFReceiver &) = delete;

            OPRFReceiver &operator =(const OPRFReceiver &) = delete;

            OPRFReceiver(
                gsl::span<const oprf_item_type, gsl::dynamic_extent> oprf_items,
                gsl::span<Byte, gsl::dynamic_extent> oprf_queries)
            {
                process_items(oprf_items, oprf_queries);
            }

            inline std::size_t item_count() const noexcept
            {
                return inv_factor_data_.item_count();
            }

            void process_responses(
                gsl::span<const Byte, gsl::dynamic_extent> oprf_responses,
                gsl::span<oprf_hash_type, gsl::dynamic_extent> oprf_hashes) const;

        private:
            void process_items(
                gsl::span<const oprf_item_type, gsl::dynamic_extent> oprf_items,
                gsl::span<Byte, gsl::dynamic_extent> oprf_queries);

            // For decrypting OPRF response
            class FactorData
            {
            public:
                static constexpr std::size_t factor_size = ECPoint::order_size;

                FactorData(std::size_t item_count = 0)
                {
                    resize(item_count);
                }

                ~FactorData() = default;

                FactorData(const FactorData &) = delete;

                FactorData &operator =(const FactorData &) = delete;

                inline void resize(std::size_t item_count = 0)
                {
                    item_count_ = item_count;
                    factor_data_.resize(item_count * factor_size);
                }

                inline std::size_t item_count() const noexcept
                {
                    return item_count_;
                }

                inline void clear()
                {
                    factor_data_ = {
                        seal::MemoryManager::GetPool(seal::mm_prof_opt::FORCE_NEW, true) };
                    item_count_ = 0;
                }

                auto get_factor(std::size_t index)
                    -> ECPoint::scalar_span_type
                {
                    if (index >= item_count_)
                    {
                        throw std::invalid_argument("index out of bounds");
                    }
                    return factor_data_.span().subspan(
                        index * factor_size, factor_size);
                }

                auto get_factor(std::size_t index) const
                    -> ECPoint::scalar_span_const_type
                {
                    if (index >= item_count_)
                    {
                        throw std::invalid_argument("index out of bounds");
                    }
                    return factor_data_.span().subspan(
                        index * factor_size, factor_size);
                }

            private:
                seal::IntArray<Byte> factor_data_{
                    seal::MemoryManager::GetPool(seal::mm_prof_opt::FORCE_NEW, true) };

                std::size_t item_count_ = 0;
            };

            inline void set_item_count(std::size_t item_count)
            {
                inv_factor_data_.resize(item_count);
            }
            
            FactorData inv_factor_data_;
        }; // class OPRFReceiver
    } // namespace oprf
} // namespace apsi
