// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <stdexcept>
#include <unordered_set>
#include <vector>

// APSI
#include "apsi/oprf/oprf_common.h"

// SEAL
#include "seal/dynarray.h"
#include "seal/memorymanager.h"

// GSL
#include "gsl/span"

namespace apsi {
    namespace oprf {
        class OPRFReceiver {
        public:
            OPRFReceiver(const OPRFReceiver &) = delete;

            OPRFReceiver(OPRFReceiver &&) = default;

            OPRFReceiver &operator=(const OPRFReceiver &) = delete;

            OPRFReceiver &operator=(OPRFReceiver &&) = default;

            OPRFReceiver(gsl::span<const Item> oprf_items)
                : oprf_queries_(pool_), inv_factor_data_(pool_)
            {
                process_items(oprf_items);
            }

            inline std::size_t item_count() const noexcept
            {
                return inv_factor_data_.item_count();
            }

            void process_responses(
                gsl::span<const unsigned char> oprf_responses,
                gsl::span<HashedItem> oprf_hashes,
                gsl::span<LabelKey> label_keys) const;

            void clear();

            std::vector<unsigned char> query_data() const;

        private:
            void set_item_count(std::size_t item_count);

            void process_items(gsl::span<const Item> oprf_items);

            // For decrypting OPRF response
            class FactorData {
            public:
                static constexpr std::size_t factor_size = ECPoint::order_size;

                FactorData(seal::MemoryPoolHandle pool, std::size_t item_count = 0)
                    : factor_data_(std::move(pool))
                {
                    resize(item_count);
                }

                ~FactorData() = default;

                FactorData(const FactorData &) = delete;

                FactorData(FactorData &&) = default;

                FactorData &operator=(const FactorData &) = delete;

                FactorData &operator=(FactorData &&) = default;

                std::size_t item_count() const noexcept
                {
                    return item_count_;
                }

                auto get_factor(std::size_t index) -> ECPoint::scalar_span_type
                {
                    if (index >= item_count_) {
                        throw std::invalid_argument("index out of bounds");
                    }
                    return ECPoint::scalar_span_type(
                        factor_data_.span().subspan(index * factor_size, factor_size).data(),
                        factor_size);
                }

                auto get_factor(std::size_t index) const -> ECPoint::scalar_span_const_type
                {
                    if (index >= item_count_) {
                        throw std::invalid_argument("index out of bounds");
                    }
                    return ECPoint::scalar_span_const_type(
                        factor_data_.span().subspan(index * factor_size, factor_size).data(),
                        factor_size);
                }

            private:
                void resize(std::size_t item_count)
                {
                    item_count_ = item_count;
                    factor_data_.resize(item_count * factor_size);
                }

                seal::DynArray<unsigned char> factor_data_;

                std::size_t item_count_ = 0;
            };

            seal::MemoryPoolHandle pool_ =
                seal::MemoryManager::GetPool(seal::mm_prof_opt::mm_force_new, true);

            seal::DynArray<unsigned char> oprf_queries_;

            FactorData inv_factor_data_;
        }; // class OPRFReceiver
    }      // namespace oprf
} // namespace apsi
