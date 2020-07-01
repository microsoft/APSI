// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <memory>

// APSI
#include "apsi/dbblock.h"
#include "apsi/logging/log.h"
#include "apsi/util/interpolate.h"

// SEAL
#include <seal/util/uintarithsmallmod.h>

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    using namespace util;
    using namespace logging;

    namespace sender
    {

        template<typename L>
        BinBundle<L>::BinBundle(
            size_t num_bins,
            std::shared_ptr<seal::SEALContext> seal_ctx,
            std::shared_ptr<seal::Evaluator> evaluator,
            std::shared_ptr<seal::BatchEncoder> batch_encoder,
            const seal::Modulus mod
        ) :
            cache_invalid_(true),
            seal_ctx_(seal_ctx),
            evaluator_(evaluator),
            batch_encoder_(batch_encoder),
            mod_(mod)
        {
                bins_.reserve(num_bins);
                cache_.bin_polyns_.reserve(num_bins);
        }

        /**
        Clears the contents of the BinBundle and wipes out the cache
        */
        template<typename L>
        void BinBundle<L>::clear()
        {
            bins_.clear();
            clear_cache();
        }

        /**
        Wipes out the cache of the BinBundle
        */
        template<typename L>
        void BinBundle<L>::clear_cache()
        {
            cache_.bin_polyns_.clear();
            cache_.plaintext_polyn_coeffs_.clear();
            cache_invalid_ = true;
        }

        /**
        Generates and caches the polynomials and plaintexts that represent the BinBundle
        */
        template<typename L>
        void BinBundle<L>::regen_cache()
        {
            clear_cache();
            regen_polyns();
            regen_plaintexts();
            cache_invalid_ = false;
        }

        /*
        template<typename L>
        std::size_t BinBundle::bin_size(std::size_t bin_idx)
        {
            if (bin_idx >= bins_.size())
            {
                throw runtime_error("bin_idx should be smaller than bins_.size()");
            }

            bins_.at(bin_idx).size()
        }
        */

        // For each bin, compute from scratch the unique monic polynomial whose roots are precisely the elements of the
        // bin
        template<>
        void BinBundle<monostate>::regen_polyns()
        {
            // We're recomputing everything, so wipe out the cache
            clear_cache();

            // For each bin, construct a polynomial
            for (size_t i = 0; i < bins_.size(); i++)
            {
                // In the unlabeled PSI case, the bin is a key-value map where the values are empty. The keys are the
                // roots of the polynomial we're making.
                const std::map<uint64_t, monostate> &bin = bins_.at(i);

                // Collect the roots
                std::vector<uint64_t> roots(bin.size());
                for (auto &kv : bin) {
                    roots.push_back(kv.first);
                }

                // Compute the polynomial and save to cache
                std::vector<uint64_t> polyn_coeffs = polyn_with_roots(roots, mod_);
                BinPolynCache bpc = BinPolynCache {
                    .interpolation_polyn_coeffs = polyn_coeffs,
                };
                cache_.bin_polyns_.push_back(bpc);
            }
        }

        // Compute the Newton interpolation polynomial from scratch
        template<>
        void BinBundle<uint64_t>::regen_polyns()
        {
            // We're recomputing everything, so wipe out the cache
            clear_cache();


            // For each bin, construct a polynomial
            for (size_t i = 0; i < bins_.size(); i++)
            {
                // Each bin is a map from points to values. We split these up and use them for interpolation.
                std::map<uint64_t, uint64_t> &bin = bins_.at(i);

                // Collect the items and labels into different vectors
                std::vector<uint64_t> points;
                std::vector<uint64_t> values;
                points.reserve(bin.size());
                values.reserve(bin.size());

                // pv is (point, value)
                for (const auto &pv : bin)
                {
                    points.push_back(pv.first);
                    values.push_back(pv.second);
                }

                // Put the Newton interpolation polynomial in the cache
                std::vector<uint64_t> interp_polyn = newton_interpolate_polyn(points, values, mod_);
                BinPolynCache bpc = BinPolynCache {
                    .interpolation_polyn_coeffs = interp_polyn,
                };
                cache_.bin_polyns_.push_back(bpc);
            }
        }

        /**
        Computes and caches the bin's polynomial coeffs in Plaintexts. Plaintext i in the cache stores all the i-th
        degree coefficients of this BinBundle's interpolation polynomials.
        */
        template<typename L>
        void BinBundle<L>::regen_plaintexts()
        {
            // Find the highest degree polynomial in this BinBundle. The max degree determines how many Plaintexts we
            // need to make
            size_t num_bins = bins_.size();
            size_t max_deg = 0;
            for (BinPolynCache &bpc : cache_.bin_polyns_)
            {
                size_t deg = bpc.interpolation_polyn_coeffs.size() - 1;
                if (deg > max_deg)
                {
                    max_deg = deg;
                }
            }

            // Now make the Plaintexts. We let Plaintext i contain all bin coefficients of degree i.
            for (size_t i = 0; i < max_deg + 1; i++)
            {
                // Go through all the bins, collecting the coefficients at degree i
                std::vector<uint64_t> coeffs_of_deg_i;
                coeffs_of_deg_i.reserve(num_bins);
                for (auto &bpc : cache_.bin_polyns_)
                {
                    std::vector<uint64_t> &p = bpc.interpolation_polyn_coeffs;

                    // Get the coefficient if it's set. Otherwise it's zero
                    uint64_t coeff = 0;
                    if (i < p.size())
                    {
                        coeff = p[i];
                    }

                    coeffs_of_deg_i.push_back(coeff);
                }

                // Now let pt be the Plaintext consisting of all those degree i coefficients
                Plaintext pt;
                batch_encoder_->encode(coeffs_of_deg_i, pt);
                evaluator_->transform_to_ntt_inplace(pt, seal_ctx_->first_parms_id());

                // Push the new Plaintext to the cache
                cache_.plaintext_polyn_coeffs_.push_back(pt);
            }
        }
    } // namespace sender
} // namespace apsi
