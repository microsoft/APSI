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
        BinBundle::BinBundle(
            size_t num_bins,
            shared_ptr<seal::SEALContext> seal_ctx,
            shared_ptr<seal::Evaluator> evaluator,
            shared_ptr<seal::BatchEncoder> batch_encoder,
            seal::Modulus mod
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
        Does a dry-run insertion of item-label pairs into sequential bins, beginning at start_bin_idx. This does not
        mutate the BinBundle.
        On success, returns the size of the largest bin bins in the modified range, after insertion has taken place
        On failed insertion, returns -1
        */
        const int BinBundle::multi_insert_dry_run(vector<pair<felt_t, L>> &item_label_pairs, size_t start_bin_idx) {
            return multi_insert(pairs, start_bin_idx, true);
        }

        /**
        Inserts item-label pairs into sequential bins, beginning at start_bin_idx
        On success, returns the size of the largest bin bins in the modified range, after insertion has taken place
        On failed insertion, returns -1. On failure, no modification is made to the BinBundle.
        */
        int BinBundle::multi_insert_for_real(vector<pair<felt_t, L>> item_label_pairs, size_t start_bin_idx)
        {
            return multi_insert(pairs, start_bin_idx, false);
        }

        /**
        Inserts item-label pairs into sequential bins, beginning at start_bin_idx. If dry_run is specified, no change is
        made to the BinBundle.
        On success, returns the size of the largest bin bins in the modified range, after insertion has taken place
        On failed insertion, returns -1. On failure, no modification is made to the BinBundle.
        */
        int BinBundle::multi_insert(vector<pair<felt_t, L>> item_label_pairs, size_t start_bin_idx, bool dry_run) {
            // For each key, check that we can insert into the corresponding bin. If the answer is "no" at any point,
            // return false.
            size_t curr_bin_idx = start_bin_idx;
            for (auto &pair : item_label_pairs)
            {
                map<felt_t, L> curr_bin = &bins_.at(curr_bin_idx);
                // Check if the key is already in the current bin. If so, that's an inserstion error
                if (curr_bin.find(pair.first) == curr_bin.end())
                {
                    return -1;
                }

                curr_bin_idx++;
            }

            // If we're here, that means we can insert in all bins
            size_t max_bin_size = 0;
            size_t curr_bin_idx = start_bin_idx;
            for (auto &pair : item_label_pairs)
            {
                map<felt_t, L> curr_bin = &bins_.at(curr_bin_idx);

                // Compare the would-be bin size here to the running max
                if (max_bin_size < curr_bin.size() + 1)
                {
                    max_bin_size = curr_bin.size() + 1;
                }

                // Insert if not dry run
                if (!dry_run)
                {
                    curr_bin.insert(pair);
                }

                curr_bin_idx++;
            }

            return max_bin_size;
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


        /**
        For each bin, compute from scratch the unique monic polynomial whose roots are precisely the elements of the
        bin
        */
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
                const map<felt_t, monostate> &bin = bins_.at(i);

                // Collect the roots
                vector<felt_t> roots(bin.size());
                for (auto &kv : bin) {
                    roots.push_back(kv.first);
                }

                // Compute the polynomial and save to cache
                vector<felt_t> polyn_coeffs = polyn_with_roots(roots, mod_);
                BinPolynCache bpc = BinPolynCache {
                    .interpolation_polyn_coeffs = polyn_coeffs,
                };
                cache_.bin_polyns_.push_back(bpc);
            }
        }

        // Compute the Newton interpolation polynomial from scratch
        template<>
        void BinBundle<felt_t>::regen_polyns()
        {
            // We're recomputing everything, so wipe out the cache
            clear_cache();


            // For each bin, construct a polynomial
            for (size_t i = 0; i < bins_.size(); i++)
            {
                // Each bin is a map from points to values. We split these up and use them for interpolation.
                map<felt_t, felt_t> &bin = bins_.at(i);

                // Collect the items and labels into different vectors
                vector<felt_t> points;
                vector<felt_t> values;
                points.reserve(bin.size());
                values.reserve(bin.size());

                // pv is (point, value)
                for (const auto &pv : bin)
                {
                    points.push_back(pv.first);
                    values.push_back(pv.second);
                }

                // Put the Newton interpolation polynomial in the cache
                vector<felt_t> interp_polyn = newton_interpolate_polyn(points, values, mod_);
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
                vector<felt_t> coeffs_of_deg_i;
                coeffs_of_deg_i.reserve(num_bins);
                for (auto &bpc : cache_.bin_polyns_)
                {
                    vector<felt_t> &p = bpc.interpolation_polyn_coeffs;

                    // Get the coefficient if it's set. Otherwise it's zero
                    felt_t coeff = 0;
                    if (i < p.size())
                    {
                        coeff = p[i];
                    }

                    coeffs_of_deg_i.push_back(coeff);
                }

                // Now let pt be the Plaintext consisting of all those degree i coefficients
                Plaintext pt;
                batch_encoder_->encode(coeffs_of_deg_i, pt);
                // Convert to NTT form so our intersection computations later are fast
                evaluator_->transform_to_ntt_inplace(pt, seal_ctx_->first_parms_id());

                // Push the new Plaintext to the cache
                cache_.plaintext_polyn_coeffs_.push_back(pt);
            }
        }
    } // namespace sender
} // namespace apsi
