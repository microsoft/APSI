// STD
#include <algorithm>
#include <utility>

// APSI
#include "apsi/binbundle.h"
#include "apsi/logging/log.h"
#include "apsi/util/interpolate.h"

namespace apsi
{

    using namespace std;
    using namespace seal;
    using namespace seal::util;
    using namespace util;
    using namespace logging;

    namespace sender
    {
        /**
        Evaluates the polynomial on the given ciphertext. We don't compute the powers of the input ciphertext C
        ourselves. Instead we assume they've been precomputed and accept the powers: (C, C², C³, ...) as input. The
        number of powers provided MUST be at least plaintext_polyn_coeffs_.size()-1.
        */
        Ciphertext BatchedPlaintextPolyn::eval(const vector<Ciphertext> &ciphertext_powers) const
        {
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
            static_assert(false,
                "SEAL must be built with SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF"); 
#endif
            // We have no way of producing fresh ciphertexts in the Sender class, so we
            // can't tolerate a situation where the polynomial evaluation results in just
            // a plaintext batched_coeffs_[0]. The query must be used.
            if (batched_coeffs_.size() < 2)
            {
                throw logic_error("cannot evaluate a constant polynomial");
            }

            // We need to have enough ciphertext powers to evaluate this polynomial
            if (batched_coeffs_.size() > ciphertext_powers.size())
            {
                throw invalid_argument("not enough ciphertext powers available");
            }

            const SEALContext &seal_context = *crypto_context_.seal_context();
            Evaluator &evaluator = *crypto_context_.evaluator();

            // Lowest degree terms are stored in the lowest index positions in vectors.
            // Specifically, ciphertext_powers[1] is the first power of the ciphertext data,
            // but batched_coeffs_[0] is the constant coefficient.
            //
            // This function only works when batched_coeffs_ has size at least 2, because
            // otherwise there is no way to produce a ciphertext for the result at all.
            // Because the plaintexts in batched_coeffs_ can be identically zero, SEAL should
            // be built with SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF.
            //
            // Both ciphertext_powers and the batched_coeffs_ are assumed to be in NTT form.
            // The return value is not in NTT form.
            Ciphertext result, temp;
            evaluator.multiply_plain(ciphertext_powers[1], batched_coeffs_[1], result);
            for (size_t deg = 2; deg < batched_coeffs_.size(); deg++)
            {
                evaluator.multiply_plain(ciphertext_powers[deg], batched_coeffs_[deg], temp);
                evaluator.add_inplace(result, temp);
            }

            // Need to transform back from NTT form so we can do final addition of batched_coeffs_[0]
            evaluator.transform_from_ntt_inplace(result);

            // Finally add the constant coefficients batched_coeffs_[0]
            evaluator.add_plain_inplace(result, batched_coeffs_[0]);

            // Make the result as small as possible by modulus switching
            while (result.parms_id() != seal_context.last_parms_id())
            {
                evaluator.mod_switch_to_next_inplace(result);
            }

            // If the last parameter set has only one prime, we can compress the result
            // further by setting low-order bits to zero. This effectively increases the
            // noise, but that doesn't matter as long as we don't use all noise budget.
            const EncryptionParameters &parms = seal_context.last_context_data()->parms();
            if (parms.coeff_modulus().size() == 1)
            {
                // The number of data bits we need to have left in each ciphertext coefficient
                int compr_coeff_bit_count = parms.plain_modulus().bit_count() +
                    seal::util::get_significant_bit_count(parms.poly_modulus_degree());

                int coeff_mod_bit_count = parms.coeff_modulus()[0].bit_count();

                // The number of bits to set to zero
                int irrelevant_bit_count = coeff_mod_bit_count - compr_coeff_bit_count;

                // Can compression achieve anything?
                if (irrelevant_bit_count > 0)
                {
                    // Mask for zeroing out the irrelevant bits
                    uint64_t mask = ~((uint64_t(1) << irrelevant_bit_count) - 1);
                    SEAL_ITERATE(iter(result), result.size(), [&](auto I) {
                        // We only have a single RNS component so dereference once more
                        SEAL_ITERATE(*I, parms.poly_modulus_degree(), [&](auto J) {
                            J &= mask;
                        });
                    });
                }
            }

            return result;
        }

        /**
        Helper function. Computes the "matching" polynomial of a bin, i.e., the unique monic polynomial whose roots are
        precisely the items of the bin. Stores the results in cache_.felt_matching_polyns.
        */
        template<typename L>
        FEltPolyn compute_matching_polyn(const map<felt_t, L> &bin, const Modulus &mod)
        {
            // Collect the roots
            vector<felt_t> roots;
            roots.reserve(bin.size());
            for (auto &kv : bin) {
                roots.push_back(kv.first);
            }

            // Compute and return the polynomial
            return polyn_with_roots(roots, mod);
        }

        /**
        Helper function. Computes the Newton interpolation polynomial of a bin
        */
        FEltPolyn compute_newton_polyn(const map<felt_t, felt_t> &bin, const Modulus &mod)
        {
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

            // Compute and return the Newton interpolation polynomial
            return newton_interpolate_polyn(points, values, mod);
        }

        /**
        Constructs a batched Plaintext polynomial from a list of polynomials. Takes an evaluator and batch encoder to do
        encoding and NTT ops.
        */
        BatchedPlaintextPolyn::BatchedPlaintextPolyn(
            vector<FEltPolyn> &polyns,
            CryptoContext crypto_context
        ) : crypto_context_(move(crypto_context))
        {
            // Find the highest degree polynomial in the list. The max degree determines how many Plaintexts we
            // need to make
            size_t max_deg = 0;
            for (FEltPolyn &p : polyns)
            {
                // Degree = number of coefficients - 1
                size_t deg = p.size() - 1;
                if (deg > max_deg)
                {
                    max_deg = deg;
                }
            }

            // Now make the Plaintexts. We let Plaintext i contain all bin coefficients of degree i.
            size_t num_polyns = polyns.size();
            for (size_t i = 0; i < max_deg + 1; i++)
            {
                // Go through all the bins, collecting the coefficients at degree i
                vector<felt_t> coeffs_of_deg_i;
                coeffs_of_deg_i.reserve(num_polyns);
                for (FEltPolyn &p : polyns)
                {
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
                crypto_context_.encoder()->encode(coeffs_of_deg_i, pt);

                // When evaluating the match and interpolation polynomials on encrypted query data, we multiply each
                // power of the encrypted query with a plaintext (pt here) corresponding to the polynomial coefficient,
                // and add the results together. Finally, the constant coefficients (i == 0 here) is added to the sum.
                // In SEAL the fastest way to the multiplications is by having both the plaintexts and the ciphertexts
                // be in NTT transformed form. However, SEAL does not support plaintext-ciphertext addition in NTT
                // transformed form, so before the final addition we need to transform the result back from NTT form and
                // add the constant coefficient. Therefore, we need to transform all plaintext polynomials here to NTT
                // form except the one corresponding to the constant coefficient.
                if (i != 0)
                {
                    crypto_context_.evaluator()->transform_to_ntt_inplace(
                        pt,
                        crypto_context_.seal_context()->first_parms_id()
                    );
                }

                // Push the new Plaintext
                batched_coeffs_.emplace_back(pt);
            }
        }

        template<typename L>
        BinBundle<L>::BinBundle(
            size_t num_bins,
            CryptoContext &crypto_context
        ) :
            cache_invalid_(true),
            cache_(crypto_context),
            crypto_context_(crypto_context)
        {
            bins_.resize(num_bins);
            cache_.felt_matching_polyns.reserve(num_bins);
        }

        /**
        Returns the modulus that defines the finite field that we're working in
        */
        template<typename L>
        const Modulus& BinBundle<L>::field_mod()
        {
            // Forgive me
            const auto &context_data = crypto_context_.seal_context()->first_context_data();
            return context_data->parms().plain_modulus();
        }

        /**
        Batches this BinBundle's polynomials into SEAL Plaintexts. Resulting values are stored in cache_.
        */
        template<typename L>
        void BinBundle<L>::regen_plaintexts()
        {
            // Compute and cache the batched "matching" polynomials. They're computed in both labeled and unlabeled PSI.
            BatchedPlaintextPolyn p(cache_.felt_matching_polyns, crypto_context_);
            cache_.batched_matching_polyn = p;

            // Compute and cache the batched Newton interpolation polynomials iff they exist. They're only computed for
            // labeled PSI.
            if (cache_.felt_interp_polyns.size() > 0)
            {
                BatchedPlaintextPolyn p(cache_.felt_interp_polyns, crypto_context_);
                cache_.batched_interp_polyn = p;
            }
        }

        /**
        Does a dry-run insertion of item-label pairs into sequential bins, beginning at start_bin_idx. This does not
        mutate the BinBundle.
        On success, returns the size of the largest bin bins in the modified range, after insertion has taken place
        On failed insertion, returns -1
        */
        template<typename L>
        int BinBundle<L>::multi_insert_dry_run(
            std::vector<std::pair<felt_t, L> > &item_label_pairs,
            size_t start_bin_idx
        ) {
            return multi_insert(item_label_pairs, start_bin_idx, true);
        }

        /**
        Inserts item-label pairs into sequential bins, beginning at start_bin_idx
        On success, returns the size of the largest bin bins in the modified range, after insertion has taken place
        On failed insertion, returns -1. On failure, no modification is made to the BinBundle.
        */
        template<typename L>
        int BinBundle<L>::multi_insert_for_real(
            std::vector<std::pair<felt_t, L> > &item_label_pairs,
            size_t start_bin_idx
        ) {
            return multi_insert(item_label_pairs, start_bin_idx, false);
        }

        /**
        Inserts item-label pairs into sequential bins, beginning at start_bin_idx. If dry_run is specified, no change is
        made to the BinBundle.
        On success, returns the size of the largest bin bins in the modified range, after insertion has taken place
        On failed insertion, returns -1. On failure, no modification is made to the BinBundle.
        */
        template<typename L>
        int BinBundle<L>::multi_insert(
            std::vector<std::pair<felt_t, L> > &item_label_pairs,
            size_t start_bin_idx,
            bool dry_run
        ) {
            // For each key, check that we can insert into the corresponding bin. If the answer is "no" at any point,
            // return false.
            size_t curr_bin_idx = start_bin_idx;
            for (auto &pair : item_label_pairs)
            {
                auto item_component = pair.first;
                map<felt_t, L> &curr_bin = bins_.at(curr_bin_idx);
                // Check if the key is already in the current bin. If so, that's an insertion error
                if (curr_bin.find(item_component) != curr_bin.end())
                {
                    return -1;
                }

                curr_bin_idx++;
            }

            // If we're here, that means we can insert in all bins
            size_t max_bin_size = 0;
            curr_bin_idx = start_bin_idx;
            for (auto &pair : item_label_pairs)
            {
                map<felt_t, L> &curr_bin = bins_.at(curr_bin_idx);

                // Compare the would-be bin size here to the running max
                if (max_bin_size < curr_bin.size() + 1)
                {
                    max_bin_size = curr_bin.size() + 1;
                }

                // Insert if not dry run
                if (!dry_run)
                {
                    curr_bin.insert(pair);

                    // Indicate that the polynomials need to be recomputed
                    cache_invalid_ = true;
                }

                curr_bin_idx++;
            }

            return max_bin_size;
        }


        /**
        Attempts to overwrite the stored items' labels with the given labels. Returns true iff it found a contiguous
        sequence of given items. If no such sequence was found, this BinBundle is not mutated. This function can be
        called on a BinBundle<monostate> but it won't do anything except force the cache to get recomputed, so don't
        bother.
        */
        template<typename L>
        bool BinBundle<L>::try_multi_overwrite(
            std::vector<std::pair<felt_t, L> > &item_label_pairs,
            size_t start_bin_idx
        ) {
            // Check that all the item components appear sequentially in this BinBundle
            size_t curr_bin_idx = start_bin_idx;
            for (auto &pair : item_label_pairs)
            {
                auto &item_component = pair.first;
                map<felt_t, L> &curr_bin = bins_.at(curr_bin_idx);

                // A non-match was found. This isn't the item we're looking for
                if (curr_bin.find(item_component) == curr_bin.end())
                {
                    return false;
                }

                curr_bin_idx++;
            }

            // If we're here, that means we can overwrite the labels
            size_t max_bin_size = 0;
            curr_bin_idx = start_bin_idx;
            for (auto &pair : item_label_pairs)
            {
                auto key = pair.first;
                auto value = pair.second;

                // Overwrite the label in the bin
                map<felt_t, L> &curr_bin = bins_.at(curr_bin_idx);
                curr_bin[key] = value;

                // Indicate that the polynomials need to be recomputed
                cache_invalid_ = true;

                curr_bin_idx++;
            }

            return true;
        }

        /**
        Sets the given labels to the set of labels associated with the sequence of items in this BinBundle, starting at
        start_idx. If any item is not present in its respective bin, this returns false and clears the given labels
        vector. Returns true on success.
        */
        template<typename L>
        bool BinBundle<L>::try_get_multi_label(const vector<felt_t> &items, size_t start_bin_idx, vector<L> labels) const
        {
            // Clear the return vector. We'll push to it as we collect labels
            labels.clear();

            // Go through all the items. If the item appears, add its label to labels. If any item doesn't appear, we
            // scrap the whole computation and return false.
            size_t curr_bin_idx = start_bin_idx;
            for (auto &item : items)
            {
                const map<felt_t, L> &curr_bin = bins_.at(curr_bin_idx);
                const auto &label_it = curr_bin.find(item);

                // One of the items isn't there. No label to fetch. Clear the vector and return early.
                if (label_it == curr_bin.end())
                {
                    labels.clear();
                    return false;
                } else
                {
                    // Found the label, put it in the return vector. *label_it is a key-value pair.
                    labels.emplace_back(label_it->second);
                }

                curr_bin_idx++;
            }

            // Success. We found all the items
            return true;
        }

        /**
        Clears the contents of the BinBundle and wipes out the cache
        */
        template<typename L>
        void BinBundle<L>::clear()
        {
            size_t bins_size = bins_.size();
            bins_.clear();
            bins_.resize(bins_size);
            clear_cache();
        }

        /**
        Wipes out the cache of the BinBundle
        */
        template<typename L>
        void BinBundle<L>::clear_cache()
        {
            cache_.felt_matching_polyns.clear();
            cache_.felt_interp_polyns.clear();
            cache_invalid_ = true;
        }

        /**
        Returns whether this BinBundle's cache needs to be recomputed
        */
        template<typename L>
        bool BinBundle<L>::cache_invalid()
        {
            return cache_invalid_;
        }

        /**
        Gets an immutable reference to this BinBundle's cache. This will throw an exception if the cache is invalid.
        Check the cache before you wreck the cache.
        */
        template<typename L>
        const BinBundleCache &BinBundle<L>::get_cache() const
        {
            if (cache_invalid_)
            {
                throw logic_error("Tried to retrieve stale cache");
            }

            return cache_;
        }

        /**
        Generates and caches the polynomials and plaintexts that represent the BinBundle. This will only do
        recomputation if the cache is invalid.
        */
        template<typename L>
        void BinBundle<L>::regen_cache()
        {
            // Only recompute the cache if it needs to be recomputed
            if (cache_invalid_)
            {
                clear_cache();
                regen_polyns();
                regen_plaintexts();
                cache_invalid_ = false;
            }
        }

        /**
        Computes and caches the appropriate polynomials of each bin. For unlabeled PSI, this is just the "matching"
        polynomial. Resulting values are stored in cache_.
        */
        template<>
        void BinBundle<monostate>::regen_polyns()
        {
            // Get the field modulus. We need this for polynomial calculations
            const Modulus& mod = field_mod();

            // Clear the cache before we push to it
            cache_.felt_matching_polyns.clear();

            // For each bin in the bundle, compute and cache the corresponding "matching" polynomial
            for (map<felt_t, monostate> &bin : bins_)
            {
                // Compute and cache the matching polynomial
                FEltPolyn p = compute_matching_polyn(bin, mod);
                cache_.felt_matching_polyns.emplace_back(p);
            }
        }

        /**
        Computes and caches the appropriate polynomials of each bin. For labeled PSI, this is the "matching" polynomial
        and the Newton interpolation polynomial. Resulting values are stored in cache_.
        */
        template<>
        void BinBundle<felt_t>::regen_polyns()
        {
            // Get the field modulus. We need this for polynomial calculations
            const Modulus& mod = field_mod();

            // Clear the cache before we push to it
            cache_.felt_matching_polyns.clear();
            cache_.felt_interp_polyns.clear();

            // For each bin in the bundle, compute and cache the corresponding "matching" and Newton polynomials
            for (map<felt_t, felt_t> &bin : bins_)
            {
                // Compute and cache the matching polynomial
                FEltPolyn p = compute_matching_polyn(bin, mod);
                cache_.felt_matching_polyns.emplace_back(move(p));

                // Compute and cache the Newton polynomial
                p = compute_newton_polyn(bin, mod);
                cache_.felt_interp_polyns.emplace_back(move(p));
            }
        }

        // BinBundle will only ever be used with these two label types. Ordinarily we'd have to put method definitions
        // of a template class with the .h file, but if we monomorphize here, we don't have to do that.
        template class BinBundle<monostate>;
        template class BinBundle<felt_t>;

    } // namespace sender
} // namespace apsi
