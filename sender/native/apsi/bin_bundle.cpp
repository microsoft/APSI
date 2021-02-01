// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <type_traits>
#include <utility>

// APSI
#include "apsi/bin_bundle_generated.h"
#include "apsi/bin_bundle.h"
#include "apsi/util/interpolate.h"

// SEAL
#include "seal/util/defines.h"

#pragma message("REMOVE THESE EVENTUALLY")
static size_t false_positives = 0;
static size_t true_positives = 0;
static size_t total_search_count = 0;

namespace apsi
{
    using namespace std;
    using namespace seal;
    using namespace seal::util;
    using namespace util;

    namespace sender
    {
        using namespace util;

        namespace
        {
            /**
            Helper function. Computes the "matching" polynomial of a bin, i.e., the unique monic polynomial whose roots are
            precisely the items of the bin.
            */
            template<typename L>
            FEltPolyn compute_matching_polyn(const vector<pair<felt_t, L>> &bin, const Modulus &mod)
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
            FEltPolyn compute_newton_polyn(const vector<pair<felt_t, felt_t>> &bin, const Modulus &mod)
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
            Helper function. Determines if a field element is present in a bin.
            */
            template<typename L>
            bool is_present(const vector<pair<felt_t, L>> &bin, felt_t element)
            {
                if (bin.end() != find_if(
                                          bin.begin(),
                                          bin.end(),
                                          [&element](const pair<felt_t, L> &elem) {
                                              return elem.first == element;
                                          })) {
                    return true;
                }

                return false;
            }

            /**
            Helper function. Determines if a field element is present in a bin.
            */
            template<typename L>
            bool is_present(const vector<pair<felt_t, L>> &bin, const BloomFilter &filter, felt_t element)
            {
                total_search_count++;

                // Check if the key is already in the current bin.
                if (filter.maybe_present(element)) {
                    // Perform a linear search to determine true/false positives
                    bool result = is_present(bin, element);

                    if (result)
                        true_positives++;
                    else
                        false_positives++;

                    return result;
                }

                return false;
            }

            /**
            Helper function. Returns an iterator pointing to the given field element in the bin if found
            and bin.end() otherwise.
            */
            template<typename L>
            auto get_iterator(
                vector<pair<felt_t, L>> &bin, const BloomFilter &filter, const felt_t &element)
            {
                total_search_count++;

                if (filter.maybe_present(element)) {
                    auto result = find_if(
                        bin.begin(), bin.end(), [&element](const pair<felt_t, L> &elem) {
                            return elem.first == element;
                        });

                    if (bin.end() == result)
                    {
                        false_positives++;
                    }
                    else
                    {
                        true_positives;
                    }

                    return result;
                }

                return bin.end();
            }

            /**
            Helper function. Returns a const iterator pointing to the given field element in the bin if
            found and bin.end() otherwise.
            */
            template <typename L>
            auto get_iterator(const vector<pair<felt_t, L>> &bin, const BloomFilter &filter, const felt_t &element)
            {
                total_search_count++;

                if (filter.maybe_present(element)) {
                    auto result = find_if(
                        bin.begin(), bin.end(), [&element](const pair<felt_t, L> &elem) {
                            return elem.first == element;
                        });

                    if (bin.end() == result)
                    {
                        false_positives++;
                    }
                    else
                    {
                        true_positives++;
                    }

                    return result;
                }

                return bin.end();
            }

            /**
            Helper function. Regenerate Bloom filter for a given bin.
            */
            template<typename L>
            void regenerate_filter(const vector<pair<felt_t, L>> &bin, BloomFilter &filter)
            {
                filter.clear();
                for (pair<felt_t, L> pair : bin)
                {
                    filter.add(pair.first);
                }
            }
        }

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
            // We need to have enough ciphertext powers to evaluate this polynomial
            if (batched_coeffs.size() > ciphertext_powers.size())
            {
                throw invalid_argument("not enough ciphertext powers available");
            }

            const SEALContext &seal_context = *crypto_context.seal_context();
            Evaluator &evaluator = *crypto_context.evaluator();

            // Lowest degree terms are stored in the lowest index positions in vectors. Specifically,
            // ciphertext_powers[1] is the first power of the ciphertext data, but batched_coeffs[0] is the constant
            // coefficient.
            //
            // Because the plaintexts in batched_coeffs can be identically zero, SEAL should be built with
            // SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF. We create a result ciphertext that is identically zero and set
            // its NTT form flag to true so the additions below will work.
            Ciphertext result;
            result.resize(seal_context, seal_context.first_parms_id(), 2);
            result.is_ntt_form() = true;
            Ciphertext temp;
            Plaintext coeff;
            for (size_t deg = 1; deg < batched_coeffs.size(); deg++)
            {
                coeff.unsafe_load(seal_context, batched_coeffs[deg].data(), batched_coeffs[deg].size());
                evaluator.multiply_plain(ciphertext_powers[deg], coeff, temp);
                evaluator.add_inplace(result, temp);
            }

            // Need to transform back from NTT form before we can add the constant coefficient. The constant coefficient
            // is specifically not in NTT form so this can work.
            evaluator.transform_from_ntt_inplace(result);
            coeff.unsafe_load(seal_context, batched_coeffs[0].data(), batched_coeffs[0].size());
            evaluator.add_plain_inplace(result, coeff);

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
                    get_significant_bit_count(parms.poly_modulus_degree());

                int coeff_mod_bit_count = parms.coeff_modulus()[0].bit_count();

                // The number of bits to set to zero
                int irrelevant_bit_count = coeff_mod_bit_count - compr_coeff_bit_count;

                // Can compression achieve anything?
                if (irrelevant_bit_count > 0)
                {
                    // Mask for zeroing out the irrelevant bits
                    uint64_t mask = ~((uint64_t(1) << irrelevant_bit_count) - 1);
                    SEAL_ITERATE(iter(result), result.size(), [&](auto &&I) {
                        // We only have a single RNS component so dereference once more
                        SEAL_ITERATE(*I, parms.poly_modulus_degree(), [&](auto &J) {
                            J &= mask;
                        });
                    });
                }
            }

            return result;
        }

        /**
        Constructs a batched Plaintext polynomial from a list of polynomials. Takes an evaluator and batch encoder to do
        encoding and NTT ops.
        */
        BatchedPlaintextPolyn::BatchedPlaintextPolyn(
            const vector<FEltPolyn> &polyns,
            CryptoContext crypto_context,
            bool compressed
        ) : crypto_context(move(crypto_context))
        {
            compr_mode_type compr_mode = compressed ? compr_mode_type::zstd : compr_mode_type::none;

            // Find the highest degree polynomial in the list. The max degree determines how many Plaintexts we
            // need to make
            size_t max_deg = 0;
            for (const FEltPolyn &p : polyns)
            {
                // Degree = number of coefficients - 1
                max_deg = max(p.size(), max_deg + 1) - 1;
            }

            // Now make the Plaintexts. We let Plaintext i contain all bin coefficients of degree i.
            size_t num_polyns = polyns.size();
            for (size_t i = 0; i < max_deg + 1; i++)
            {
                // Go through all the bins, collecting the coefficients at degree i
                vector<felt_t> coeffs_of_deg_i;
                coeffs_of_deg_i.reserve(num_polyns);
                for (const FEltPolyn &p : polyns)
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
                this->crypto_context.encoder()->encode(coeffs_of_deg_i, pt);

                // When evaluating the match and interpolation polynomials on encrypted query data, we multiply each
                // power of the encrypted query with a plaintext (pt here) corresponding to the polynomial coefficient,
                // and add the results together. The constant coefficient (i == 0 here) is handled by simply adding to
                // the result, which requires that the plaintext is not in NTT form.
                if (i != 0)
                {
                    this->crypto_context.evaluator()->transform_to_ntt_inplace(
                        pt,
                        this->crypto_context.seal_context()->first_parms_id()
                    );
                }

                // Push the new Plaintext
                vector<seal_byte> pt_data;
                pt_data.resize(pt.save_size(compr_mode));
                size_t size = pt.save(pt_data.data(), pt_data.size(), compr_mode);
                pt_data.resize(size);
                batched_coeffs.push_back(move(pt_data));
            }
        }

        template<typename L>
        BinBundle<L>::BinBundle(const CryptoContext &crypto_context, bool compressed, size_t max_bin_size) :
            cache_invalid_(true),
            cache_(crypto_context),
            crypto_context_(crypto_context),
            compressed_(compressed),
            max_bin_size_(max_bin_size)
        {
            if (!crypto_context_.evaluator())
            {
                throw invalid_argument("evaluator is not set in crypto_context");
            }

            size_t num_bins = crypto_context_.seal_context()->first_context_data()->parms().poly_modulus_degree();
            bins_.resize(num_bins);
            filters_.reserve(num_bins);
            cache_.felt_matching_polyns.reserve(num_bins);

            for (size_t i = 0; i < num_bins; i++)
            {
                filters_.emplace_back(max_bin_size, /* size_ratio */ 20);
            }
        }

        /**
        Returns the modulus that defines the finite field that we're working in
        */
        template<typename L>
        const Modulus& BinBundle<L>::field_mod() const
        {
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
            BatchedPlaintextPolyn p(cache_.felt_matching_polyns, crypto_context_, compressed_);
            cache_.batched_matching_polyn = move(p);

            // Compute and cache the batched Newton interpolation polynomials iff they exist. They're only computed for
            // labeled PSI.
            if (cache_.felt_interp_polyns.size() > 0)
            {
                BatchedPlaintextPolyn p(cache_.felt_interp_polyns, crypto_context_, compressed_);
                cache_.batched_interp_polyn = move(p);
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
            const vector<pair<felt_t, L>> &item_label_pairs,
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
            const vector<pair<felt_t, L>> &item_label_pairs,
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
            const vector<pair<felt_t, L>> &item_label_pairs,
            size_t start_bin_idx,
            bool dry_run
        ) {
            // Return -1 if there isn't enough room in the bin bundle to insert at the given location
            if (start_bin_idx >= bins_.size() || item_label_pairs.size() > bins_.size() - start_bin_idx)
            {
                return -1;
            }

            if (is_same<L, felt_t>::value)
            {
                // For each key, check that we can insert into the corresponding bin. If the answer is "no" at any
                // point, return -1.
                size_t curr_bin_idx = start_bin_idx;
                for (auto &curr_pair : item_label_pairs)
                {
                    auto item = curr_pair.first;
                    vector<pair<felt_t, L>> &curr_bin = bins_.at(curr_bin_idx);
                    auto &curr_filter = filters_.at(curr_bin_idx);

                    // Check if the key is already in the current bin. If so, that's an insertion error
                    if (is_present(curr_bin, curr_filter, item))
                    {
                        return -1;
                    }

                    curr_bin_idx++;
                }
            }

            // If we're here, that means we can insert in all bins
            size_t max_bin_size = 0;
            size_t curr_bin_idx = start_bin_idx;
            for (auto &curr_pair : item_label_pairs)
            {
                vector<pair<felt_t, L>> &curr_bin = bins_.at(curr_bin_idx);

                // Compare the would-be bin size here to the running max
                if (max_bin_size < curr_bin.size() + 1)
                {
                    max_bin_size = curr_bin.size() + 1;
                }

                // Insert if not dry run
                if (!dry_run)
                {
                    auto &curr_filter = filters_.at(curr_bin_idx);
                    curr_bin.push_back(curr_pair);
                    curr_filter.add(curr_pair.first);

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
            const vector<pair<felt_t, L>> &item_label_pairs,
            size_t start_bin_idx
        ) {
            // Return false if there isn't enough room in the bin bundle to insert at the given location
            if (start_bin_idx >= bins_.size() || item_label_pairs.size() > bins_.size() - start_bin_idx)
            {
                return false;
            }

            // Check that all the item components appear sequentially in this BinBundle
            size_t curr_bin_idx = start_bin_idx;
            for (auto &curr_pair : item_label_pairs) {
                auto &item = curr_pair.first;
                vector<pair<felt_t, L>> &curr_bin = bins_.at(curr_bin_idx);
                auto &curr_filter = filters_.at(curr_bin_idx);

                // A non-match was found. This isn't the item we're looking for
                if (!is_present(curr_bin, curr_filter, curr_pair.first)) {
                    return false;
                } 

                curr_bin_idx++;
            }

            // If we're here, that means we can overwrite the labels
            size_t max_bin_size = 0;
            curr_bin_idx = start_bin_idx;
            for (auto &curr_pair : item_label_pairs)
            {
                auto key = curr_pair.first;
                auto value = curr_pair.second;

                // Overwrite the label in the bin
                vector <pair<felt_t, L>> &curr_bin = bins_.at(curr_bin_idx);
                auto &curr_filter = filters_.at(curr_bin_idx);

                auto found_pos = find_if(
                    curr_bin.begin(), curr_bin.end(), [&key](const pair<felt_t, L> &element) {
                        return element.first == key;
                    });
                if (found_pos != curr_bin.end())
                {
                    found_pos->second = value;
                    regenerate_filter(curr_bin, curr_filter);
                }

                // Indicate that the polynomials need to be recomputed
                cache_invalid_ = true;

                curr_bin_idx++;
            }

            return true;
        }

        /**
        Attempts to remove the stored items and labels. Returns true iff it found a contiguous sequence of given
        items and the data was successfully removed. If no such sequence was found, this BinBundle is not mutated.
        */
        template<typename L>
        bool BinBundle<L>::try_multi_remove(
            const vector<felt_t> &items,
            size_t start_bin_idx
        ) {
            // Return false if there isn't enough room in the bin bundle at the given location
            if (start_bin_idx >= bins_.size() || items.size() > bins_.size() - start_bin_idx)
            {
                return false;
            }

            // Go through all the items. If any item doesn't appear, we scrap the whole computation and return false.
            size_t curr_bin_idx = start_bin_idx;
            vector<typename vector<pair<felt_t, L>>::iterator> to_remove_its;
            for (auto &item : items)
            {
                vector < pair<felt_t, L>> &curr_bin = bins_.at(curr_bin_idx);
                auto &curr_filter = filters_.at(curr_bin_idx);

                auto to_remove_it = get_iterator(curr_bin, curr_filter, item);
                if (to_remove_it == curr_bin.end())
                {
                    // One of the items isn't there; return false;
                    return false;
                }
                else
                {
                    // Found the label, put it in the return vector. *label_it is a key-value pair.
                    to_remove_its.push_back(to_remove_it);
                }

                curr_bin_idx++;
            }

            // We got to this point, so all of the items were found. Now just erase them.
            curr_bin_idx = start_bin_idx;
            for (auto to_remove_it : to_remove_its)
            {
                vector < pair<felt_t, L>> &curr_bin = bins_.at(curr_bin_idx);
                auto &curr_filter = filters_.at(curr_bin_idx);

                curr_bin.erase(to_remove_it);
                regenerate_filter(curr_bin, curr_filter);

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
        bool BinBundle<L>::try_get_multi_label(
            const vector<felt_t> &items,
            size_t start_bin_idx,
            vector<L> &labels
        ) const
        {
            // Clear the return vector. We'll push to it as we collect labels
            labels.clear();

            // Return false if there isn't enough room in the bin bundle at the given location
            if (start_bin_idx >= bins_.size() || items.size() > bins_.size() - start_bin_idx)
            {
                return false;
            }

            // Go through all the items. If the item appears, add its label to labels. If any item doesn't appear, we
            // scrap the whole computation and return false.
            size_t curr_bin_idx = start_bin_idx;
            for (auto &item : items)
            {
                const vector<pair<felt_t, L>> &curr_bin = bins_.at(curr_bin_idx);
                const auto &curr_filter = filters_.at(curr_bin_idx);

                auto label_it = get_iterator(curr_bin, curr_filter, item);

                if (label_it == curr_bin.end())
                {
                    // One of the items isn't there. No label to fetch. Clear the vector and return early.
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
            filters_.clear();
            filters_.reserve(bins_size);

            for (size_t i = 0; i < bins_size; i++) {
                filters_.emplace_back(max_bin_size_, /* size_ratio */ 20);
            }

            clear_cache();
        }

        /**
        Wipes out the cache of the BinBundle
        */
        template<typename L>
        void BinBundle<L>::clear_cache()
        {
            cache_.felt_matching_polyns.clear();
            cache_.batched_matching_polyn = crypto_context_;

            cache_.felt_interp_polyns.clear();
            cache_.batched_interp_polyn.crypto_context = crypto_context_;

            cache_invalid_ = true;
        }

        /**
        Returns whether this BinBundle's cache needs to be recomputed
        */
        template<typename L>
        bool BinBundle<L>::cache_invalid() const
        {
            return cache_invalid_;
        }

        /**
        Gets a constant reference to this BinBundle's cache. This will throw an exception if the cache is invalid.
        Check the cache before you wreck the cache.
        */
        template<typename L>
        const BinBundleCache &BinBundle<L>::get_cache() const
        {
            if (cache_invalid_)
            {
                throw logic_error("tried to retrieve stale cache");
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
            for (const auto &bin : bins_)
            {
                // Compute and cache the matching polynomial
                FEltPolyn p = compute_matching_polyn(bin, mod);
                cache_.felt_matching_polyns.push_back(move(p));
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
            for (const auto &bin : bins_)
            {
                // Compute and cache the matching polynomial
                FEltPolyn p = compute_matching_polyn(bin, mod);
                cache_.felt_matching_polyns.push_back(move(p));

                // Compute and cache the Newton polynomial
                p = compute_newton_polyn(bin, mod);
                cache_.felt_interp_polyns.push_back(move(p));
            }
        }

        /**
        Returns whether this BinBundle is empty.
        */
        template<typename L>
        bool BinBundle<L>::empty() const
        {
            return all_of(bins_.begin(), bins_.end(), [](auto &b) { return b.empty(); });
        }

        namespace
        {
            template<typename L>
            flatbuffers::Offset<fbs::FEltArray> add_felt_items(flatbuffers::FlatBufferBuilder &fbs_builder, const vector<pair<felt_t, L>> &bin)
            {
                vector<felt_t> felts_data;
                felts_data.reserve(bin.size());
                transform(bin.cbegin(), bin.cend(), back_inserter(felts_data), [](const auto &ilp) { return ilp.first; });
                auto felt_items = fbs_builder.CreateVector(felts_data);
                return fbs::CreateFEltArray(fbs_builder, felt_items);
            }

            template<typename L>
            flatbuffers::Offset<fbs::FEltArray> add_felt_labels(flatbuffers::FlatBufferBuilder &fbs_builder, const vector<pair<felt_t, L>> &bin);

            template<>
            flatbuffers::Offset<fbs::FEltArray> add_felt_labels(flatbuffers::FlatBufferBuilder &fbs_builder, const vector<pair<felt_t, monostate>> &bin)
            {
                return flatbuffers::Offset<fbs::FEltArray>{};
            }

            template<>
            flatbuffers::Offset<fbs::FEltArray> add_felt_labels(flatbuffers::FlatBufferBuilder &fbs_builder, const vector<pair<felt_t, felt_t>> &bin)
            {
                vector<felt_t> felts_data;
                felts_data.reserve(bin.size());
                transform(bin.cbegin(), bin.cend(), back_inserter(felts_data), [](const auto &ilp) { return ilp.second; });
                auto felt_labels = fbs_builder.CreateVector(felts_data);
                return fbs::CreateFEltArray(fbs_builder, felt_labels);
            }
        }

        /**
        Saves the BinBundle to a stream.
        */
        template<typename L>
        size_t BinBundle<L>::save(ostream &out, uint32_t bundle_idx) const
        {
            // Is this a labeled BinBundle?
            constexpr bool labeled = is_same<L, felt_t>::value;
            
            const Modulus &mod = field_mod();
            auto mod_bit_count = mod.bit_count();
            auto mod_byte_count = (mod_bit_count + 7) >> 3;
            
            flatbuffers::FlatBufferBuilder fbs_builder(1024);

            auto bins = fbs_builder.CreateVector([&]() {
                // The Bin vector is populated with an immediately-invoked lambda
                vector<flatbuffers::Offset<fbs::Bin>> ret;
                for (const auto &bin : bins_)
                {
                    // Create the FEltArrays of items and labels (if in labeled mode)
                    auto felt_items = add_felt_items(fbs_builder, bin);
                    auto felt_labels = add_felt_labels(fbs_builder, bin);
                    ret.push_back(fbs::CreateBin(fbs_builder, felt_items, felt_labels));
                }
                return ret;
            }());

            flatbuffers::Offset<fbs::BinBundleCache> bin_bundle_cache;
            if (!cache_invalid_)
            {
                auto felt_matching_polyns = fbs_builder.CreateVector([&]() {
                    // The felt_matching_polyns vector is populated with an immediately-invoked lambda
                    vector<flatbuffers::Offset<fbs::FEltArray>> ret;
                    for (const auto &fmp : cache_.felt_matching_polyns)
                    {
                        auto fmp_coeffs = fbs_builder.CreateVector(fmp);
                        ret.push_back(fbs::CreateFEltArray(fbs_builder, fmp_coeffs));
                    }
                    return ret;
                }());

                auto batched_matching_polyn_data = fbs_builder.CreateVector([&]() {
                    // The batched_matching_polyn is populated with an immediately-invoked lambda
                    vector<flatbuffers::Offset<fbs::Plaintext>> ret;
                    for (const auto &coeff : cache_.batched_matching_polyn.batched_coeffs)
                    {
                        auto data = fbs_builder.CreateVector(
                            reinterpret_cast<const unsigned char*>(coeff.data()),
                            coeff.size());
                        ret.push_back(fbs::CreatePlaintext(fbs_builder, data));
                    }
                    return ret;
                }());
                auto batched_matching_polyn = fbs::CreateBatchedPlaintextPolyn(fbs_builder, batched_matching_polyn_data);

                flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<fbs::FEltArray>>> felt_interp_polyns;
                flatbuffers::Offset<fbs::BatchedPlaintextPolyn> batched_interp_polyn;
                if (labeled)
                {
                    felt_interp_polyns = fbs_builder.CreateVector([&]() {
                        // The felt_interp_polyns vector is populated with an immediately-invoked lambda
                        vector<flatbuffers::Offset<fbs::FEltArray>> ret;
                        for (const auto &fip : cache_.felt_interp_polyns)
                        {
                            auto fip_coeffs = fbs_builder.CreateVector(fip);
                            ret.push_back(fbs::CreateFEltArray(fbs_builder, fip_coeffs));
                        }
                        return ret;
                    }());

                    auto batched_interp_polyn_data = fbs_builder.CreateVector([&]() {
                        // The batched_interp_polyn is populated with an immediately-invoked lambda
                        vector<flatbuffers::Offset<fbs::Plaintext>> ret;
                        for (const auto &coeff : cache_.batched_interp_polyn.batched_coeffs)
                        {
                            auto data = fbs_builder.CreateVector(
                                reinterpret_cast<const unsigned char*>(coeff.data()),
                                coeff.size());
                            ret.push_back(fbs::CreatePlaintext(fbs_builder, data));
                        }
                        return ret;
                    }());
                    batched_interp_polyn = fbs::CreateBatchedPlaintextPolyn(fbs_builder, batched_interp_polyn_data);
                }

                fbs::BinBundleCacheBuilder bin_bundle_cache_builder(fbs_builder);
                bin_bundle_cache_builder.add_felt_matching_polyns(felt_matching_polyns);
                bin_bundle_cache_builder.add_batched_matching_polyn(batched_matching_polyn);
                bin_bundle_cache_builder.add_felt_interp_polyns(felt_interp_polyns);
                bin_bundle_cache_builder.add_batched_interp_polyn(batched_interp_polyn);
                bin_bundle_cache = bin_bundle_cache_builder.Finish();
            }

            fbs::BinBundleBuilder bin_bundle_builder(fbs_builder);
            bin_bundle_builder.add_bundle_idx(bundle_idx);
            bin_bundle_builder.add_labeled(labeled);
            bin_bundle_builder.add_mod(mod.value());
            bin_bundle_builder.add_bins(bins);
            bin_bundle_builder.add_cache(bin_bundle_cache);

            auto bb = bin_bundle_builder.Finish();
            fbs_builder.FinishSizePrefixed(bb);

            out.write(
                reinterpret_cast<const char*>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        namespace
        {
            template<typename L>
            bool add_to_bin(vector<pair<felt_t, L>> &bin, util::BloomFilter &filter, felt_t felt_item, felt_t felt_label);

            template<>
            bool add_to_bin(vector<pair<felt_t, monostate>> &bin, util::BloomFilter &filter, felt_t felt_item, felt_t felt_label)
            {
                bin.push_back(make_pair(felt_item, monostate{}));
                return true;
            }

            template<>
            bool add_to_bin(vector<pair<felt_t, felt_t>> &bin, util::BloomFilter &filter, felt_t felt_item, felt_t felt_label)
            {
                if (is_present(bin, filter, felt_item))
                {
                    return false;
                }

                bin.push_back(make_pair(felt_item, felt_label));
                return true;
            }
        }

        /**
        Loads the BinBundle from a stream. Returns the bundle index and the number of bytes read.
        */
        template<typename L>
        pair<uint32_t, size_t> BinBundle<L>::load(istream &in)
        {
            // Remove everything and clear the cache
            clear();

            vector<seal_byte> in_data(apsi::util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(reinterpret_cast<const unsigned char*>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedBinBundleBuffer(verifier);
            if (!safe)
            {
                APSI_LOG_ERROR("Failed to load BinBundle: the buffer is invalid");
                throw runtime_error("failed to load BinBundle");
            }

            auto bb = fbs::GetSizePrefixedBinBundle(in_data.data());

            // Throw if this is not the right kind of BinBundle
            constexpr bool labeled = is_same<L, felt_t>::value;
            const char *loaded_type_str = bb->labeled() ? "labeled" : "unlabeled";
            const char *this_type_str = labeled ? "labeled" : "unlabeled";
            if (bb->labeled() != labeled)
            {
                APSI_LOG_ERROR("The loaded BinBundle is of incorrect type (" << loaded_type_str
                    << "; expected " << this_type_str << ")");
                throw runtime_error("failed to load BinBundle");
            }

            // Load the bundle index
            uint32_t bundle_idx = bb->bundle_idx();

            // Throw if the field modulus does not match
            uint64_t mod = bb->mod();
            if (mod != field_mod().value())
            {
                APSI_LOG_ERROR("The loaded BinBundle field modulus (" << mod
                    << ") differs from the field modulus of this BinBundle (" << field_mod().value() << ")");
                throw runtime_error("failed to load BinBundle");
            }

            auto mod_bit_count = field_mod().bit_count();
            auto mod_byte_count = (mod_bit_count + 7) >> 3;

            size_t num_bins = bins_.size();

            // Check that the number of bins is correct
            const auto &bins = *bb->bins();
            if (num_bins != bins.size())
            {
                APSI_LOG_ERROR("The loaded BinBundle has " << bins.size()
                    << " bins but this BinBundle expects " << num_bins << " bins");
                throw runtime_error("failed to load BinBundle");
            }

            for (size_t i = 0; i < bins.size(); i++)
            {
                bool has_labels = !!(bins[i]->felt_labels());
                if (labeled != has_labels)
                {
                    const char *labeled_type_str = has_labels ? "labeled" : "unlabeled";
                    APSI_LOG_ERROR("The loaded BinBundle contains data of incorrect type (" << labeled_type_str
                        << "; expected " << this_type_str << ")");
                    throw runtime_error("failed to load BinBundle");
                }

                if (labeled && (bins[i]->felt_items()->felts()->size() != bins[i]->felt_labels()->felts()->size()))
                {
                    APSI_LOG_ERROR("The loaded BinBundle contains data for " << bins[i]->felt_items()->felts()->size()
                        << " items and " << bins[i]->felt_labels()->felts()->size() << " labels (expected to be equal)");
                    throw runtime_error("failed to load BinBundle");
                }

                for (size_t j = 0; j < bins[i]->felt_items()->felts()->size(); j++)
                {
                    felt_t felt_item = bins[i]->felt_items()->felts()->data()[j];

                    felt_t felt_label = 0;
                    if (labeled)
                    {
                        felt_label = bins[i]->felt_labels()->felts()->data()[j];
                    }

                    // Add the loaded item-label pair to the bin
                    if (!add_to_bin(bins_[i], filters_[i], felt_item, felt_label))
                    {
                        APSI_LOG_ERROR("The loaded BinBundle data contains repeated values for the same bin");
                        throw runtime_error("failed to load BinBundle");
                    }
                }

                regenerate_filter(bins_[i], filters_[i]);
            }

            if (bb->cache())
            {
                const auto &cache = *bb->cache();

                if (cache.felt_matching_polyns()->size() != num_bins)
                {
                    APSI_LOG_ERROR("The loaded BinBundle cache contains an incorrect number ("
                        << cache.felt_matching_polyns()->size() << ") of matching polynomials (expected "
                        << num_bins << ")");
                    throw runtime_error("failed to load BinBundle");
                }

                size_t max_bin_size = 0;
                cache_.felt_matching_polyns.reserve(num_bins);
                for (const auto &felt_matching_polyn : *cache.felt_matching_polyns())
                {
                    FEltPolyn p;
                    p.reserve(felt_matching_polyn->felts()->size());
                    copy(
                        felt_matching_polyn->felts()->cbegin(),
                        felt_matching_polyn->felts()->cend(),
                        back_inserter(p));
                    cache_.felt_matching_polyns.push_back(move(p));
                    max_bin_size = max<size_t>(max_bin_size, felt_matching_polyn->felts()->size());
                }

                if (cache.batched_matching_polyn()->coeffs()->size() != max_bin_size)
                {
                    APSI_LOG_ERROR("The loaded BinBundle cache contains an incorrect number ("
                        << cache.batched_matching_polyn()->coeffs()->size() 
                        << ") of batched matching polynomial coefficients (expected " << max_bin_size << ")");
                    throw runtime_error("failed to load BinBundle");
                }
                for (auto batched_matching_polyn_coeff : *cache.batched_matching_polyn()->coeffs())
                {
                    vector<seal_byte> pt_data;
                    pt_data.reserve(batched_matching_polyn_coeff->data()->size());
                    transform(
                        batched_matching_polyn_coeff->data()->cbegin(),
                        batched_matching_polyn_coeff->data()->cend(),
                        back_inserter(pt_data),
                        [](auto b) { return static_cast<seal_byte>(b); });
                    cache_.batched_matching_polyn.batched_coeffs.push_back(move(pt_data));
                }

                if (labeled)
                {
                    if (!cache.felt_interp_polyns())
                    {
                        APSI_LOG_ERROR("The loaded BinBundle cache does not contain interpolation polynomials");
                        throw runtime_error("failed to load BinBundle");
                    }

                    if (cache.felt_interp_polyns()->size() != num_bins)
                    {
                        APSI_LOG_ERROR("The loaded BinBundle cache contains an incorrect number ("
                            << cache.felt_interp_polyns()->size() << ") of interpolation polynomials (expected "
                            << num_bins << ")");
                        throw runtime_error("failed to load BinBundle");
                    }

                    max_bin_size = 0;
                    cache_.felt_interp_polyns.reserve(num_bins);
                    for (const auto &felt_interp_polyn : *cache.felt_interp_polyns())
                    {
                        FEltPolyn p;
                        p.reserve(felt_interp_polyn->felts()->size());
                        copy(
                            felt_interp_polyn->felts()->cbegin(),
                            felt_interp_polyn->felts()->cend(),
                            back_inserter(p));
                        cache_.felt_interp_polyns.push_back(move(p));
                        max_bin_size = max<size_t>(max_bin_size, felt_interp_polyn->felts()->size());
                    }

                    if (!cache.batched_interp_polyn())
                    {
                        APSI_LOG_ERROR("The loaded BinBundle cache does not contain a batched interpolation polynomial");
                        throw runtime_error("failed to load BinBundle");
                    }

                    if (cache.batched_interp_polyn()->coeffs()->size() != max_bin_size)
                    {
                        APSI_LOG_ERROR("The loaded BinBundle cache contains an incorrect number ("
                            << cache.batched_interp_polyn()->coeffs()->size() 
                            << ") of batched interpolation polynomial coefficients (expected " << max_bin_size << ")");
                        throw runtime_error("failed to load BinBundle");
                    }
                    for (auto batched_interp_polyn_coeff : *cache.batched_interp_polyn()->coeffs())
                    {
                        vector<seal_byte> pt_data;
                        pt_data.reserve(batched_interp_polyn_coeff->data()->size());
                        transform(
                            batched_interp_polyn_coeff->data()->cbegin(),
                            batched_interp_polyn_coeff->data()->cend(),
                            back_inserter(pt_data),
                            [](auto b) { return static_cast<seal_byte>(b); });
                        cache_.batched_interp_polyn.batched_coeffs.push_back(move(pt_data));
                    }
                }

                // Mark the cache as valid
                cache_invalid_ = false;
            }

            return { bundle_idx, in_data.size() };
        }

        // BinBundle will only ever be used with these two label types. Ordinarily we'd have to put method definitions
        // of a template class with the .h file, but if we monomorphize here, we don't have to do that.
        template class BinBundle<monostate>;
        template class BinBundle<felt_t>;
    } // namespace sender
} // namespace apsi
