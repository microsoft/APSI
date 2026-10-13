// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <utility>

// APSI
#include "apsi/bin_bundle.h"
#include "apsi/bin_bundle_generated.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/interpolate.h"
#include "apsi/util/log_noexcept.h"
#include "apsi/util/task_group.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/defines.h"

// The polynomial evaluations below deliberately produce ciphertexts that Microsoft SEAL considers
// transparent, as the comments on each explain, so SEAL has to be built to return one rather than
// reject it. A sender built the other way would fail to answer a legitimate query.
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
#error "APSI requires Microsoft SEAL built with SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF"
#endif

namespace apsi {
    using namespace std;
    using namespace seal;
    using namespace seal::util;
    using namespace util;

    namespace sender {
        using namespace util;

        namespace {
            /**
            Helper function. Determines if a field element is present in a bin.
            */
            bool is_present(const vector<felt_t> &bin, felt_t element)
            {
                return bin.end() != find(bin.begin(), bin.end(), element);
            }

            /**
            Helper function. Determines if a field element is present in a bin.
            */
            bool is_present(const vector<felt_t> &bin, const CuckooFilter &filter, felt_t element)
            {
                // A filter that has refused an item does not know everything the bin holds, so
                // its negative answers stop being conclusive and the bin has to be searched
                // either way. Bins are small, so this costs a scan rather than correctness.
                if (filter.contains(element) || filter.has_dropped_items()) {
                    // Perform a linear search to determine true/false positives
                    return is_present(bin, element);
                }

                return false;
            }

            /**
            Helper function. Returns an iterator pointing to the given field element in the bin if
            found and bin.end() otherwise.
            */
            template <typename BinT>
            auto get_iterator(BinT &bin, const CuckooFilter &filter, felt_t element)
            {
                // See is_present for why a dropped item makes a negative inconclusive.
                if (filter.contains(element) || filter.has_dropped_items()) {
                    return find(bin.begin(), bin.end(), element);
                }

                return bin.end();
            }

            /**
            Helper function. Makes sure that one more element can be appended to the vector
            without allocating, growing its capacity geometrically, as push_back would.
            */
            template <typename T>
            void reserve_one_more(vector<T> &v)
            {
                if (v.size() == v.capacity()) {
                    v.reserve(max<size_t>(v.size() + 1, 2 * v.capacity()));
                }
            }

            /**
            Helper function. Logs that the cuckoo filters of refused_count of the bins beginning at
            start_bin_idx refused an item, once the item is stored. Logging allocates and calls the
            user's handler, either of which can throw, and an exception would report as failed a
            change that has been made; a SenderDB that moves an item between BinBundles relies on
            a change, once begun, not to throw. The message is dropped instead.
            */
            void log_filter_refusals(size_t refused_count, size_t start_bin_idx) noexcept
            {
                log_noexcept([&] {
                    APSI_LOG_DEBUG(
                        "Cuckoo filters for " << refused_count << " of the bins beginning at index "
                                              << start_bin_idx
                                              << " refused an item; lookups in those bins now "
                                                 "search them directly");
                });
            }

            /**
            Helper function for a BinBundle that uses match tags. Finds the item with the given
            field elements and HashedItem in the bins beginning at start_bin_idx, which the caller
            has checked are all in range. Returns false if the item is not stored there, and
            otherwise true, with positions[i] the index of the item in the i-th bin.

            The item is identified by its HashedItem alone. With few bits per item, two items can
            share their field elements, so those cannot tell them apart; they only let the cuckoo
            filter rule out most bins without a search. The field element found with the
            HashedItem must still be the item's, or the two have been stored inconsistently.
            */
            bool find_hashed_item(
                const vector<vector<felt_t>> &item_bins,
                const vector<vector<HashedItem>> &hashed_item_bins,
                const vector<CuckooFilter> &filters,
                const vector<felt_t> &items,
                const HashedItem &item,
                size_t start_bin_idx,
                vector<size_t> &positions)
            {
                positions.clear();
                positions.reserve(items.size());

                size_t curr_bin_idx = start_bin_idx;
                for (felt_t curr_item : items) {
                    // See is_present for why a dropped item makes a negative inconclusive
                    const CuckooFilter &curr_filter = filters[curr_bin_idx];
                    if (!curr_filter.contains(curr_item) && !curr_filter.has_dropped_items()) {
                        return false;
                    }

                    const vector<HashedItem> &hashed_item_bin = hashed_item_bins[curr_bin_idx];
                    auto found = find(hashed_item_bin.begin(), hashed_item_bin.end(), item);
                    if (found == hashed_item_bin.end()) {
                        return false;
                    }

                    auto pos = static_cast<size_t>(distance(hashed_item_bin.begin(), found));
                    if (item_bins[curr_bin_idx][pos] != curr_item) {
                        APSI_LOG_ERROR(
                            "Found an item in the bin at index "
                            << curr_bin_idx
                            << " with a field element other than the one expected; the internal "
                               "state of this BinBundle has been corrupted");
                        return false;
                    }

                    positions.push_back(pos);
                    curr_bin_idx++;
                }

                return true;
            }

            void try_clear_irrelevant_bits(
                const EncryptionParameters &parms, Ciphertext &ciphertext)
            {
                // If the parameter set has only one prime, we can compress the ciphertext by
                // setting low-order bits to zero. This effectively maxes out the noise, but that
                // doesn't matter as long as we don't use quite all noise budget.
                if (parms.coeff_modulus().size() == 1) {
                    // The number of data bits we need to have left in each ciphertext coefficient
                    int compr_coeff_bit_count =
                        parms.plain_modulus().bit_count() +
                        get_significant_bit_count(parms.poly_modulus_degree())
                        // Being pretty aggressive here
                        - 1;

                    int coeff_mod_bit_count = parms.coeff_modulus()[0].bit_count();

                    // The number of bits to set to zero
                    int irrelevant_bit_count = coeff_mod_bit_count - compr_coeff_bit_count;

                    // Can compression achieve anything?
                    if (irrelevant_bit_count > 0) {
                        // Mask for zeroing out the irrelevant bits
                        uint64_t mask = ~((static_cast<uint64_t>(1) << irrelevant_bit_count) - 1);
                        seal_for_each_n(iter(ciphertext), ciphertext.size(), [&](auto &&I) {
                            // We only have a single RNS component so dereference once more
                            seal_for_each_n(
                                *I, parms.poly_modulus_degree(), [&](auto &J) { J &= mask; });
                        });
                    }
                }
            }
        } // namespace

        /**
        Evaluates the polynomial on the given ciphertext. We don't compute the powers of the input
        ciphertext C ourselves. Instead we assume they've been precomputed and accept the powers:
        (C, C², C³, ...) as input. The number of powers provided MUST be at least
        plaintext_polyn_coeffs_.size()-1.
        */
        Ciphertext BatchedPlaintextPolyn::eval(
            const vector<Ciphertext> &ciphertext_powers, MemoryPoolHandle &pool) const
        {
            // We need at least the constant coefficient, which is added below
            if (batched_coeffs.empty()) {
                throw invalid_argument("batched_coeffs cannot be empty");
            }

            // We need to have enough ciphertext powers to evaluate this polynomial
            if (ciphertext_powers.size() < max<size_t>(batched_coeffs.size(), 2)) {
                throw invalid_argument("not enough ciphertext powers available");
            }

            auto seal_context = crypto_context.seal_context();
            auto evaluator = crypto_context.evaluator();

            // We know now that ciphertext_powers is non-empty so read the parms_id from the first
            // one; they should all be the same.
            const auto &encode_parms_id = ciphertext_powers[1].parms_id();

            // Lowest degree terms are stored in the lowest index positions in vectors.
            // Specifically, ciphertext_powers[1] is the first power of the ciphertext data, but
            // batched_coeffs[0] is the constant coefficient.
            //
            // Because the plaintexts in batched_coeffs can be identically zero, SEAL should be
            // built with SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF. We create a result ciphertext
            // that is identically zero and set its NTT form flag to true so the additions below
            // will work.
            Ciphertext result(pool);
            result.resize(*seal_context, encode_parms_id, 2);
            result.is_ntt_form() = true;
            Ciphertext temp(pool);
            Plaintext coeff(pool);
            for (size_t deg = 1; deg < batched_coeffs.size(); deg++) {
                coeff.unsafe_load(
                    *seal_context,
                    reinterpret_cast<const seal_byte *>(batched_coeffs[deg].data()),
                    batched_coeffs[deg].size());
                evaluator->multiply_plain(ciphertext_powers[deg], coeff, temp, pool);
                evaluator->add_inplace(result, temp);
            }

            // Need to transform back from NTT form before we can add the constant coefficient. The
            // constant coefficient is specifically not in NTT form so this can work.
            evaluator->transform_from_ntt_inplace(result);
            coeff.unsafe_load(
                *seal_context,
                reinterpret_cast<const seal_byte *>(batched_coeffs[0].data()),
                batched_coeffs[0].size());
            evaluator->add_plain_inplace(result, coeff);

            // Make the result as small as possible by modulus switching and possibly clearing
            // irrelevant bits.
            while (result.parms_id() != seal_context->last_parms_id()) {
                evaluator->mod_switch_to_next_inplace(result, pool);
            }
            try_clear_irrelevant_bits(seal_context->last_context_data()->parms(), result);

            return result;
        }

        /**
        Evaluates the polynomial on the given ciphertext using the Paterson-Stockmeyer algorithm,
        as long as it requires less computation than the standard evaluation function above.
        The algorithm computes h+1 inner polynomials on low powers (C^1 to C^{l-1}).
        Each inner polynomial is then multiplied by the corresponding high power.
        The parameters l and h are determined according to the degree of the polynomial and the
        number of splits in order to minimize the computation complexity.

        Evaluated polynomial a_0 + a_1*C + a_2*C^2 + ... + C^degree

        Inner polynomials: a_{l*i} + a_{l*i+1}*C + ... + a_{l*i+l-1}*C^{l-1}    (for i=0,...,h-1)
                      and: a_{l*h} + a_{l*h+1}*C + ... + a_{l*h+degree%l}*C^{degree%l}  (for i=h)

        Low powers:  C^{1}, ..., C^{l-1}
        High powers: C^{1*l}, ..., C^{l*h}
        */
        Ciphertext BatchedPlaintextPolyn::eval_patstock(
            const CryptoContext &eval_crypto_context,
            const vector<Ciphertext> &ciphertext_powers,
            size_t ps_low_degree,
            MemoryPoolHandle &pool) const
        {
            // We need at least the constant coefficient, or the degree below would wrap around
            if (batched_coeffs.empty()) {
                throw invalid_argument("batched_coeffs cannot be empty");
            }

            // We need to have enough ciphertext powers to evaluate this polynomial
            if (ciphertext_powers.size() < max<size_t>(batched_coeffs.size(), 2)) {
                throw invalid_argument("not enough ciphertext powers available");
            }

            // This function should not be called when the low-degree is 1
            size_t degree = batched_coeffs.size() - 1;
            if (ps_low_degree <= 1 || ps_low_degree >= degree) {
                throw invalid_argument(
                    "ps_low_degree must be greater than 1 and less than the "
                    "size of batched_coeffs");
            }

            auto seal_context = eval_crypto_context.seal_context();
            auto evaluator = eval_crypto_context.evaluator();
            auto relin_keys = eval_crypto_context.relin_keys();
            bool relinearize = eval_crypto_context.seal_context()->using_keyswitching();

            auto high_powers_parms_id =
                get_parms_id_for_chain_idx(*crypto_context.seal_context(), 1);

            // This is the number of high-degree powers we have: the first high-degree is
            // ps_low_degree + 1 and the rest are multiples of that up to (but not exceeding) the
            // total degree.
            size_t ps_high_degree = ps_low_degree + 1;
            size_t ps_high_degree_powers = degree / ps_high_degree;

            // Lowest degree terms are stored in the lowest index positions in vectors.
            // Specifically, ciphertext_powers[1] is the first power of the ciphertext data, but
            // batched_coeffs[0] is the constant coefficient.
            //
            // Because the plaintexts in batched_coeffs can be identically zero, SEAL should be
            // built with SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF. We create a result ciphertext
            // that is identically zero and set its NTT form flag to true so the additions below
            // will work. The ciphertext here will have three components; we relinearize only at the
            // end.
            Ciphertext result(pool);
            result.resize(*seal_context, high_powers_parms_id, 3);
            result.is_ntt_form() = false;

            // Temporary variables
            Ciphertext temp(pool);
            Ciphertext temp_in(pool);
            Plaintext coeff(pool);

            // Calculate polynomial for i=1,...,ps_high_degree_powers-1
            for (size_t i = 1; i < ps_high_degree_powers; i++) {
                // Evaluate inner polynomial. The free term is left out and added later on.
                // The evaluation result is stored in temp_in.
                for (size_t j = 1; j < ps_high_degree; j++) {
                    coeff.unsafe_load(
                        *seal_context,
                        reinterpret_cast<const seal_byte *>(
                            batched_coeffs[(i * ps_high_degree) + j].data()),
                        batched_coeffs[(i * ps_high_degree) + j].size());

                    evaluator->multiply_plain(ciphertext_powers[j], coeff, temp, pool);

                    if (j == 1) {
                        temp_in = temp;
                    } else {
                        evaluator->add_inplace(temp_in, temp);
                    }
                }

                // Transform inner polynomial to coefficient form
                evaluator->transform_from_ntt_inplace(temp_in);
                evaluator->mod_switch_to_inplace(temp_in, high_powers_parms_id);

                // The high powers are already in coefficient form
                evaluator->multiply_inplace(temp_in, ciphertext_powers[i * ps_high_degree], pool);
                evaluator->add_inplace(result, temp_in);
            }

            // Calculate polynomial for i=ps_high_degree_powers.
            // Done separately because here the degree of the inner poly is degree % ps_high_degree.
            // Once again, the free term will only be added later on.
            if (degree % ps_high_degree > 0) {
                for (size_t j = 1; j <= degree % ps_high_degree; j++) {
                    coeff.unsafe_load(
                        *seal_context,
                        reinterpret_cast<const seal_byte *>(
                            batched_coeffs[(ps_high_degree_powers * ps_high_degree) + j].data()),
                        batched_coeffs[(ps_high_degree_powers * ps_high_degree) + j].size());

                    evaluator->multiply_plain(ciphertext_powers[j], coeff, temp, pool);

                    if (j == 1) {
                        temp_in = temp;
                    } else {
                        evaluator->add_inplace(temp_in, temp);
                    }
                }

                // Transform inner polynomial to coefficient form
                evaluator->transform_from_ntt_inplace(temp_in);
                evaluator->mod_switch_to_inplace(temp_in, high_powers_parms_id);

                // The high powers are already in coefficient form
                evaluator->multiply_inplace(
                    temp_in, ciphertext_powers[ps_high_degree_powers * ps_high_degree], pool);
                evaluator->add_inplace(result, temp_in);
            }

            // Relinearize sum of ciphertext-ciphertext products if relinearization is supported by
            // the parameters.
            if (relinearize) {
                evaluator->relinearize_inplace(result, *relin_keys, pool);
            }

            // Calculate inner polynomial for i=0.
            // Done separately since there is no multiplication with a power of high-degree
            for (size_t j = 1; j < ps_high_degree; j++) {
                coeff.unsafe_load(
                    *seal_context,
                    reinterpret_cast<const seal_byte *>(batched_coeffs[j].data()),
                    batched_coeffs[j].size());

                evaluator->multiply_plain(ciphertext_powers[j], coeff, temp, pool);
                evaluator->transform_from_ntt_inplace(temp);
                evaluator->mod_switch_to_inplace(temp, high_powers_parms_id);
                evaluator->add_inplace(result, temp);
            }

            // Add the constant coefficients of the inner polynomials multiplied by the respective
            // powers of high-degree
            for (size_t i = 1; i < ps_high_degree_powers + 1; i++) {
                coeff.unsafe_load(
                    *seal_context,
                    reinterpret_cast<const seal_byte *>(batched_coeffs[i * ps_high_degree].data()),
                    batched_coeffs[i * ps_high_degree].size());

                evaluator->multiply_plain(ciphertext_powers[i * ps_high_degree], coeff, temp, pool);
                evaluator->mod_switch_to_inplace(temp, high_powers_parms_id);
                evaluator->add_inplace(result, temp);
            }

            // Add the constant coefficient
            coeff.unsafe_load(
                *seal_context,
                reinterpret_cast<const seal_byte *>(batched_coeffs[0].data()),
                batched_coeffs[0].size());

            evaluator->add_plain_inplace(result, coeff);

            // Make the result as small as possible by modulus switching and possibly clearing
            // irrelevant bits.
            while (result.parms_id() != seal_context->last_parms_id()) {
                evaluator->mod_switch_to_next_inplace(result, pool);
            }
            try_clear_irrelevant_bits(seal_context->last_context_data()->parms(), result);

            return result;
        }

        /**
        Constructs a batched Plaintext polynomial from a list of polynomials. Takes an evaluator and
        batch encoder to do encoding and NTT ops.
        */
        BatchedPlaintextPolyn::BatchedPlaintextPolyn(
            const vector<FEltPolyn> &polyns,
            CryptoContext context,
            uint32_t ps_low_degree,
            bool compressed)
            : crypto_context(std::move(context))
        {
            compr_mode_type compr_mode = compressed ? compr_mode_type::zstd : compr_mode_type::none;

            // Find the highest degree polynomial in the list. The max degree determines how many
            // Plaintexts we need to make
            size_t max_deg = 0;
            for (const FEltPolyn &p : polyns) {
                // Degree = number of coefficients - 1
                max_deg = max(p.size(), max_deg + 1) - 1;
            }

            // We will encode with parameters that leave one or two levels, depending on whether
            // Paterson-Stockmeyer is used.
            size_t plain_coeffs_chain_idx = min<size_t>(
                crypto_context.seal_context()->first_context_data()->chain_index(),
                ps_low_degree ? 2 : 1);
            auto encode_parms_id =
                get_parms_id_for_chain_idx(*crypto_context.seal_context(), plain_coeffs_chain_idx);

            // Now make the Plaintexts. We let Plaintext i contain all bin coefficients of degree i.
            size_t num_polyns = polyns.size();
            for (size_t i = 0; i < max_deg + 1; i++) {
                // Go through all the bins, collecting the coefficients at degree i
                vector<felt_t> coeffs_of_deg_i;
                coeffs_of_deg_i.reserve(num_polyns);
                for (const FEltPolyn &p : polyns) {
                    // Get the coefficient if it's set. Otherwise it's zero
                    felt_t coeff = 0;
                    if (i < p.size()) {
                        coeff = p[i];
                    }

                    coeffs_of_deg_i.push_back(coeff);
                }

                // Now let pt be the Plaintext consisting of all those degree i coefficients
                Plaintext pt;
                crypto_context.encoder()->encode(coeffs_of_deg_i, pt);

                // When evaluating the match and interpolation polynomials on encrypted query data,
                // we multiply each power of the encrypted query with a plaintext (pt here)
                // corresponding to the polynomial coefficient, and add the results together. The
                // constant coefficient is handled by simply adding to the result,  which requires
                // that the plaintext is not in NTT form. When Paterson-Stockmeyer is used, this
                // applies also to the constant coefficients for all inner polynomials, i.e., with
                // i a multiple of the ps_high_degree == ps_low_degree + 1.
                if ((!ps_low_degree && (i != 0)) || (ps_low_degree && (i % (ps_low_degree + 1)))) {
                    crypto_context.evaluator()->transform_to_ntt_inplace(pt, encode_parms_id);
                }

                // Push the new Plaintext
                vector<unsigned char> pt_data;
                pt_data.resize(safe_cast<size_t>(pt.save_size(compr_mode)));
                size_t size = static_cast<size_t>(pt.save(
                    reinterpret_cast<seal_byte *>(pt_data.data()), pt_data.size(), compr_mode));
                pt_data.resize(size);
                batched_coeffs.push_back(std::move(pt_data));
            }
        }

        BinBundleCache::BinBundleCache(const CryptoContext &crypto_context, size_t label_size)
            : batched_matching_polyn(crypto_context)
        {
            batched_interp_polyns.reserve(label_size);
            for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                batched_interp_polyns.emplace_back(crypto_context);
            }
        }

        BinBundle::BinBundle(
            CryptoContext crypto_context,
            size_t label_size,
            size_t max_bin_size,
            size_t ps_low_degree,
            size_t num_bins,
            bool compressed,
            bool stripped,
            size_t tag_part_count)
            : crypto_context_(std::move(crypto_context)), compressed_(compressed),
              label_size_(label_size), tag_part_count_(tag_part_count), max_bin_size_(max_bin_size),
              ps_low_degree_(ps_low_degree), num_bins_(num_bins),
              cache_(crypto_context_, label_size_)
        {
            if (!crypto_context_.evaluator()) {
                throw invalid_argument("evaluator is not set in crypto_context");
            }
            if (ps_low_degree > max_bin_size) {
                throw invalid_argument("ps_low_degree cannot be larger than max_bin_size");
            }
            if (!num_bins) {
                throw invalid_argument("num_bins cannot be zero");
            }
            if (tag_part_count > label_size) {
                throw invalid_argument("tag_part_count cannot be larger than label_size");
            }

            // Set up internal data structures
            clear(stripped);
        }

        /**
        Returns the modulus that defines the finite field that we're working in
        */
        const Modulus &BinBundle::field_mod() const
        {
            const auto &context_data = crypto_context_.seal_context()->first_context_data();
            return context_data->parms().plain_modulus();
        }

        template <>
        // Unlabeled overload names its argument 'items' rather than the generic 'item_labels'.
        // NOLINTNEXTLINE(readability-inconsistent-declaration-parameter-name)
        int32_t BinBundle::multi_insert(
            const vector<felt_t> &items, size_t start_bin_idx, bool dry_run)
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot insert data to a stripped BinBundle");
                throw logic_error("failed to insert data");
            }
            if (items.empty()) {
                APSI_LOG_ERROR("No item data to insert");
                return -1;
            }

            // We are inserting items only; no labels. This BinBundle cannot have a non-zero label
            // size.
            if (get_label_size()) {
                APSI_LOG_ERROR("Attempted to insert unlabeled data in a labeled BinBundle");
                throw logic_error("failed to insert data");
            }

            // Return -1 if there isn't enough room in the BinBundle to insert at the given location
            if (start_bin_idx >= get_num_bins() || items.size() > get_num_bins() - start_bin_idx) {
                return -1;
            }

            // If we're here, that means we can insert in all bins
            size_t max_bin_size = 0;
            for (size_t item_idx = 0; item_idx < items.size(); item_idx++) {
                max_bin_size =
                    std::max(max_bin_size, item_bins_[start_bin_idx + item_idx].size() + 1);
            }
            auto new_max_bin_size = safe_cast<int32_t>(max_bin_size);

            if (dry_run) {
                return new_max_bin_size;
            }

            // Make room for the item in every bin it goes into before changing any of them. An
            // allocation that fails then leaves the BinBundle as it was, and nothing below
            // allocates, so the item is stored in full or not at all.
            for (size_t item_idx = 0; item_idx < items.size(); item_idx++) {
                reserve_one_more(item_bins_[start_bin_idx + item_idx]);
            }

            // Store the item at the end of each of its bins. A filter is probabilistic and can
            // refuse an item while holding fewer than the bin does, when enough of them share a
            // fingerprint. The item still goes into the bin; the filter records that it no longer
            // knows everything the bin holds, which is what stops is_present from trusting its
            // negatives.
            size_t refused_count = 0;
            size_t curr_bin_idx = start_bin_idx;
            for (felt_t curr_item : items) {
                if (!filters_[curr_bin_idx].add(curr_item)) {
                    refused_count++;
                }
                item_bins_[curr_bin_idx].push_back(curr_item);

                curr_bin_idx++;
            }

            // Indicate that the polynomials of these bins need to be recomputed
            mark_bins_dirty(start_bin_idx, items.size());

            if (refused_count) {
                log_filter_refusals(refused_count, start_bin_idx);
            }

            return new_max_bin_size;
        }

        template <>
        int32_t BinBundle::multi_insert(
            const vector<pair<felt_t, vector<felt_t>>> &item_labels,
            size_t start_bin_idx,
            bool dry_run)
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot insert data to a stripped BinBundle");
                throw logic_error("failed to insert data");
            }
            if (uses_tags()) {
                APSI_LOG_ERROR(
                    "Attempted to insert an item without its HashedItem in a BinBundle that uses "
                    "match tags");
                throw logic_error("failed to insert data");
            }
            if (item_labels.empty()) {
                APSI_LOG_ERROR("No item or label data to insert");
                return -1;
            }

            // We are inserting item-labels. This BinBundle cannot have a zero label size.
            if (!get_label_size()) {
                APSI_LOG_ERROR("Attempted to insert labeled data in an unlabeled BinBundle");
                throw logic_error("failed to insert data");
            }

            // Check that item_labels has correct size
            size_t label_size = get_label_size();
            for (const auto &curr_item_label : item_labels) {
                size_t curr_label_size = curr_item_label.second.size();
                if (curr_label_size != label_size) {
                    APSI_LOG_ERROR(
                        "Attempted to insert item-label with incorrect label size "
                        << curr_label_size << " (expected " << label_size << ")");
                    throw invalid_argument("failed to insert data");
                }
            }

            // Return -1 if there isn't enough room in the BinBundle to insert at the given location
            if (start_bin_idx >= get_num_bins() ||
                item_labels.size() > get_num_bins() - start_bin_idx) {
                return -1;
            }

            // Do we have a non-zero label size? In that case we cannot have repeated item parts in
            // bins
            if (get_label_size()) {
                // For each key, check that we can insert into the corresponding bin. If the answer
                // is "no" at any point, return -1.
                size_t curr_bin_idx = start_bin_idx;
                for (const auto &curr_item_label : item_labels) {
                    felt_t curr_item = curr_item_label.first;
                    vector<felt_t> &curr_bin = item_bins_[curr_bin_idx];
                    CuckooFilter &curr_filter = filters_[curr_bin_idx];

                    // Check if the key is already in the current bin. If so, that's an insertion
                    // error
                    if (is_present(curr_bin, curr_filter, curr_item)) {
                        return -1;
                    }

                    curr_bin_idx++;
                }
            }

            // If we're here, that means we can insert in all bins
            size_t max_bin_size = 0;
            for (size_t item_idx = 0; item_idx < item_labels.size(); item_idx++) {
                max_bin_size =
                    std::max(max_bin_size, item_bins_[start_bin_idx + item_idx].size() + 1);
            }
            auto new_max_bin_size = safe_cast<int32_t>(max_bin_size);

            if (dry_run) {
                return new_max_bin_size;
            }

            // Make room for the item in every vector it goes into before changing any of them.
            // An allocation that fails then leaves the BinBundle as it was, and nothing below
            // allocates, so the item is stored in full or not at all.
            for (size_t item_idx = 0; item_idx < item_labels.size(); item_idx++) {
                size_t reserve_bin_idx = start_bin_idx + item_idx;
                reserve_one_more(item_bins_[reserve_bin_idx]);
                for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                    reserve_one_more(label_bins_[label_idx][reserve_bin_idx]);
                }
            }

            // Store the item and its label parts at the end of each of its bins
            size_t refused_count = 0;
            size_t curr_bin_idx = start_bin_idx;
            for (const auto &curr_item_label : item_labels) {
                felt_t curr_item = curr_item_label.first;

                // See the unlabeled overload: a refusal is recorded rather than refused, so that
                // the item and its labels stay in step.
                if (!filters_[curr_bin_idx].add(curr_item)) {
                    refused_count++;
                }
                item_bins_[curr_bin_idx].push_back(curr_item);

                // Insert the new label; loop over each label part
                for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                    label_bins_[label_idx][curr_bin_idx].push_back(
                        curr_item_label.second[label_idx]);
                }

                curr_bin_idx++;
            }

            // Indicate that the polynomials of these bins need to be recomputed
            mark_bins_dirty(start_bin_idx, item_labels.size());

            if (refused_count) {
                log_filter_refusals(refused_count, start_bin_idx);
            }

            return new_max_bin_size;
        }

        template <>
        // Unlabeled overload names its argument 'items' rather than the generic 'item_labels'.
        // NOLINTNEXTLINE(readability-inconsistent-declaration-parameter-name)
        bool BinBundle::try_multi_overwrite(const vector<felt_t> &items, size_t start_bin_idx)
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot overwrite data in a stripped BinBundle");
                throw logic_error("failed to overwrite data");
            }
            if (uses_tags()) {
                APSI_LOG_ERROR(
                    "Attempted to overwrite an item without its HashedItem in a BinBundle that "
                    "uses match tags");
                throw logic_error("failed to overwrite data");
            }
            if (items.empty()) {
                APSI_LOG_ERROR("No item data to insert");
                return false;
            }

            // This function may have been called accidentally; no label data is given, so nothing
            // will be overwritten. This is equivalent to searching for the presence of the felt
            // items in this BinBundle and forcing the cache to be recomputed.
            APSI_LOG_WARNING(
                "No label data was given to overwrite existing label data; nothing will be done");

            // Return false if there isn't enough room in the BinBundle to insert at the given
            // location
            if (start_bin_idx >= get_num_bins() || items.size() > get_num_bins() - start_bin_idx) {
                return false;
            }

            // Check that all the item components appear sequentially in this BinBundle
            size_t curr_bin_idx = start_bin_idx;
            for (felt_t curr_item : items) {
                vector<felt_t> &curr_bin = item_bins_[curr_bin_idx];
                CuckooFilter &curr_filter = filters_[curr_bin_idx];

                // A non-match was found; the item is not here.
                if (!is_present(curr_bin, curr_filter, curr_item)) {
                    return false;
                }

                curr_bin_idx++;
            }

            // Nothing was done, but mark every bin as dirty anyway
            mark_bins_dirty(0, get_num_bins());

            return true;
        }

        template <>
        bool BinBundle::try_multi_overwrite(
            const vector<pair<felt_t, vector<felt_t>>> &item_labels, size_t start_bin_idx)
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot overwrite data in a stripped BinBundle");
                throw logic_error("failed to overwrite data");
            }
            if (uses_tags()) {
                APSI_LOG_ERROR(
                    "Attempted to overwrite an item without its HashedItem in a BinBundle that "
                    "uses match tags");
                throw logic_error("failed to overwrite data");
            }
            if (item_labels.empty()) {
                APSI_LOG_ERROR("No item or label data to insert");
                return false;
            }

            // Check that item_labels has correct size
            size_t label_size = get_label_size();
            for (const auto &curr_item_label : item_labels) {
                size_t curr_label_size = curr_item_label.second.size();
                if (curr_label_size != label_size) {
                    APSI_LOG_ERROR(
                        "Attempted to overwrite item-label with incorrect label size "
                        << curr_label_size << " (expected " << label_size << ")");
                    throw invalid_argument("failed to overwrite data");
                }
            }

            // Return false if there isn't enough room in the BinBundle to insert at the given
            // location
            if (start_bin_idx >= get_num_bins() ||
                item_labels.size() > get_num_bins() - start_bin_idx) {
                return false;
            }

            // Check that all the item components appear sequentially in this BinBundle
            size_t curr_bin_idx = start_bin_idx;
            for (const auto &curr_item_label : item_labels) {
                felt_t curr_item = curr_item_label.first;
                vector<felt_t> &curr_bin = item_bins_[curr_bin_idx];
                CuckooFilter &curr_filter = filters_[curr_bin_idx];

                // A non-match was found; the item is not here.
                if (!is_present(curr_bin, curr_filter, curr_item)) {
                    return false;
                }

                curr_bin_idx++;
            }

            // If we're here, that means we can overwrite the labels
            curr_bin_idx = start_bin_idx;
            for (const auto &curr_item_label : item_labels) {
                felt_t curr_item = curr_item_label.first;

                // Overwrite the label in the bin
                vector<felt_t> &curr_bin = item_bins_[curr_bin_idx];

                // No point in using cuckoo filters here for look-up: we know the item exists so do
                // linear search
                auto found_pos = find(curr_bin.begin(), curr_bin.end(), curr_item);

                // From the earlier check we know that found_pos is not the end-iterator. Check this
                // again to be sure.
                if (found_pos == curr_bin.end()) {
                    APSI_LOG_ERROR(
                        "Attempted to overwrite item-label, but the item could no longer be found; "
                        "the internal state of this BinBundle has been corrupted");
                    throw runtime_error("failed to overwrite data");
                }

                // Compute the location in the curr_bin so we know how to index into the label bins
                auto item_idx_in_bin = static_cast<size_t>(distance(curr_bin.begin(), found_pos));

                // Indicate that the polynomials of this bin need to be recomputed
                mark_bins_dirty(curr_bin_idx, 1);

                // Write the new label; loop over each label part
                for (size_t label_idx = 0; label_idx < get_label_size(); label_idx++) {
                    // Overwrite this label part in the matching bin
                    felt_t curr_label = curr_item_label.second[label_idx];
                    label_bins_[label_idx][curr_bin_idx][item_idx_in_bin] = curr_label;
                }

                curr_bin_idx++;
            }

            return true;
        }

        template <>
        // Unlabeled overload names its argument 'items' rather than the generic 'item_labels'.
        // NOLINTNEXTLINE(readability-inconsistent-declaration-parameter-name)
        bool BinBundle::multi_contains(const vector<felt_t> &items, size_t start_bin_idx) const
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot search for data in a stripped BinBundle");
                throw logic_error("failed to search for data");
            }
            if (uses_tags()) {
                APSI_LOG_ERROR(
                    "Attempted to search for an item without its HashedItem in a BinBundle that "
                    "uses match tags");
                throw logic_error("failed to search for data");
            }
            if (items.empty()) {
                APSI_LOG_ERROR("No item data to search for");
                return false;
            }

            // Return false if there isn't enough room in the BinBundle at the given location
            if (start_bin_idx >= get_num_bins() || items.size() > get_num_bins() - start_bin_idx) {
                return false;
            }

            // Every item component must appear in its bin, as try_multi_overwrite and
            // try_multi_remove require
            size_t curr_bin_idx = start_bin_idx;
            for (felt_t curr_item : items) {
                if (!is_present(item_bins_[curr_bin_idx], filters_[curr_bin_idx], curr_item)) {
                    return false;
                }

                curr_bin_idx++;
            }

            return true;
        }

        template <>
        bool BinBundle::multi_contains(
            const vector<pair<felt_t, vector<felt_t>>> &item_labels, size_t start_bin_idx) const
        {
            vector<felt_t> items;
            items.reserve(item_labels.size());
            for (const auto &curr_item_label : item_labels) {
                items.push_back(curr_item_label.first);
            }

            return multi_contains(items, start_bin_idx);
        }

        bool BinBundle::try_multi_remove(const vector<felt_t> &items, size_t start_bin_idx)
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot remove data from a stripped BinBundle");
                throw logic_error("failed to remove data");
            }
            if (uses_tags()) {
                APSI_LOG_ERROR(
                    "Attempted to remove an item without its HashedItem from a BinBundle that uses "
                    "match tags");
                throw logic_error("failed to remove data");
            }
            if (items.empty()) {
                APSI_LOG_ERROR("No item data to remove");
                return false;
            }

            // Return false if there isn't enough room in the BinBundle at the given location
            if (start_bin_idx >= get_num_bins() || items.size() > get_num_bins() - start_bin_idx) {
                return false;
            }

            // Go through all the items. If any item doesn't appear, we scrap the whole computation
            // and return false.
            size_t curr_bin_idx = start_bin_idx;
            vector<vector<felt_t>::iterator> to_remove_item_its;
            vector<vector<vector<felt_t>::iterator>> to_remove_label_its(get_label_size());

            for (const auto &item : items) {
                vector<felt_t> &curr_bin = item_bins_[curr_bin_idx];
                CuckooFilter &curr_filter = filters_[curr_bin_idx];

                auto to_remove_item_it = get_iterator(curr_bin, curr_filter, item);
                if (curr_bin.end() == to_remove_item_it) {
                    // One of the items isn't there; return false;
                    return false;
                }

                // Found the item; mark it for removal
                to_remove_item_its.push_back(to_remove_item_it);

                // We need to also mark the corresponding labels for removal
                auto item_loc_in_bin = distance(curr_bin.begin(), to_remove_item_it);
                for (size_t label_idx = 0; label_idx < get_label_size(); label_idx++) {
                    auto to_remove_label_it =
                        label_bins_[label_idx][curr_bin_idx].begin() + item_loc_in_bin;
                    to_remove_label_its[label_idx].push_back(to_remove_label_it);
                }

                curr_bin_idx++;
            }

            // We got to this point, so all of the items were found. Now just erase them.
            curr_bin_idx = start_bin_idx;
            for (auto to_remove_item_it : to_remove_item_its) {
                // Indicate that the polynomials of this bin need to be recomputed
                mark_bins_dirty(curr_bin_idx, 1);

                // Remove the item. A filter that has refused something holds no tag for what it
                // refused, so finding nothing to remove is expected there and nothing is wrong.
                // A filter that has refused nothing holds a tag for every item in its bin, so
                // finding nothing to remove means the two have drifted apart, which is worth
                // saying even though it costs only a fruitless search later: a tag left behind
                // is a false positive, and those are checked against the bin.
                CuckooFilter &curr_filter = filters_[curr_bin_idx];
                if (!curr_filter.remove(*to_remove_item_it) && !curr_filter.has_dropped_items()) {
                    log_noexcept([&] {
                        APSI_LOG_WARNING(
                            "Cuckoo filter for the bin at index "
                            << curr_bin_idx
                            << " held no tag for an item being removed from the bin");
                    });
                }
                item_bins_[curr_bin_idx].erase(to_remove_item_it);

                curr_bin_idx++;
            }

            // Finally erase the label parts
            for (size_t label_idx = 0; label_idx < get_label_size(); label_idx++) {
                curr_bin_idx = start_bin_idx;
                for (auto to_remove_label_it : to_remove_label_its[label_idx]) {
                    // Remove the label
                    label_bins_[label_idx][curr_bin_idx].erase(to_remove_label_it);

                    curr_bin_idx++;
                }
            }

            return true;
        }

        bool BinBundle::try_get_multi_label(
            const vector<felt_t> &items, size_t start_bin_idx, vector<felt_t> &labels) const
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot retrieve labels from a stripped BinBundle");
                throw logic_error("failed to retrieve labels");
            }
            if (uses_tags()) {
                APSI_LOG_ERROR(
                    "Attempted to retrieve labels without a HashedItem from a BinBundle that uses "
                    "match tags");
                throw logic_error("failed to retrieve labels");
            }
            if (items.empty()) {
                APSI_LOG_ERROR("No item data to search for");
                return false;
            }

            // Return false if there isn't enough room in the BinBundle at the given location
            if (start_bin_idx >= get_num_bins() || items.size() > get_num_bins() - start_bin_idx) {
                return false;
            }

            // Resize the labels vector to expected size; we will write in a non-linear order
            labels.clear();
            labels.resize(mul_safe(items.size(), get_label_size()));

            // Go through all the items. If the item appears, find its label and write to labels. If
            // any item doesn't appear, we scrap the whole computation and return false.
            size_t curr_bin_idx = start_bin_idx;
            for (size_t item_idx = 0; item_idx < items.size(); item_idx++) {
                const vector<felt_t> &curr_bin = item_bins_[curr_bin_idx];
                const CuckooFilter &curr_filter = filters_[curr_bin_idx];

                // Find the item if present in this bin
                auto item_it = get_iterator(curr_bin, curr_filter, items[item_idx]);

                if (curr_bin.end() == item_it) {
                    // One of the items isn't there. No label to fetch. Clear the labels and return
                    // early.
                    labels.clear();
                    return false;
                }

                // Found the (felt) item. Next collect the label parts for this and write to label.
                size_t item_idx_in_bin = static_cast<size_t>(distance(curr_bin.begin(), item_it));
                for (size_t label_idx = 0; label_idx < get_label_size(); label_idx++) {
                    // Need to reorder the felts
                    labels[(items.size() * label_idx) + item_idx] =
                        label_bins_[label_idx][curr_bin_idx][item_idx_in_bin];
                }

                curr_bin_idx++;
            }

            return true;
        }

        int32_t BinBundle::multi_insert(
            const TaggedAlgItemLabel &item, size_t start_bin_idx, bool dry_run)
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot insert data to a stripped BinBundle");
                throw logic_error("failed to insert data");
            }
            if (!uses_tags()) {
                APSI_LOG_ERROR(
                    "Attempted to insert an item with its HashedItem in a BinBundle that does not "
                    "use match tags");
                throw logic_error("failed to insert data");
            }

            const AlgItemLabel &item_labels = item.alg_item_label;
            if (item_labels.empty()) {
                APSI_LOG_ERROR("No item or label data to insert");
                return -1;
            }

            // Check that item_labels has correct size
            size_t label_size = get_label_size();
            for (const auto &curr_item_label : item_labels) {
                size_t curr_label_size = curr_item_label.second.size();
                if (curr_label_size != label_size) {
                    APSI_LOG_ERROR(
                        "Attempted to insert item-label with incorrect label size "
                        << curr_label_size << " (expected " << label_size << ")");
                    throw invalid_argument("failed to insert data");
                }
            }

            // Return -1 if there isn't enough room in the BinBundle to insert at the given location
            if (start_bin_idx >= get_num_bins() ||
                item_labels.size() > get_num_bins() - start_bin_idx) {
                return -1;
            }

            // The label polynomials interpolate through the items' field elements, so an item
            // whose field element is already in its bin cannot be inserted here
            size_t curr_bin_idx = start_bin_idx;
            for (const auto &curr_item_label : item_labels) {
                if (is_present(
                        item_bins_[curr_bin_idx], filters_[curr_bin_idx], curr_item_label.first)) {
                    return -1;
                }

                curr_bin_idx++;
            }

            // If we're here, that means we can insert in all bins
            size_t max_bin_size = 0;
            for (size_t item_idx = 0; item_idx < item_labels.size(); item_idx++) {
                max_bin_size =
                    std::max(max_bin_size, item_bins_[start_bin_idx + item_idx].size() + 1);
            }
            auto new_max_bin_size = safe_cast<int32_t>(max_bin_size);

            if (dry_run) {
                return new_max_bin_size;
            }

            // Make room for the item in every vector it goes into before changing any of them.
            // An allocation that fails then leaves the BinBundle as it was, and nothing below
            // allocates, so the item is stored in full or not at all.
            for (size_t item_idx = 0; item_idx < item_labels.size(); item_idx++) {
                size_t reserve_bin_idx = start_bin_idx + item_idx;
                reserve_one_more(item_bins_[reserve_bin_idx]);
                reserve_one_more(hashed_item_bins_[reserve_bin_idx]);
                for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                    reserve_one_more(label_bins_[label_idx][reserve_bin_idx]);
                }
            }

            // Store the item, its HashedItem and its label parts at the end of each of its bins
            size_t refused_count = 0;
            curr_bin_idx = start_bin_idx;
            for (const auto &curr_item_label : item_labels) {
                felt_t curr_item = curr_item_label.first;

                // See the unlabeled overload: a refusal is recorded rather than refused, so that
                // the item, its labels and its HashedItem stay in step.
                if (!filters_[curr_bin_idx].add(curr_item)) {
                    refused_count++;
                }
                item_bins_[curr_bin_idx].push_back(curr_item);
                hashed_item_bins_[curr_bin_idx].push_back(item.item);

                // Insert the new label; loop over each label part
                for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                    label_bins_[label_idx][curr_bin_idx].push_back(
                        curr_item_label.second[label_idx]);
                }

                curr_bin_idx++;
            }

            // Indicate that the polynomials of these bins need to be recomputed
            mark_bins_dirty(start_bin_idx, item_labels.size());

            if (refused_count) {
                log_filter_refusals(refused_count, start_bin_idx);
            }

            return new_max_bin_size;
        }

        bool BinBundle::try_multi_replace(
            const HashedItem &stored_item,
            size_t pos,
            const TaggedAlgItemLabel &item,
            size_t start_bin_idx,
            bool dry_run)
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot replace data in a stripped BinBundle");
                throw logic_error("failed to replace data");
            }
            if (!uses_tags()) {
                APSI_LOG_ERROR(
                    "Attempted to replace an item by its HashedItem in a BinBundle that does not "
                    "use match tags");
                throw logic_error("failed to replace data");
            }

            const AlgItemLabel &item_labels = item.alg_item_label;
            if (item_labels.empty()) {
                APSI_LOG_ERROR("No item or label data to replace with");
                return false;
            }

            // Check that item_labels has correct size
            size_t label_size = get_label_size();
            for (const auto &curr_item_label : item_labels) {
                size_t curr_label_size = curr_item_label.second.size();
                if (curr_label_size != label_size) {
                    APSI_LOG_ERROR(
                        "Attempted to replace an item with an item-label of incorrect label size "
                        << curr_label_size << " (expected " << label_size << ")");
                    throw invalid_argument("failed to replace data");
                }
            }

            // Return false if there isn't enough room in the BinBundle at the given location
            if (start_bin_idx >= get_num_bins() ||
                item_labels.size() > get_num_bins() - start_bin_idx) {
                return false;
            }

            // The stored item must be at position pos of every bin; if it is not, this BinBundle
            // is left as it is. Its place is given rather than searched for, so that nothing here
            // allocates.
            for (size_t item_idx = 0; item_idx < item_labels.size(); item_idx++) {
                size_t curr_bin_idx = start_bin_idx + item_idx;
                const vector<HashedItem> &hashed_item_bin = hashed_item_bins_[curr_bin_idx];
                if ((pos >= item_bins_[curr_bin_idx].size()) || (pos >= hashed_item_bin.size()) ||
                    !(hashed_item_bin[pos] == stored_item)) {
                    return false;
                }
                for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                    if (pos >= label_bins_[label_idx][curr_bin_idx].size()) {
                        return false;
                    }
                }
            }

            // The label polynomials need distinct points, so each of the new item's field
            // elements may be in its bin only where the stored item's is, which it replaces
            for (size_t item_idx = 0; item_idx < item_labels.size(); item_idx++) {
                size_t curr_bin_idx = start_bin_idx + item_idx;
                const vector<felt_t> &curr_bin = item_bins_[curr_bin_idx];
                auto found =
                    get_iterator(curr_bin, filters_[curr_bin_idx], item_labels[item_idx].first);
                if ((found != curr_bin.end()) &&
                    (static_cast<size_t>(distance(curr_bin.begin(), found)) != pos)) {
                    return false;
                }
            }

            if (dry_run) {
                return true;
            }

            // Nothing below allocates: the new item takes the stored item's places
            size_t refused_count = 0;
            for (size_t item_idx = 0; item_idx < item_labels.size(); item_idx++) {
                size_t curr_bin_idx = start_bin_idx + item_idx;
                felt_t stored_felt = item_bins_[curr_bin_idx][pos];
                felt_t new_felt = item_labels[item_idx].first;

                // The stored item was found, so its tag is in the filter unless the filter has
                // dropped one; see try_multi_remove
                if (stored_felt != new_felt) {
                    CuckooFilter &curr_filter = filters_[curr_bin_idx];
                    static_cast<void>(curr_filter.remove(stored_felt));
                    if (!curr_filter.add(new_felt)) {
                        refused_count++;
                    }
                }

                item_bins_[curr_bin_idx][pos] = new_felt;
                hashed_item_bins_[curr_bin_idx][pos] = item.item;
                for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                    label_bins_[label_idx][curr_bin_idx][pos] =
                        item_labels[item_idx].second[label_idx];
                }
            }

            // Indicate that the polynomials of these bins need to be recomputed
            mark_bins_dirty(start_bin_idx, item_labels.size());

            if (refused_count) {
                log_filter_refusals(refused_count, start_bin_idx);
            }

            return true;
        }

        bool BinBundle::try_multi_overwrite(const TaggedAlgItemLabel &item, size_t start_bin_idx)
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot overwrite data in a stripped BinBundle");
                throw logic_error("failed to overwrite data");
            }
            if (!uses_tags()) {
                APSI_LOG_ERROR(
                    "Attempted to overwrite an item by its HashedItem in a BinBundle that does not "
                    "use match tags");
                throw logic_error("failed to overwrite data");
            }

            const AlgItemLabel &item_labels = item.alg_item_label;
            if (item_labels.empty()) {
                APSI_LOG_ERROR("No item or label data to insert");
                return false;
            }

            // Check that item_labels has correct size
            size_t label_size = get_label_size();
            for (const auto &curr_item_label : item_labels) {
                size_t curr_label_size = curr_item_label.second.size();
                if (curr_label_size != label_size) {
                    APSI_LOG_ERROR(
                        "Attempted to overwrite item-label with incorrect label size "
                        << curr_label_size << " (expected " << label_size << ")");
                    throw invalid_argument("failed to overwrite data");
                }
            }

            // Return false if there isn't enough room in the BinBundle at the given location
            if (start_bin_idx >= get_num_bins() ||
                item_labels.size() > get_num_bins() - start_bin_idx) {
                return false;
            }

            // Find the item by its HashedItem. If it is not here, this BinBundle is left as it is.
            vector<felt_t> items;
            items.reserve(item_labels.size());
            for (const auto &curr_item_label : item_labels) {
                items.push_back(curr_item_label.first);
            }

            vector<size_t> positions;
            if (!find_hashed_item(
                    item_bins_,
                    hashed_item_bins_,
                    filters_,
                    items,
                    item.item,
                    start_bin_idx,
                    positions)) {
                return false;
            }

            // Indicate that the polynomials of these bins need to be recomputed
            mark_bins_dirty(start_bin_idx, item_labels.size());

            // The tag parts are the same as before, as the tag depends only on the item, but
            // writing every label part keeps this simple
            for (size_t item_idx = 0; item_idx < item_labels.size(); item_idx++) {
                for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                    label_bins_[label_idx][start_bin_idx + item_idx][positions[item_idx]] =
                        item_labels[item_idx].second[label_idx];
                }
            }

            return true;
        }

        bool BinBundle::multi_contains(
            const vector<felt_t> &items, const HashedItem &item, size_t start_bin_idx) const
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot search for data in a stripped BinBundle");
                throw logic_error("failed to search for data");
            }
            if (!uses_tags()) {
                APSI_LOG_ERROR(
                    "Attempted to search for an item by its HashedItem in a BinBundle that does "
                    "not use match tags");
                throw logic_error("failed to search for data");
            }
            if (items.empty()) {
                APSI_LOG_ERROR("No item data to search for");
                return false;
            }

            // Return false if there isn't enough room in the BinBundle at the given location
            if (start_bin_idx >= get_num_bins() || items.size() > get_num_bins() - start_bin_idx) {
                return false;
            }

            vector<size_t> positions;
            return find_hashed_item(
                item_bins_, hashed_item_bins_, filters_, items, item, start_bin_idx, positions);
        }

        bool BinBundle::multi_contains(const TaggedAlgItemLabel &item, size_t start_bin_idx) const
        {
            vector<felt_t> items;
            items.reserve(item.alg_item_label.size());
            for (const auto &curr_item_label : item.alg_item_label) {
                items.push_back(curr_item_label.first);
            }

            return multi_contains(items, item.item, start_bin_idx);
        }

        bool BinBundle::try_multi_remove(
            const vector<felt_t> &items, const HashedItem &item, size_t start_bin_idx)
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot remove data from a stripped BinBundle");
                throw logic_error("failed to remove data");
            }
            if (!uses_tags()) {
                APSI_LOG_ERROR(
                    "Attempted to remove an item by its HashedItem from a BinBundle that does not "
                    "use match tags");
                throw logic_error("failed to remove data");
            }
            if (items.empty()) {
                APSI_LOG_ERROR("No item data to remove");
                return false;
            }

            // Return false if there isn't enough room in the BinBundle at the given location
            if (start_bin_idx >= get_num_bins() || items.size() > get_num_bins() - start_bin_idx) {
                return false;
            }

            // Find the item. If it is not here, this BinBundle is left as it is.
            vector<size_t> positions;
            if (!find_hashed_item(
                    item_bins_,
                    hashed_item_bins_,
                    filters_,
                    items,
                    item,
                    start_bin_idx,
                    positions)) {
                return false;
            }

            // Indicate that the polynomials of these bins need to be recomputed
            mark_bins_dirty(start_bin_idx, items.size());

            for (size_t item_idx = 0; item_idx < items.size(); item_idx++) {
                size_t curr_bin_idx = start_bin_idx + item_idx;
                auto pos = static_cast<ptrdiff_t>(positions[item_idx]);

                // See the overload without a HashedItem for when a filter may hold no tag for the
                // item
                CuckooFilter &curr_filter = filters_[curr_bin_idx];
                if (!curr_filter.remove(items[item_idx]) && !curr_filter.has_dropped_items()) {
                    log_noexcept([&] {
                        APSI_LOG_WARNING(
                            "Cuckoo filter for the bin at index "
                            << curr_bin_idx
                            << " held no tag for an item being removed from the bin");
                    });
                }

                // Remove the item, its HashedItem and its label parts, all at the same position
                vector<felt_t> &curr_bin = item_bins_[curr_bin_idx];
                curr_bin.erase(curr_bin.begin() + pos);
                vector<HashedItem> &hashed_item_bin = hashed_item_bins_[curr_bin_idx];
                hashed_item_bin.erase(hashed_item_bin.begin() + pos);
                for (size_t label_idx = 0; label_idx < get_label_size(); label_idx++) {
                    vector<felt_t> &label_bin = label_bins_[label_idx][curr_bin_idx];
                    label_bin.erase(label_bin.begin() + pos);
                }
            }

            return true;
        }

        bool BinBundle::try_get_multi_label(
            const vector<felt_t> &items,
            const HashedItem &item,
            size_t start_bin_idx,
            vector<felt_t> &labels) const
        {
            if (stripped_) {
                APSI_LOG_ERROR("Cannot retrieve labels from a stripped BinBundle");
                throw logic_error("failed to retrieve labels");
            }
            if (!uses_tags()) {
                APSI_LOG_ERROR(
                    "Attempted to retrieve labels by HashedItem from a BinBundle that does not use "
                    "match tags");
                throw logic_error("failed to retrieve labels");
            }
            if (items.empty()) {
                APSI_LOG_ERROR("No item data to search for");
                return false;
            }

            // Return false if there isn't enough room in the BinBundle at the given location
            if (start_bin_idx >= get_num_bins() || items.size() > get_num_bins() - start_bin_idx) {
                return false;
            }

            vector<size_t> positions;
            if (!find_hashed_item(
                    item_bins_,
                    hashed_item_bins_,
                    filters_,
                    items,
                    item,
                    start_bin_idx,
                    positions)) {
                labels.clear();
                return false;
            }

            // Lay the label parts out as the overload without a HashedItem does
            labels.clear();
            labels.resize(mul_safe(items.size(), get_label_size()));
            for (size_t item_idx = 0; item_idx < items.size(); item_idx++) {
                for (size_t label_idx = 0; label_idx < get_label_size(); label_idx++) {
                    labels[(items.size() * label_idx) + item_idx] =
                        label_bins_[label_idx][start_bin_idx + item_idx][positions[item_idx]];
                }
            }

            return true;
        }

        void BinBundle::clear(bool stripped)
        {
            // Set the stripped flag
            stripped_ = stripped;

            // Clear item data
            item_bins_.clear();
            if (!stripped_) {
                item_bins_.resize(num_bins_);
            }

            // Clear the HashedItems kept alongside the items with match tags
            hashed_item_bins_.clear();
            if (!stripped_ && uses_tags()) {
                hashed_item_bins_.resize(num_bins_);
            }

            // Clear label data
            label_bins_.clear();
            if (!stripped_) {
                label_bins_.reserve(label_size_);
                for (size_t i = 0; i < label_size_; i++) {
                    label_bins_.emplace_back(num_bins_);
                }
            }

            // Clear filters
            filters_.clear();
            if (!stripped_) {
                filters_.reserve(num_bins_);
                for (size_t i = 0; i < num_bins_; i++) {
                    filters_.emplace_back(max_bin_size_, /* bits per tag */ 12);
                }
            }

            // Clear the cache
            clear_cache();
        }

        void BinBundle::clear_cache()
        {
            cache_.felt_matching_polyns.clear();
            cache_.batched_matching_polyn = crypto_context_;

            cache_.felt_interp_polyns.clear();
            cache_.batched_interp_polyns.clear();

            // The polynomials of the bins are gone, so every bin is to be interpolated again
            dirty_bins_.assign(num_bins_, true);
            cache_invalid_ = true;
        }

        void BinBundle::mark_bins_dirty(size_t start_bin_idx, size_t count) noexcept
        {
            cache_invalid_ = true;

            // The callers have checked the range. Should it nevertheless not lie within the
            // BinBundle, marking every bin is safe where marking too few is not.
            size_t bin_count = dirty_bins_.size();
            if ((start_bin_idx > bin_count) || (count > bin_count - start_bin_idx)) {
                fill(dirty_bins_.begin(), dirty_bins_.end(), true);
                return;
            }

            fill_n(dirty_bins_.begin() + static_cast<ptrdiff_t>(start_bin_idx), count, true);
        }

        bool BinBundle::polyns_reusable() const
        {
            // There is nothing to keep unless some bin is not dirty
            if (find(dirty_bins_.begin(), dirty_bins_.end(), false) == dirty_bins_.end()) {
                return false;
            }

            // Otherwise the cache must hold the polynomials of every bin: a matching polynomial,
            // unless there are match tags, and a label polynomial for each label part
            size_t num_bins = get_num_bins();
            size_t label_size = get_label_size();
            bool reusable = (dirty_bins_.size() == num_bins) && (item_bins_.size() == num_bins) &&
                            (cache_.felt_matching_polyns.size() == (uses_tags() ? 0 : num_bins)) &&
                            (cache_.felt_interp_polyns.size() == label_size);
            for (const auto &fips : cache_.felt_interp_polyns) {
                reusable = reusable && (fips.size() == num_bins);
            }

            // A bin of n items that is not dirty must have polynomials of the sizes regen_polyns
            // computes: n + 1 coefficients for its matching polynomial and max(n, 1) for its label
            // polynomials. This costs little to check, and refuses the polynomials of a bin changed
            // without being marked dirty.
            for (size_t bin_idx = 0; reusable && (bin_idx < num_bins); bin_idx++) {
                if (dirty_bins_[bin_idx]) {
                    continue;
                }

                size_t item_count = item_bins_[bin_idx].size();
                if (!uses_tags()) {
                    reusable = (cache_.felt_matching_polyns[bin_idx].size() == item_count + 1);
                }

                size_t label_coeff_count = max<size_t>(item_count, 1);
                for (const auto &fips : cache_.felt_interp_polyns) {
                    reusable = reusable && (fips[bin_idx].size() == label_coeff_count);
                }
            }

            if (!reusable) {
                log_noexcept([] {
                    APSI_LOG_WARNING(
                        "The cache of a BinBundle does not hold the polynomials of the bins that "
                        "have not changed; the polynomials of every bin will be computed again");
                });
            }

            return reusable;
        }

        const BinBundleCache &BinBundle::get_cache() const
        {
            if (cache_invalid_) {
                throw logic_error("tried to retrieve stale cache");
            }

            return cache_;
        }

        void BinBundle::regen_plaintexts()
        {
            // This function assumes that BinBundle::regen_polyns has been called and the
            // polynomials have not been modified since then. Each plaintext holds the coefficients
            // of one degree of every bin, so all of them are made from the polynomials of all the
            // bins, and how many there are follows from the largest of those polynomials.

            // Allocate memory for the batched "label polynomials"
            cache_.batched_interp_polyns.resize(get_label_size());

            ThreadPoolMgr tpm;

            TaskGroup tasks(tpm.thread_pool());

            // Compute and cache the batched "matching polynomials". They're computed in both
            // labeled and unlabeled PSI, but not with match tags, which need none.
            if (!uses_tags()) {
                tasks.add([&] {
                    BatchedPlaintextPolyn bmp(
                        cache_.felt_matching_polyns,
                        crypto_context_,
                        static_cast<uint32_t>(ps_low_degree_),
                        compressed_);
                    cache_.batched_matching_polyn = std::move(bmp);
                });
            }

            for (size_t label_idx = 0; label_idx < cache_.felt_interp_polyns.size(); label_idx++) {
                tasks.add([&, label_idx] {
                    // Compute and cache the batched Newton interpolation polynomials
                    const auto &interp_polyn = cache_.felt_interp_polyns[label_idx];
                    BatchedPlaintextPolyn bip(
                        interp_polyn,
                        crypto_context_,
                        static_cast<uint32_t>(ps_low_degree_),
                        compressed_);
                    cache_.batched_interp_polyns[label_idx] = std::move(bip);
                });
            }

            // Wait for the tasks to finish
            tasks.join();
        }

        void BinBundle::regen_polyns()
        {
            // This function assumes that the cache holds the polynomials of every bin that is not
            // dirty, as polyns_reusable checks, or that it has been cleared, which makes every bin
            // dirty. It computes the polynomials of the dirty bins and keeps those of the others.

            // Get the field modulus. We need this for polynomial calculations
            const Modulus &mod = field_mod();

            // Make room for the polynomials of every bin. Resizing keeps those of the bins that are
            // not dirty.
            size_t num_bins = get_num_bins();
            size_t label_size = get_label_size();
            if (!uses_tags()) {
                cache_.felt_matching_polyns.resize(num_bins);
            }
            cache_.felt_interp_polyns.resize(label_size);
            for (auto &fips : cache_.felt_interp_polyns) {
                fips.resize(num_bins);
            }

            auto dirty_count =
                static_cast<size_t>(count(dirty_bins_.begin(), dirty_bins_.end(), true));
            log_noexcept([&] {
                APSI_LOG_DEBUG(
                    "Computing the polynomials of " << dirty_count << " of " << num_bins
                                                    << " bins of a BinBundle");
            });

            ThreadPoolMgr tpm;

            TaskGroup tasks(tpm.thread_pool());
            tasks.reserve(dirty_count);

            // The dirty bins are read only here, as the tasks are added, and are not changed until
            // the tasks have finished
            if (!label_size) {
                // For each dirty bin in the bundle, compute and cache the corresponding "matching
                // polynomial"
                for (size_t bin_idx = 0; bin_idx < num_bins; bin_idx++) {
                    if (!dirty_bins_[bin_idx]) {
                        continue;
                    }

                    tasks.add([&, bin_idx] {
                        // Compute and cache the matching polynomial
                        FEltPolyn fmp = polyn_with_roots(item_bins_[bin_idx], mod);
                        cache_.felt_matching_polyns[bin_idx] = std::move(fmp);
                    });
                }
            } else {
                // For each dirty bin in the bundle, compute and cache the corresponding "matching
                // polynomial" and "label polynomials". They have the same roots and interpolation
                // points, so computing them together shares most of the work. With match tags no
                // matching polynomial is kept: the tag parts, which are label parts, decide
                // whether an item matches.
                for (size_t bin_idx = 0; bin_idx < num_bins; bin_idx++) {
                    if (!dirty_bins_[bin_idx]) {
                        continue;
                    }

                    tasks.add([&, bin_idx] {
                        vector<gsl::span<const felt_t>> label_values;
                        label_values.reserve(label_size);
                        for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                            label_values.emplace_back(label_bins_[label_idx][bin_idx]);
                        }

                        // Compute and cache the matching polynomial and the label polynomials
                        FEltPolyn fmp;
                        vector<FEltPolyn> fips = newton_interpolate_polyns(
                            item_bins_[bin_idx], label_values, mod, uses_tags() ? nullptr : &fmp);
                        if (!uses_tags()) {
                            cache_.felt_matching_polyns[bin_idx] = std::move(fmp);
                        }
                        for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                            cache_.felt_interp_polyns[label_idx][bin_idx] =
                                std::move(fips[label_idx]);
                        }
                    });
                }
            }

            // Wait for the tasks to finish
            tasks.join();
        }

        void BinBundle::regen_cache()
        {
            // Only recompute the cache if it needs to be recomputed
            if (cache_invalid_) {
                // Keep the polynomials of the bins that are not dirty if the cache holds them, and
                // otherwise clear the cache, which makes every bin dirty. Either way, free the
                // plaintexts before making new ones: each holds coefficients of every bin.
                if (polyns_reusable()) {
                    cache_.batched_matching_polyn = crypto_context_;
                    cache_.batched_interp_polyns.clear();
                } else {
                    clear_cache();
                }

                regen_polyns();
                regen_plaintexts();

                // The polynomials of every bin are now those of its items. Had anything above
                // thrown, the dirty bins would have stayed dirty, and the cache invalid.
                fill(dirty_bins_.begin(), dirty_bins_.end(), false);
                cache_invalid_ = false;
            }
        }

        bool BinBundle::empty() const
        {
            return all_of(item_bins_.begin(), item_bins_.end(), [](auto &b) { return b.empty(); });
        }

        void BinBundle::strip()
        {
            // Ensure the cache is valid
            regen_cache();

            stripped_ = true;

            item_bins_.clear();
            hashed_item_bins_.clear();
            label_bins_.clear();
            filters_.clear();

            cache_.felt_matching_polyns.clear();
            cache_.felt_interp_polyns.clear();

            // The cache no longer holds the polynomials of the bins
            fill(dirty_bins_.begin(), dirty_bins_.end(), true);
        }

        namespace {
            flatbuffers::Offset<fbs::FEltArray> fbs_create_felt_array(
                flatbuffers::FlatBufferBuilder &fbs_builder, const vector<felt_t> &felts)
            {
                auto felt_array_data = fbs_builder.CreateVector(felts);
                return fbs::CreateFEltArray(fbs_builder, felt_array_data);
            }

            flatbuffers::Offset<fbs::FEltMatrix> fbs_create_felt_matrix(
                flatbuffers::FlatBufferBuilder &fbs_builder, const vector<vector<felt_t>> &felts)
            {
                auto felt_matrix_data = fbs_builder.CreateVector([&] {
                    vector<flatbuffers::Offset<fbs::FEltArray>> ret;
                    ret.reserve(felts.size());
                    for (const auto &felts_row : felts) {
                        ret.push_back(fbs_create_felt_array(fbs_builder, felts_row));
                    }
                    return ret;
                }());
                return fbs::CreateFEltMatrix(fbs_builder, felt_matrix_data);
            }

            flatbuffers::Offset<fbs::Plaintext> fbs_create_plaintext(
                flatbuffers::FlatBufferBuilder &fbs_builder, const vector<unsigned char> &pt)
            {
                auto pt_data = fbs_builder.CreateVector(
                    reinterpret_cast<const uint8_t *>(pt.data()), pt.size());
                return fbs::CreatePlaintext(fbs_builder, pt_data);
            }

            flatbuffers::Offset<fbs::BatchedPlaintextPolyn> fbs_create_batched_plaintext_polyn(
                flatbuffers::FlatBufferBuilder &fbs_builder,
                const vector<vector<unsigned char>> &polyn)
            {
                auto polyn_data = fbs_builder.CreateVector([&] {
                    vector<flatbuffers::Offset<fbs::Plaintext>> ret;
                    ret.reserve(polyn.size());
                    for (const auto &coeff : polyn) {
                        ret.push_back(fbs_create_plaintext(fbs_builder, coeff));
                    }
                    return ret;
                }());
                return fbs::CreateBatchedPlaintextPolyn(fbs_builder, polyn_data);
            }
        } // namespace

        size_t BinBundle::save(ostream &out, uint32_t bundle_idx) const
        {
            flatbuffers::FlatBufferBuilder fbs_builder(1024);

            // Write the items and labels
            auto item_bins = fbs_create_felt_matrix(fbs_builder, item_bins_);
            auto label_bins = fbs_builder.CreateVector([&] {
                vector<flatbuffers::Offset<fbs::FEltMatrix>> ret;
                ret.reserve(label_bins_.size());
                for (const auto &bin : label_bins_) {
                    ret.push_back(fbs_create_felt_matrix(fbs_builder, bin));
                }
                return ret;
            }());

            flatbuffers::Offset<fbs::BinBundleCache> bin_bundle_cache;
            if (!cache_invalid_) {
                // With match tags there is no matching polynomial, so its fields are left out;
                // without them, they are written first, as in APSI 1.x.
                flatbuffers::Offset<fbs::FEltMatrix> felt_matching_polyns;
                flatbuffers::Offset<fbs::BatchedPlaintextPolyn> batched_matching_polyn;
                if (!uses_tags()) {
                    felt_matching_polyns =
                        fbs_create_felt_matrix(fbs_builder, cache_.felt_matching_polyns);
                    batched_matching_polyn = fbs_create_batched_plaintext_polyn(
                        fbs_builder, cache_.batched_matching_polyn.batched_coeffs);
                }

                auto felt_interp_polyns = fbs_builder.CreateVector([&] {
                    vector<flatbuffers::Offset<fbs::FEltMatrix>> ret;
                    ret.reserve(cache_.felt_interp_polyns.size());
                    for (const auto &fips : cache_.felt_interp_polyns) {
                        ret.push_back(fbs_create_felt_matrix(fbs_builder, fips));
                    }
                    return ret;
                }());

                auto batched_interp_polyns = fbs_builder.CreateVector([&] {
                    vector<flatbuffers::Offset<fbs::BatchedPlaintextPolyn>> ret;
                    ret.reserve(cache_.batched_interp_polyns.size());
                    for (const auto &bips : cache_.batched_interp_polyns) {
                        ret.push_back(
                            fbs_create_batched_plaintext_polyn(fbs_builder, bips.batched_coeffs));
                    }
                    return ret;
                }());

                fbs::BinBundleCacheBuilder bin_bundle_cache_builder(fbs_builder);
                if (!uses_tags()) {
                    bin_bundle_cache_builder.add_felt_matching_polyns(felt_matching_polyns);
                    bin_bundle_cache_builder.add_batched_matching_polyn(batched_matching_polyn);
                }
                bin_bundle_cache_builder.add_felt_interp_polyns(felt_interp_polyns);
                bin_bundle_cache_builder.add_batched_interp_polyns(batched_interp_polyns);
                bin_bundle_cache = bin_bundle_cache_builder.Finish();
            }

            // Write the HashedItems kept alongside the items, bin by bin, for a BinBundle with
            // match tags that is not stripped; any other BinBundle has none
            bool has_hashed_items = uses_tags() && !stripped_;
            flatbuffers::Offset<flatbuffers::Vector<const fbs::ItemHash *>> hashed_items;
            if (has_hashed_items) {
                hashed_items = fbs_builder.CreateVectorOfStructs([&] {
                    vector<fbs::ItemHash> ret;
                    for (const auto &hashed_item_bin : hashed_item_bins_) {
                        for (const auto &hashed_item : hashed_item_bin) {
                            // Read the two 64-bit halves with memcpy to avoid strict-aliasing UB
                            const auto &v = hashed_item.value();
                            uint64_t lw = 0;
                            uint64_t hw = 0;
                            memcpy(&lw, v.data(), sizeof(lw));
                            memcpy(&hw, v.data() + sizeof(lw), sizeof(hw));
                            ret.emplace_back(lw, hw);
                        }
                    }
                    return ret;
                }());
            }

            fbs::BinBundleBuilder bin_bundle_builder(fbs_builder);
            bin_bundle_builder.add_bundle_idx(bundle_idx);
            bin_bundle_builder.add_mod(field_mod().value());
            bin_bundle_builder.add_item_bins(item_bins);
            bin_bundle_builder.add_label_bins(label_bins);
            bin_bundle_builder.add_cache(bin_bundle_cache);
            bin_bundle_builder.add_stripped(stripped_);
            if (has_hashed_items) {
                bin_bundle_builder.add_hashed_items(hashed_items);
            }

            auto bb = bin_bundle_builder.Finish();
            fbs_builder.FinishSizePrefixed(bb);

            out.write(
                reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        pair<uint32_t, size_t> BinBundle::load(gsl::span<const unsigned char> in)
        {
            // A BinBundle holds a table for every bin of every label part, and once more in its
            // cache, which with long labels and many bins comes to more than the 1,000,000 tables
            // the verifier allows by default. Every table takes at least four bytes, so allowing
            // one for every four bytes of the buffer still bounds the verifier's work by the size
            // of the buffer.
            flatbuffers::Verifier::Options verifier_options;
            verifier_options.max_tables = max<flatbuffers::uoffset_t>(
                verifier_options.max_tables,
                safe_cast<flatbuffers::uoffset_t>(in.size() / sizeof(flatbuffers::uoffset_t)));
            auto verifier = flatbuffers::Verifier(
                reinterpret_cast<const unsigned char *>(in.data()), in.size(), verifier_options);
            bool safe = fbs::VerifySizePrefixedBinBundleBuffer(verifier);
            if (!safe) {
                APSI_LOG_ERROR("Failed to load BinBundle: the buffer is invalid");
                throw runtime_error("failed to load BinBundle");
            }

            const auto *bb = fbs::GetSizePrefixedBinBundle(in.data());

            // Load the bundle index
            uint32_t bundle_idx = bb->bundle_idx();

            // Throw if the field modulus does not match
            uint64_t mod = bb->mod();
            if (mod != field_mod().value()) {
                APSI_LOG_ERROR(
                    "The loaded BinBundle field modulus ("
                    << mod << ") differs from the field modulus of this BinBundle ("
                    << field_mod().value() << ")");
                throw runtime_error("failed to load BinBundle");
            }

            // Remove all data and clear the cache; reset data structures according to the stripped
            // flag
            clear(bb->stripped());

            // Check that the number of bins is correct
            size_t num_bins = get_num_bins();
            const auto &item_bins = *bb->item_bins()->rows();
            if (!stripped_ && (num_bins != item_bins.size())) {
                APSI_LOG_ERROR(
                    "The loaded BinBundle has "
                    << item_bins.size() << " item bins but this BinBundle expects " << num_bins
                    << " bins");
                throw runtime_error("failed to load BinBundle");
            }

            // Check that num_bins fits into flatbuffers::uoffset_t
            if (!fits_in<flatbuffers::uoffset_t>(num_bins)) {
                APSI_LOG_ERROR("The loaded BinBundle has too many bins");
                throw runtime_error("failed to load BinBundle");
            }

            // The loaded label size must match the label size for this BinBundle
            size_t label_size = get_label_size();

            for (size_t bin_idx = 0; !stripped_ && (bin_idx < num_bins); bin_idx++) {
                const auto &item_bin =
                    *item_bins[static_cast<flatbuffers::uoffset_t>(bin_idx)]->felts();

                // Check that the sizes of the bins are at most max_bin_size_
                if (item_bin.size() > max_bin_size_) {
                    APSI_LOG_ERROR(
                        "The loaded BinBundle has an item bin of size "
                        << item_bin.size() << " but this BinBundle has a maximum bin size "
                        << max_bin_size_);
                    throw runtime_error("failed to load BinBundle");
                }

                // All is good; copy over the item data
                transform(
                    item_bin.begin(),
                    item_bin.end(),
                    back_inserter(item_bins_[bin_idx]),
                    [&](auto felt_item) {
#ifdef APSI_DEBUG
                        if (label_size &&
                            is_present(item_bins_[bin_idx], filters_[bin_idx], felt_item)) {
                            APSI_LOG_ERROR(
                                "The loaded BinBundle data contains a repeated value "
                                << felt_item << " in bin at index " << bin_idx);
                            throw runtime_error("failed to load BinBundle");
                        }
#endif
                        // Add to the cuckoo filter
                        // A refusal is recorded rather than refused, exactly as during
                        // insertion: the filter marks itself incomplete and lookups in this bin
                        // search it directly.
                        if (!filters_[bin_idx].add(felt_item)) {
                            APSI_LOG_DEBUG(
                                "Cuckoo filter for the bin at index "
                                << bin_idx
                                << " refused an item while loading; lookups in this bin now "
                                   "search it directly");
                        }

                        // Return to add the item to item_bins_[bin_idx]
                        return felt_item;
                    });
            }

            // We are now done with the item data; next check that the label size is correct
            size_t loaded_label_size = bb->label_bins() ? bb->label_bins()->size() : 0;
            if (!stripped_ && (label_size != loaded_label_size)) {
                APSI_LOG_ERROR(
                    "The loaded BinBundle has label size "
                    << loaded_label_size << " but this BinBundle expects label size "
                    << label_size);
                throw runtime_error("failed to load BinBundle");
            }

            // Check that label_size fits into flatbuffers::uoffset_t
            if (!fits_in<flatbuffers::uoffset_t>(label_size)) {
                APSI_LOG_ERROR("The loaded BinBundle has too large label size");
                throw runtime_error("failed to load BinBundle");
            }

            for (size_t label_idx = 0; !stripped_ && (label_idx < label_size); label_idx++) {
                // We can now safely dereference bb->label_bins()
                const auto &label_bins =
                    *bb->label_bins()
                         ->operator[](static_cast<flatbuffers::uoffset_t>(label_idx))
                         ->rows();

                // Check that the number of bins is the same as for the items
                if (label_bins.size() != num_bins) {
                    APSI_LOG_ERROR(
                        "The loaded BinBundle has label data for "
                        << label_bins.size() << " bins but this BinBundle expects " << num_bins
                        << " bins");
                    throw runtime_error("failed to load BinBundle");
                }

                // Check that each bin has the same size as the corresponding items bin
                for (size_t bin_idx = 0; bin_idx < num_bins; bin_idx++) {
                    size_t item_bin_size = item_bins_[bin_idx].size();
                    const auto &label_bin =
                        *label_bins[static_cast<flatbuffers::uoffset_t>(bin_idx)]->felts();
                    if (label_bin.size() != item_bin_size) {
                        APSI_LOG_ERROR(
                            "The loaded BinBundle has at bin index "
                            << bin_idx << " a label bin of size " << label_bin.size()
                            << " which does not match the item bin size " << item_bin_size);
                        throw runtime_error("failed to load BinBundle");
                    }

                    // All is good; copy over the label data
                    copy(
                        label_bin.begin(),
                        label_bin.end(),
                        back_inserter(label_bins_[label_idx][bin_idx]));
                }
            }

            // A BinBundle with match tags that is not stripped identifies its items by the
            // HashedItems kept alongside them, so they must be present, one for each item, and
            // otherwise absent
            bool expect_hashed_items = uses_tags() && !stripped_;
            if (expect_hashed_items != (bb->hashed_items() != nullptr)) {
                APSI_LOG_ERROR(
                    "The loaded BinBundle "
                    << (expect_hashed_items ? "lacks" : "has")
                    << " the HashedItems of its items, which "
                    << (expect_hashed_items ? "a" : "only a")
                    << " BinBundle with match tags that is not stripped has");
                throw runtime_error("failed to load BinBundle");
            }

            if (expect_hashed_items) {
                const auto &hashed_items = *bb->hashed_items();
                size_t item_count = 0;
                for (const auto &item_bin : item_bins_) {
                    item_count += item_bin.size();
                }

                if (hashed_items.size() != item_count) {
                    APSI_LOG_ERROR(
                        "The loaded BinBundle has " << hashed_items.size()
                                                    << " HashedItems for its " << item_count
                                                    << " items");
                    throw runtime_error("failed to load BinBundle");
                }

                // The HashedItems are stored bin by bin, in the order of the items
                flatbuffers::uoffset_t hashed_item_idx = 0;
                for (size_t bin_idx = 0; bin_idx < num_bins; bin_idx++) {
                    vector<HashedItem> &hashed_item_bin = hashed_item_bins_[bin_idx];
                    hashed_item_bin.reserve(item_bins_[bin_idx].size());
                    for (size_t i = 0; i < item_bins_[bin_idx].size(); i++) {
                        const auto *hashed_item = hashed_items[hashed_item_idx++];
                        hashed_item_bin.emplace_back(
                            hashed_item->low_word(), hashed_item->high_word());
                    }
                }
            }

            // If the BinBundle is stripped the cache must be present
            if (stripped_ && !bb->cache()) {
                APSI_LOG_ERROR(
                    "The loaded BinBundle is stripped but no cache data was found; this "
                    "BinBundle cannot be used");
                throw runtime_error("failed to load BinBundle");
            }

            // Finally load the cache, if present
            if (bb->cache()) {
                const auto &cache = *bb->cache();

                // We keep track of the largest polynomial coefficient count
                size_t max_coeff_count = 0;

                // With match tags there is no matching polynomial, and its fields must be absent:
                // finding them means the data was written for parameters without match tags.
                // Without match tags they must be present. The schema cannot require them, since
                // a BinBundle with match tags leaves them out, so the requirement is enforced
                // here.
                if (uses_tags() &&
                    (cache.felt_matching_polyns() || cache.batched_matching_polyn())) {
                    APSI_LOG_ERROR(
                        "The loaded BinBundle cache contains matching polynomials but this "
                        "BinBundle uses match tags");
                    throw runtime_error("failed to load BinBundle");
                }
                if (!uses_tags() &&
                    (!cache.felt_matching_polyns() || !cache.batched_matching_polyn())) {
                    APSI_LOG_ERROR(
                        "The loaded BinBundle cache contains no matching polynomials but this "
                        "BinBundle does not use match tags");
                    throw runtime_error("failed to load BinBundle");
                }

                if (!uses_tags()) {
                    // Do we have the right number of rows in the loaded felt_matching_polyns data?
                    const auto &felt_matching_polyns = *cache.felt_matching_polyns()->rows();
                    if (!stripped_ && (felt_matching_polyns.size() != num_bins)) {
                        APSI_LOG_ERROR(
                            "The loaded BinBundle cache contains an incorrect number ("
                            << felt_matching_polyns.size() << ") of matching polynomials (expected "
                            << num_bins << ")");
                        throw runtime_error("failed to load BinBundle");
                    }

                    for (size_t bin_idx = 0; !stripped_ && (bin_idx < num_bins); bin_idx++) {
                        const auto &felt_matching_polyn =
                            *felt_matching_polyns[static_cast<flatbuffers::uoffset_t>(bin_idx)]
                                 ->felts();

                        // Copy over the matching polynomial coefficients for this bin index
                        FEltPolyn p;
                        p.reserve(felt_matching_polyn.size());
                        copy(
                            felt_matching_polyn.begin(),
                            felt_matching_polyn.end(),
                            back_inserter(p));
                        cache_.felt_matching_polyns.push_back(std::move(p));

                        // Keep track of the largest coefficient count
                        max_coeff_count = max<size_t>(max_coeff_count, felt_matching_polyn.size());
                    }

                    // max_coeff_count can't be larger than the bin size
                    if (max_coeff_count > max_bin_size_) {
                        APSI_LOG_ERROR(
                            "The loaded BinBundle cache contains too many ("
                            << max_coeff_count << ") matching polynomial coefficients (maximum is "
                            << max_bin_size_ << ")");
                        throw runtime_error("failed to load BinBundle");
                    }

                    // Nor can it be zero unless the BinBundle is stripped, as every matching
                    // polynomial has at least one coefficient
                    if (!stripped_ && !max_coeff_count) {
                        APSI_LOG_ERROR(
                            "The loaded BinBundle cache contains matching polynomials with no "
                            "coefficients");
                        throw runtime_error("failed to load BinBundle");
                    }

                    // Each "column" of coefficients is batched into a single plaintext, so check
                    // that the number of plaintexts actually matches max_coeff_count. A query
                    // evaluates the batched matching polynomial, so a stripped BinBundle must give
                    // it at least one coefficient as well.
                    const auto &batched_matching_polyn = *cache.batched_matching_polyn()->coeffs();
                    if (!stripped_ && (batched_matching_polyn.size() != max_coeff_count)) {
                        APSI_LOG_ERROR(
                            "The loaded BinBundle cache contains an incorrect number ("
                            << batched_matching_polyn.size()
                            << ") of batched matching polynomial coefficients (expected "
                            << max_coeff_count << ")");
                        throw runtime_error("failed to load BinBundle");
                    }
                    if (stripped_ && (batched_matching_polyn.size() > max_bin_size_)) {
                        APSI_LOG_ERROR(
                            "The loaded BinBundle cache contains too many ("
                            << batched_matching_polyn.size()
                            << ") batched matching polynomial coefficients (maximum is "
                            << max_bin_size_ << ")");
                        throw runtime_error("failed to load BinBundle");
                    }
                    if (stripped_ && !batched_matching_polyn.size()) {
                        APSI_LOG_ERROR(
                            "The loaded BinBundle cache contains a batched matching polynomial "
                            "with no coefficients");
                        throw runtime_error("failed to load BinBundle");
                    }

                    // Create the batched matching polynomial; we load the data below
                    cache_.batched_matching_polyn = crypto_context_;

                    // The number of plaintexts is correct; copy them over
                    for (const auto *coeff_idx : batched_matching_polyn) {
                        // Get the current coefficient data
                        const auto &batched_matching_polyn_coeff = *coeff_idx->data();

                        // Copy the data over to a local vector
                        vector<unsigned char> pt_data(batched_matching_polyn_coeff.size());
                        copy_bytes(
                            batched_matching_polyn_coeff.data(),
                            batched_matching_polyn_coeff.size(),
                            pt_data.data());

                        // Move the loaded data to the cache
                        cache_.batched_matching_polyn.batched_coeffs.push_back(std::move(pt_data));
                    }
                } else {
                    // With match tags, the label polynomial of a bin of k items has k
                    // coefficients, or the single coefficient of the zero polynomial when the bin
                    // is empty. The item bins were checked above against max_bin_size_, so the
                    // largest count cannot exceed it either.
                    for (size_t bin_idx = 0; !stripped_ && (bin_idx < num_bins); bin_idx++) {
                        max_coeff_count = max<size_t>(
                            max_coeff_count, max<size_t>(item_bins_[bin_idx].size(), 1));
                    }
                }

                // We are now done with the item cache data; next check that the label cache size is
                // correct
                size_t felt_interp_polyns_size =
                    cache.felt_interp_polyns() ? cache.felt_interp_polyns()->size() : 0;
                size_t batched_interp_polyns_size =
                    cache.batched_interp_polyns() ? cache.batched_interp_polyns()->size() : 0;

                if (!stripped_ && (label_size != felt_interp_polyns_size)) {
                    APSI_LOG_ERROR(
                        "The loaded BinBundle cache has (felt_interp_polyns) label size "
                        << felt_interp_polyns_size << " but this BinBundle expects label size "
                        << label_size);
                    throw runtime_error("failed to load BinBundle");
                }
                if (label_size != batched_interp_polyns_size) {
                    APSI_LOG_ERROR(
                        "The loaded BinBundle cache has (batched_interp_polyns) label size "
                        << batched_interp_polyns_size << " but this BinBundle expects label size "
                        << label_size);
                    throw runtime_error("failed to load BinBundle");
                }

                // Resize felt_interp_polyns to correct size at this point; reserve space for
                // batched_interp_polyns but construct them only when needed
                if (!stripped_) {
                    cache_.felt_interp_polyns.resize(label_size);
                }
                cache_.batched_interp_polyns.reserve(label_size);

                // The coefficient count shared by the batched interpolation polynomials of a
                // stripped BinBundle with match tags
                size_t stripped_coeff_count = 0;

                for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                    // The felt interpolation polynomial data is present only when the BinBundle is
                    // not stripped
                    const auto *felt_interp_polyns_ptr =
                        stripped_ ? nullptr
                                  : cache.felt_interp_polyns()
                                        ->operator[](static_cast<flatbuffers::uoffset_t>(label_idx))
                                        ->rows();

                    // Do we have the right number of rows in the loaded felt_interp_polyns data?
                    if (!stripped_ && (felt_interp_polyns_ptr->size() != num_bins)) {
                        APSI_LOG_ERROR(
                            "The loaded BinBundle cache contains an incorrect number ("
                            << felt_interp_polyns_ptr->size()
                            << ") of interpolation polynomials (expected " << num_bins << ")");
                        throw runtime_error("failed to load BinBundle");
                    }

                    // Next, check that the number of coefficients is correct and copy data over
                    for (size_t bin_idx = 0; !stripped_ && (bin_idx < num_bins); bin_idx++) {
                        const auto &felt_interp_polyn =
                            *felt_interp_polyns_ptr
                                 ->operator[](static_cast<flatbuffers::uoffset_t>(bin_idx))
                                 ->felts();

                        size_t interp_polyn_coeff_count = felt_interp_polyn.size();
                        size_t expected_interp_polyn_coeff_count = 0;
                        if (uses_tags()) {
                            // See above: a bin of k items has a polynomial of k coefficients, and
                            // an empty one the zero polynomial with one
                            expected_interp_polyn_coeff_count =
                                max<size_t>(item_bins_[bin_idx].size(), 1);
                        } else {
                            // Compare the number of interpolation polynomial coefficients to the
                            // number of matching polynomial coefficients
                            size_t matching_polyn_coeff_count =
                                cache_.felt_matching_polyns[bin_idx].size();

                            // This is an empty bin if the matching polynomial has zero or one
                            // coefficients; in this case the interpolation polynomial size should
                            // equal the matching polynomial size. Otherwise the interpolation
                            // polynomial size is one less than the matching polynomial size.
                            bool empty_bin = matching_polyn_coeff_count <= 1;
                            expected_interp_polyn_coeff_count =
                                empty_bin ? matching_polyn_coeff_count
                                          : matching_polyn_coeff_count - 1;
                        }

                        if (!stripped_ &&
                            (interp_polyn_coeff_count != expected_interp_polyn_coeff_count)) {
                            APSI_LOG_ERROR(
                                "The loaded BinBundle cache has at bin index "
                                << bin_idx << " " << interp_polyn_coeff_count
                                << " interpolation polynomial coefficients (expected "
                                << expected_interp_polyn_coeff_count << ")");
                            throw runtime_error("failed to load BinBundle");
                        }

                        // Copy over the interpolation polynomial coefficients for this bin index
                        FEltPolyn p;
                        p.reserve(interp_polyn_coeff_count);
                        copy(felt_interp_polyn.begin(), felt_interp_polyn.end(), back_inserter(p));
                        cache_.felt_interp_polyns[label_idx].push_back(std::move(p));
                    }

                    // Finally check that the number of batched interpolation polynomial
                    // coefficients is correct and copy them over.
                    const auto &batched_interp_polyn =
                        *cache.batched_interp_polyns()
                             ->operator[](static_cast<flatbuffers::uoffset_t>(label_idx))
                             ->coeffs();
                    flatbuffers::uoffset_t batched_interp_polyn_coeff_count =
                        batched_interp_polyn.size();

                    // Without match tags, max_coeff_count counts the coefficients of the matching
                    // polynomials, which have one more than the interpolation polynomials unless
                    // the bundle is empty. With match tags it counts the coefficients of the
                    // interpolation polynomials themselves.
                    size_t expected_batch_interp_polyn_coeff_count = max_coeff_count;
                    if (!uses_tags()) {
                        bool empty_bundle = max_coeff_count <= 1;
                        expected_batch_interp_polyn_coeff_count =
                            empty_bundle ? max_coeff_count : max_coeff_count - 1;
                    }

                    if (!stripped_ && (batched_interp_polyn_coeff_count !=
                                       expected_batch_interp_polyn_coeff_count)) {
                        APSI_LOG_ERROR(
                            "The loaded BinBundle cache contains an incorrect number ("
                            << batched_interp_polyn_coeff_count
                            << ") of batched interpolation polynomial coefficients (expected "
                            << expected_batch_interp_polyn_coeff_count << ")");
                        throw runtime_error("failed to load BinBundle");
                    }
                    if (stripped_ && (batched_interp_polyn_coeff_count > max_bin_size_)) {
                        APSI_LOG_ERROR(
                            "The loaded BinBundle cache contains too many ("
                            << batched_interp_polyn_coeff_count
                            << ") batched interpolation polynomial coefficients (maximum is "
                            << max_bin_size_ << ")");
                        throw runtime_error("failed to load BinBundle");
                    }

                    // A query evaluates each of these polynomials, so each must have at least one
                    // coefficient, as every label polynomial does. With match tags a query is
                    // answered from them alone, so a stripped BinBundle must also give them all the
                    // same number, as every label polynomial of a bin has the same number of
                    // coefficients.
                    if (!batched_interp_polyn_coeff_count) {
                        APSI_LOG_ERROR(
                            "The loaded BinBundle cache contains a batched interpolation "
                            "polynomial with no coefficients");
                        throw runtime_error("failed to load BinBundle");
                    }
                    if (uses_tags() && stripped_) {
                        if (label_idx == 0) {
                            stripped_coeff_count = batched_interp_polyn_coeff_count;
                        } else if (batched_interp_polyn_coeff_count != stripped_coeff_count) {
                            APSI_LOG_ERROR(
                                "The loaded BinBundle cache contains batched interpolation "
                                "polynomials with different numbers of coefficients ("
                                << batched_interp_polyn_coeff_count << " and "
                                << stripped_coeff_count << ")");
                            throw runtime_error("failed to load BinBundle");
                        }
                    }

                    // Create a new batched interpolation polynomial; we load the data below
                    cache_.batched_interp_polyns.emplace_back(crypto_context_);

                    // The number of plaintexts is correct; copy them over
                    for (flatbuffers::uoffset_t coeff_idx = 0;
                         coeff_idx < batched_interp_polyn_coeff_count;
                         coeff_idx++) {
                        // Get the current coefficient data
                        const auto &batched_interp_polyn_coeff =
                            *batched_interp_polyn[coeff_idx]->data();

                        // Copy the data over to a local vector
                        vector<unsigned char> pt_data(batched_interp_polyn_coeff.size());
                        copy_bytes(
                            batched_interp_polyn_coeff.data(),
                            batched_interp_polyn_coeff.size(),
                            pt_data.data());

                        // Move the loaded data to the cache
                        cache_.batched_interp_polyns[label_idx].batched_coeffs.push_back(
                            std::move(pt_data));
                    }
                }

                // Mark the cache as valid
                cache_invalid_ = false;

                // Unless the BinBundle is stripped, the cache holds the polynomials of every bin,
                // so a change to a bin needs only that bin interpolated again. Like the rest of a
                // saved SenderDB, they are trusted to be those of the loaded items; regen_cache
                // checks that their sizes fit the bins before keeping any.
                if (!stripped_) {
                    fill(dirty_bins_.begin(), dirty_bins_.end(), false);
                }
            }

            return { bundle_idx, in.size() };
        }

        pair<uint32_t, size_t> BinBundle::load(istream &in)
        {
            vector<unsigned char> in_data = read_from_stream(in);
            return load(in_data);
        }
    } // namespace sender
} // namespace apsi
