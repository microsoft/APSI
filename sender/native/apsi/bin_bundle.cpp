// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <utility>

// APSI
#include "apsi/bin_bundle_generated.h"
#include "apsi/bin_bundle.h"
#include "apsi/util/interpolate.h"

// SEAL
#include "seal/util/defines.h"

namespace apsi
{
    using namespace std;
    using namespace seal;
    using namespace seal::util;
    using namespace util;

    namespace sender
    {
        namespace
        {
            /**
            Helper function. Computes the "matching" polynomial of a bin, i.e., the unique monic polynomial whose roots are
            precisely the items of the bin.
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
            if (batched_coeffs_.size() > ciphertext_powers.size())
            {
                throw invalid_argument("not enough ciphertext powers available");
            }

            const SEALContext &seal_context = *crypto_context_.seal_context();
            Evaluator &evaluator = *crypto_context_.evaluator();

            // Lowest degree terms are stored in the lowest index positions in vectors. Specifically,
            // ciphertext_powers[1] is the first power of the ciphertext data, but batched_coeffs_[0] is the constant
            // coefficient.
            //
            // Because the plaintexts in batched_coeffs_ can be identically zero, SEAL should be built with
            // SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF. We create a result ciphertext that is identically zero and set
            // its NTT form flag to true so the additions below will work.
            Ciphertext result;
            result.resize(seal_context, seal_context.first_parms_id(), 2);
            result.is_ntt_form() = true;
            Ciphertext temp;
            Plaintext coeff;
            for (size_t deg = 1; deg < batched_coeffs_.size(); deg++)
            {
                coeff.unsafe_load(seal_context, batched_coeffs_[deg].data(), batched_coeffs_[deg].size());
                evaluator.multiply_plain(ciphertext_powers[deg], coeff, temp);
                evaluator.add_inplace(result, temp);
            }

            // Need to transform back from NTT form before we can add the constant coefficient. The constant coefficient
            // is specifically not in NTT form so this can work.
            evaluator.transform_from_ntt_inplace(result);
            coeff.unsafe_load(seal_context, batched_coeffs_[0].data(), batched_coeffs_[0].size());
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
                    SEAL_ITERATE(iter(result), result.size(), [&](auto I) {
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
        ) : crypto_context_(move(crypto_context))
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
                crypto_context_.encoder()->encode(coeffs_of_deg_i, pt);

                // When evaluating the match and interpolation polynomials on encrypted query data, we multiply each
                // power of the encrypted query with a plaintext (pt here) corresponding to the polynomial coefficient,
                // and add the results together. The constant coefficients (i == 0 here) is handled by performing
                // a "dummy encryption" operation on it so it can be added to the result. The dummy encryption, however,
                // requires that the plaintext is not in NTT form.
                if (i != 0)
                {
                    crypto_context_.evaluator()->transform_to_ntt_inplace(
                        pt,
                        crypto_context_.seal_context()->first_parms_id()
                    );
                }

                // Push the new Plaintext
                vector<seal_byte> pt_data;
                pt_data.resize(pt.save_size(compr_mode));
                size_t size = pt.save(pt_data.data(), pt_data.size(), compr_mode);
                pt_data.resize(size);
                batched_coeffs_.push_back(move(pt_data));
            }
        }

        template<typename L>
        BinBundle<L>::BinBundle(const CryptoContext &crypto_context, bool compressed) :
            cache_invalid_(true),
            cache_(crypto_context),
            crypto_context_(crypto_context),
            compressed_(compressed)
        {
            if (!crypto_context_.evaluator())
            {
                throw invalid_argument("evaluator is not set in crypto_context");
            }

            size_t num_bins = crypto_context_.seal_context()->first_context_data()->parms().poly_modulus_degree();
            bins_.resize(num_bins);
            cache_.felt_matching_polyns.reserve(num_bins);
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

            // For each key, check that we can insert into the corresponding bin. If the answer is "no" at any point,
            // return -1.
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
            vector<typename map<felt_t, L>::iterator> to_remove_its;
            for (auto &item : items)
            {
                map<felt_t, L> &curr_bin = bins_.at(curr_bin_idx);
                auto to_remove_it = curr_bin.find(item);

                if (to_remove_it == curr_bin.end())
                {
                    // One of the items isn't there; return false;
                    return false;
                }
                else
                {
                    // Found the label, put it in the return vector. *label_it is a key-value pair.
                    to_remove_its.push_back(move(to_remove_it));
                }

                curr_bin_idx++;
            }

            // We got to this point, so all of the items were found. Now just erase them.
            curr_bin_idx = start_bin_idx;
            for (auto to_remove_it : to_remove_its)
            {
                map<felt_t, L> &curr_bin = bins_.at(curr_bin_idx);
                curr_bin.erase(to_remove_it);

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
                const map<felt_t, L> &curr_bin = bins_.at(curr_bin_idx);
                auto label_it = curr_bin.find(item);

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

        /**
        Returns whether this BinBundle is empty.
        */
        template<typename L>
        bool BinBundle<L>::empty() const
        {
            return all_of(bins_.begin(), bins_.end(), [](auto &b) { return b.empty(); });
        }

        /**
        Saves the BinBundle to a stream.
        */
        template<typename L>
        size_t BinBundle<L>::save(ostream &out, uint32_t bundle_idx) const
        {
            // Is this a labeled BinBundle?
            constexpr bool labeled = is_same_v<L, felt_t>;
            
            const Modulus &mod = field_mod();
            auto mod_bit_count = mod.bit_count();
            auto mod_byte_count = (mod_bit_count + 7) >> 3;
            
            flatbuffers::FlatBufferBuilder fbs_builder(1024);

            auto bins = fbs_builder.CreateVector([&]() {
                // The Bin vector is populated with an immediately-invoked lambda
                vector<flatbuffers::Offset<fbs::Bin>> ret;
                for (const auto &bin : bins_)
                {
                    // Then create the vector of FEltItemLabels
                    vector<flatbuffers::Offset<fbs::FEltItemLabel>> ret_inner;
                    for (auto felt_item_label : bin)
                    {
                        auto felt_item = fbs_builder.CreateVector(
                            reinterpret_cast<const unsigned char *>(&felt_item_label.first), mod_byte_count);
                        SEAL_IF_CONSTEXPR (labeled)
                        {
                            auto felt_label = fbs_builder.CreateVector(
                                reinterpret_cast<const unsigned char *>(&felt_item_label.second), mod_byte_count);
                            ret_inner.push_back(fbs::CreateFEltItemLabel(fbs_builder, felt_item, felt_label));
                        }
                        else
                        {
                            ret_inner.push_back(fbs::CreateFEltItemLabel(fbs_builder, felt_item));
                        }
                    }
                    auto felt_item_labels = fbs_builder.CreateVector(ret_inner);
                    ret.push_back(fbs::CreateBin(fbs_builder, felt_item_labels));
                }
                return ret;
            }());

            fbs::BinBundleBuilder bin_bundle_builder(fbs_builder);
            bin_bundle_builder.add_bundle_idx(bundle_idx);
            bin_bundle_builder.add_labeled(labeled);
            bin_bundle_builder.add_mod(mod.value());
            bin_bundle_builder.add_bins(bins);
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
            bool add_to_bin(map<felt_t, L> &bin, felt_t felt_item, felt_t felt_label);

            template<>
            bool add_to_bin(map<felt_t, monostate> &bin, felt_t felt_item, felt_t felt_label)
            {
                return bin.emplace(make_pair(felt_item, monostate{})).second;
            }

            template<>
            bool add_to_bin(map<felt_t, felt_t> &bin, felt_t felt_item, felt_t felt_label)
            {
                return bin.emplace(make_pair(felt_item, felt_label)).second;
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

            vector<seal_byte> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(reinterpret_cast<const uint8_t*>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedBinBundleBuffer(verifier);
            if (!safe)
            {
                APSI_LOG_ERROR("Failed to load BinBundle: the buffer is invalid");
                throw runtime_error("failed to load BinBundle");
            }

            auto bb = fbs::GetSizePrefixedBinBundle(in_data.data());

            // Throw if this is not the right kind of BinBundle
            constexpr bool labeled = is_same_v<L, felt_t>;
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

            // Check that the number of bins is correct
            const auto &bins = *bb->bins();
            if (bins_.size() != bins.size())
            {
                APSI_LOG_ERROR("The loaded BinBundle has " << bins.size()
                    << " bins but this BinBundle expects " << bins_.size() << " bins");
                throw runtime_error("failed to load BinBundle");
            }

            for (size_t i = 0; i < bins.size(); i++)
            {
                for (const auto &felt_item_label : *bins[i]->felt_item_labels())
                {
                    // This felt_item_label must have a label precisely when labeled is true
                    bool has_label = !!(felt_item_label->felt_label());
                    if (labeled != has_label)
                    {
                        const char *felt_item_label_type_str = has_label ? "labeled" : "unlabeled";
                        APSI_LOG_ERROR("The loaded BinBundle contains data of incorrect type (" << felt_item_label_type_str
                            << "; expected " << this_type_str << ")");
                        throw runtime_error("failed to load BinBundle");
                    }

                    if (felt_item_label->felt_item()->size() != mod_byte_count)
                    {
                        APSI_LOG_ERROR("The loaded BinBundle contains (item) data buffers of incorrect size ("
                            << felt_item_label->felt_item()->size() << " bytes; expected " << mod_byte_count
                            << " bytes)");
                        throw runtime_error("failed to load BinBundle");
                    }

                    felt_t felt_item = 0;
                    copy_n(
                        reinterpret_cast<const seal_byte*>(felt_item_label->felt_item()->data()),
                        mod_byte_count,
                        reinterpret_cast<seal_byte*>(&felt_item));

                    felt_t felt_label = 0;
                    SEAL_IF_CONSTEXPR (labeled)
                    {
                        if (felt_item_label->felt_label()->size() != mod_byte_count)
                        {
                            APSI_LOG_ERROR("The loaded BinBundle contains (label) data buffers of incorrect size ("
                                << felt_item_label->felt_label()->size() << " bytes; expected " << mod_byte_count
                                << " bytes)");
                            throw runtime_error("failed to load BinBundle");
                        }

                        copy_n(
                            reinterpret_cast<const seal_byte*>(felt_item_label->felt_label()->data()),
                            mod_byte_count,
                            reinterpret_cast<seal_byte*>(&felt_label));
                    }

                    // Add the loaded item-label pair to the bin
                    if (!add_to_bin(bins_[i], felt_item, felt_label))
                    {
                        APSI_LOG_ERROR("The loaded BinBundle data contains repeated values for the same bin");
                        throw runtime_error("failed to load BinBundle");
                    }
                }
            }

            return { bundle_idx, in_data.size() };
        }

        // BinBundle will only ever be used with these two label types. Ordinarily we'd have to put method definitions
        // of a template class with the .h file, but if we monomorphize here, we don't have to do that.
        template class BinBundle<monostate>;
        template class BinBundle<felt_t>;
    } // namespace sender
} // namespace apsi
