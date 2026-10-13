// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cmath>
#include <cstring>
#include <functional>
#include <iterator>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>

// APSI
#include "apsi/psi_params.h"
#include "apsi/sender_db.h"
#include "apsi/sender_db_generated.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/db_encoding.h"
#include "apsi/util/label_encryptor.h"
#include "apsi/util/log_noexcept.h"
#include "apsi/util/task_group.h"
#include "apsi/util/utils.h"

// Kuku
#include "kuku/locfunc.h"

// SEAL
#include "seal/util/common.h"
#include "seal/util/streambuf.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace kuku;

namespace apsi {
    using namespace util;
    using namespace oprf;

    namespace sender {
        using util::log_noexcept;

        namespace {
            /**
            Creates and returns the vector of hash functions similarly to how Kuku 2.x sets them
            internally.
            */
            vector<LocFunc> hash_functions(const PSIParams &params)
            {
                vector<LocFunc> result;
                result.reserve(params.table_params().hash_func_count);
                for (uint32_t i = 0; i < params.table_params().hash_func_count; i++) {
                    result.emplace_back(params.table_params().table_size, make_item(i, 0));
                }

                return result;
            }

            /**
            Computes all cuckoo hash table locations for a given item.
            */
            unordered_set<location_type> all_locations(
                const vector<LocFunc> &hash_funcs, const HashedItem &item)
            {
                kuku::item_type kuku_item;
                std::memcpy(&kuku_item, item.value().data(), sizeof(kuku_item));

                unordered_set<location_type> result;
                for (const auto &hf : hash_funcs) {
                    result.emplace(hf(kuku_item));
                }

                return result;
            }

            /**
            Compute the label size in multiples of item-size chunks.
            */
            size_t compute_label_size(size_t label_byte_count, const PSIParams &params)
            {
                return ((label_byte_count * 8) + params.item_bit_count() - 1) /
                       params.item_bit_count();
            }

            /**
            Computes the number of label parts a BinBundle stores for each item. Without match
            tags these are the parts of the encrypted label, nonce included, exactly as
            compute_label_size gives them. With match tags they are the tag parts followed by
            the parts of the encrypted label, if the items have labels; without labels there is
            no nonce either.
            */
            size_t compute_label_part_count(
                size_t label_byte_count, size_t nonce_byte_count, const PSIParams &params)
            {
                if (!params.uses_tags()) {
                    return compute_label_size(nonce_byte_count + label_byte_count, params);
                }

                size_t payload_part_count =
                    label_byte_count
                        ? compute_label_size(nonce_byte_count + label_byte_count, params)
                        : 0;
                return params.tag_part_count() + payload_part_count;
            }

            /**
            Unpacks a cuckoo idx into its bin and bundle indices
            */
            pair<size_t, size_t> unpack_cuckoo_idx(size_t cuckoo_idx, size_t bins_per_bundle)
            {
                // Recall that bin indices are relative to the bundle index. That is, the first bin
                // index of a bundle at bundle index 5 is 0. A cuckoo index is similar, except it is
                // not relative to the bundle index. It just keeps counting past bundle boundaries.
                // So in order to get the bin index from the cuckoo index, just compute cuckoo_idx
                // (mod bins_per_bundle).
                size_t bin_idx = cuckoo_idx % bins_per_bundle;

                // Compute which bundle index this cuckoo index belongs to
                size_t bundle_idx = (cuckoo_idx - bin_idx) / bins_per_bundle;

                return { bin_idx, bundle_idx };
            }

            /**
            Converts each given Item-Label pair in between the given iterators into its algebraic
            form, i.e., a sequence of felt-felt pairs. Also computes each Item's cuckoo index.
            */
            vector<pair<AlgItemLabel, size_t>> preprocess_labeled_data(
                const vector<pair<HashedItem, EncryptedLabel>>::const_iterator begin,
                const vector<pair<HashedItem, EncryptedLabel>>::const_iterator end,
                const PSIParams &params)
            {
                STOPWATCH(sender_stopwatch, "preprocess_labeled_data");
                log_noexcept([&] {
                    APSI_LOG_DEBUG(
                        "Start preprocessing " << distance(begin, end) << " labeled items");
                });

                // Some variables we'll need
                size_t bins_per_item = params.item_params().felts_per_item;
                size_t item_bit_count = params.item_bit_count();

                // Set up Kuku hash functions
                auto hash_funcs = hash_functions(params);

                // Calculate the cuckoo indices for each item. Store every pair of (item-label,
                // cuckoo_idx) in a vector. Later, we're gonna sort this vector by cuckoo_idx and
                // use the result to parallelize the work of inserting the items into BinBundles.
                vector<pair<AlgItemLabel, size_t>> data_with_indices;
                for (auto it = begin; it != end; it++) {
                    const auto &[item, label] = *it;

                    // Serialize the data into field elements

                    AlgItemLabel alg_item_label = algebraize_item_label(
                        item, label, item_bit_count, params.seal_params().plain_modulus());

                    // Get the cuckoo table locations for this item and add to data_with_indices
                    for (auto location : all_locations(hash_funcs, item)) {
                        // The current hash value is an index into a table of Items. In reality our
                        // BinBundles are tables of bins, which contain chunks of items. How many
                        // chunks? bins_per_item many chunks
                        size_t bin_idx = location * bins_per_item;

                        // Store the data along with its index
                        data_with_indices.emplace_back(alg_item_label, bin_idx);
                    }
                }

                log_noexcept([&] {
                    APSI_LOG_DEBUG(
                        "Finished preprocessing " << distance(begin, end) << " labeled items");
                });

                return data_with_indices;
            }

            /**
            Converts each given Item into its algebraic form, i.e., a sequence of felt-monostate
            pairs. Also computes each Item's cuckoo index.
            */
            vector<pair<AlgItem, size_t>> preprocess_unlabeled_data(
                const vector<HashedItem>::const_iterator begin,
                const vector<HashedItem>::const_iterator end,
                const PSIParams &params)
            {
                STOPWATCH(sender_stopwatch, "preprocess_unlabeled_data");
                log_noexcept([&] {
                    APSI_LOG_DEBUG(
                        "Start preprocessing " << distance(begin, end) << " unlabeled items");
                });

                // Some variables we'll need
                size_t bins_per_item = params.item_params().felts_per_item;
                size_t item_bit_count = params.item_bit_count();

                // Set up Kuku hash functions
                auto hash_funcs = hash_functions(params);

                // Calculate the cuckoo indices for each item. Store every pair of (item-label,
                // cuckoo_idx) in a vector. Later, we're gonna sort this vector by cuckoo_idx and
                // use the result to parallelize the work of inserting the items into BinBundles.
                vector<pair<AlgItem, size_t>> data_with_indices;
                for (auto it = begin; it != end; it++) {
                    const HashedItem &item = *it;

                    // Serialize the data into field elements
                    AlgItem alg_item =
                        algebraize_item(item, item_bit_count, params.seal_params().plain_modulus());

                    // Get the cuckoo table locations for this item and add to data_with_indices
                    for (auto location : all_locations(hash_funcs, item)) {
                        // The current hash value is an index into a table of Items. In reality our
                        // BinBundles are tables of bins, which contain chunks of items. How many
                        // chunks? bins_per_item many chunks
                        size_t bin_idx = location * bins_per_item;

                        // Store the data along with its index
                        data_with_indices.emplace_back(alg_item, bin_idx);
                    }
                }

                log_noexcept([&] {
                    APSI_LOG_DEBUG(
                        "Finished preprocessing " << distance(begin, end) << " unlabeled items");
                });

                return data_with_indices;
            }

            /**
            Converts given Item into its algebraic form, i.e., a sequence of felt-monostate pairs.
            Also computes the Item's cuckoo index.
            */
            vector<pair<AlgItem, size_t>> preprocess_unlabeled_data(
                const HashedItem &item, const PSIParams &params)
            {
                vector<HashedItem> item_singleton{ item };
                return preprocess_unlabeled_data(
                    item_singleton.begin(), item_singleton.end(), params);
            }

            /**
            An item with its encrypted label, empty for an unlabeled SenderDB, and its match tag.
            */
            using TaggedHashedItem = tuple<HashedItem, EncryptedLabel, vector<felt_t>>;

            /**
            Converts each given item, with its encrypted label and its match tag, into the form a
            SenderDB with match tags stores it in: its HashedItem, and its field elements with
            label parts that begin with the parts of its tag. Also computes each item's cuckoo
            indices.
            */
            vector<pair<TaggedAlgItemLabel, size_t>> preprocess_tagged_data(
                const vector<TaggedHashedItem>::const_iterator begin,
                const vector<TaggedHashedItem>::const_iterator end,
                const PSIParams &params)
            {
                STOPWATCH(sender_stopwatch, "preprocess_tagged_data");
                log_noexcept([&] {
                    APSI_LOG_DEBUG(
                        "Start preprocessing " << distance(begin, end) << " tagged items");
                });

                // Some variables we'll need
                size_t bins_per_item = params.item_params().felts_per_item;
                size_t item_bit_count = params.item_bit_count();

                // Set up Kuku hash functions
                auto hash_funcs = hash_functions(params);

                vector<pair<TaggedAlgItemLabel, size_t>> data_with_indices;
                for (auto it = begin; it != end; it++) {
                    const auto &[item, label, tag] = *it;

                    TaggedAlgItemLabel tagged_item{
                        item,
                        algebraize_item_tag_label(
                            item, tag, label, item_bit_count, params.seal_params().plain_modulus())
                    };

                    // Get the cuckoo table locations for this item and add to data_with_indices
                    for (auto location : all_locations(hash_funcs, item)) {
                        size_t bin_idx = location * bins_per_item;
                        data_with_indices.emplace_back(tagged_item, bin_idx);
                    }
                }

                log_noexcept([&] {
                    APSI_LOG_DEBUG(
                        "Finished preprocessing " << distance(begin, end) << " tagged items");
                });

                return data_with_indices;
            }

            /**
            An item as a SenderDB with match tags looks for it: its field elements, and its
            HashedItem, which is what identifies it.
            */
            using AlgItemWithHash = pair<AlgItem, HashedItem>;

            /**
            Converts each given item into the form a SenderDB with match tags looks it up in, and
            computes each item's cuckoo indices.
            */
            vector<pair<AlgItemWithHash, size_t>> preprocess_tagged_lookup_data(
                const vector<HashedItem>::const_iterator begin,
                const vector<HashedItem>::const_iterator end,
                const PSIParams &params)
            {
                // Some variables we'll need
                size_t bins_per_item = params.item_params().felts_per_item;
                size_t item_bit_count = params.item_bit_count();

                // Set up Kuku hash functions
                auto hash_funcs = hash_functions(params);

                vector<pair<AlgItemWithHash, size_t>> data_with_indices;
                for (auto it = begin; it != end; it++) {
                    const HashedItem &item = *it;
                    AlgItem alg_item =
                        algebraize_item(item, item_bit_count, params.seal_params().plain_modulus());

                    // Get the cuckoo table locations for this item and add to data_with_indices
                    for (auto location : all_locations(hash_funcs, item)) {
                        size_t bin_idx = location * bins_per_item;
                        data_with_indices.emplace_back(make_pair(alg_item, item), bin_idx);
                    }
                }

                return data_with_indices;
            }

            /**
            Looks an item up in, or removes it from, a BinBundle: as an AlgItem without match tags,
            and by its HashedItem with them.
            */
            bool bundle_contains(const BinBundle &bundle, const AlgItem &data, size_t bin_idx)
            {
                return bundle.multi_contains(data, bin_idx);
            }

            bool bundle_contains(
                const BinBundle &bundle, const AlgItemWithHash &data, size_t bin_idx)
            {
                return bundle.multi_contains(data.first, data.second, bin_idx);
            }

            bool bundle_remove(BinBundle &bundle, const AlgItem &data, size_t bin_idx)
            {
                return bundle.try_multi_remove(data, bin_idx);
            }

            bool bundle_remove(BinBundle &bundle, const AlgItemWithHash &data, size_t bin_idx)
            {
                return bundle.try_multi_remove(data.first, data.second, bin_idx);
            }

            /**
            Returns whether each of the felt_count bins of a BinBundle beginning at start_bin_idx
            holds fewer than max_bin_size items. An item occupies one place in each of the bins
            of its location, so with match tags those bins always hold equally many items, but
            each is checked.
            */
            bool has_room(
                const BinBundle &bundle,
                size_t start_bin_idx,
                size_t felt_count,
                size_t max_bin_size)
            {
                const vector<vector<felt_t>> &item_bins = bundle.get_item_bins();
                for (size_t felt_idx = 0; felt_idx < felt_count; felt_idx++) {
                    if (item_bins[start_bin_idx + felt_idx].size() >= max_bin_size) {
                        return false;
                    }
                }

                return true;
            }

            /**
            Reads the item stored at position pos of the felt_count bins of a BinBundle with match
            tags beginning at start_bin_idx: its HashedItem, its field elements, and all its label
            parts, tag parts included, in the form multi_insert takes. An item is stored at the
            same position in each of the bins of its location. Returns false if the bins do not
            hold one item there, which happens only if the BinBundle has been corrupted.
            */
            bool read_stored_item(
                const BinBundle &bundle,
                size_t start_bin_idx,
                size_t felt_count,
                size_t pos,
                TaggedAlgItemLabel &stored_item)
            {
                const vector<vector<felt_t>> &item_bins = bundle.get_item_bins();
                const vector<vector<HashedItem>> &hashed_item_bins = bundle.get_hashed_item_bins();
                const vector<vector<vector<felt_t>>> &label_bins = bundle.get_label_bins();
                size_t label_size = bundle.get_label_size();

                stored_item.alg_item_label.clear();
                stored_item.alg_item_label.reserve(felt_count);
                for (size_t felt_idx = 0; felt_idx < felt_count; felt_idx++) {
                    size_t curr_bin_idx = start_bin_idx + felt_idx;
                    if ((pos >= item_bins[curr_bin_idx].size()) ||
                        (pos >= hashed_item_bins[curr_bin_idx].size())) {
                        return false;
                    }

                    const HashedItem &hashed_item = hashed_item_bins[curr_bin_idx][pos];
                    if (felt_idx == 0) {
                        stored_item.item = hashed_item;
                    } else if (!(hashed_item == stored_item.item)) {
                        return false;
                    }

                    vector<felt_t> label_parts(label_size);
                    for (size_t label_idx = 0; label_idx < label_size; label_idx++) {
                        const vector<felt_t> &label_bin = label_bins[label_idx][curr_bin_idx];
                        if (pos >= label_bin.size()) {
                            return false;
                        }
                        label_parts[label_idx] = label_bin[pos];
                    }

                    stored_item.alg_item_label.emplace_back(
                        item_bins[curr_bin_idx][pos], std::move(label_parts));
                }

                return true;
            }

            /**
            What insert_by_relocation did: moved a stored item and inserted the new one in its
            place; found no move possible, as no BinBundle is both full and free of the new item's
            field elements, or none has room; declined a move through a BinBundle that the batch
            had not changed; or found no move among the BinBundles it tried.
            */
            enum class Relocation { moved, impossible, declined, not_found };

            /**
            Inserts an item into one of the BinBundles of a SenderDB with match tags at the item's
            bundle index, none of which accepts it, by first moving an item already stored there to
            another of them. Unless it returns Relocation::moved, the BinBundles are left as they
            were, and the caller puts the item in a new BinBundle.

            A bin cannot hold two items with the same field element, as its label polynomials
            interpolate through them. When the item's bins are full in some BinBundles and hold one
            of its field elements in all the others, the item would need a new BinBundle, which
            costs every query tag_part_count more result ciphertexts and one more per label part,
            although there is room for it. Instead, this moves a stored item out of a source, a
            BinBundle whose bins at the location are full and hold none of the item's field
            elements, into a destination whose bins there have room and hold none of the moved
            item's field elements, and puts the new item in its place. Every lookup searches all the
            BinBundles at a bundle index, so the moved item is still found. With one field element
            per item, such a move exists whenever the bins have room for the item and not every
            BinBundle holds its field element: a full source holds max_bin_size distinct field
            elements, more than a destination with room, so one of them is not in the destination.
            With more field elements per item, a single move is merely tried.

            Only BinBundles the batch has already changed, and so regenerates anyway, are used:
            moving an item through any other would make the batch encode all its plaintexts again,
            while the new BinBundle the move avoids costs almost nothing to generate. So a large
            batch moves items for free, and a small one opens a new BinBundle instead. Newer
            BinBundles are tried first, and the stored items of a source in the order they are
            stored, so the choice is deterministic.

            Nothing is changed until dry runs have shown that the moved item fits in the destination
            and that the new item can take its place in the source. Adding the moved item to the
            destination then either throws having changed nothing, as it reserves memory first, or
            succeeds, and replacing it in the source neither allocates nor throws, and cannot fail,
            as the source has not changed since its dry run. So nothing ever needs to be undone, and
            the moved item is stored throughout, and in the end exactly once.
            */
            Relocation insert_by_relocation(
                vector<BinBundle> &bundle_set,
                const TaggedAlgItemLabel &item,
                size_t bin_idx,
                size_t max_bin_size)
            {
                size_t felt_count = item.alg_item_label.size();

                // A BinBundle with room holds one of the item's field elements, or the item would
                // have gone into it. One that is full can take the item only if it holds none of
                // them, which its dry run shows by returning a size, one too large, rather than
                // -1; the item fits once a stored item has made way for it.
                vector<size_t> sources;
                vector<size_t> destinations;
                for (size_t set_idx = bundle_set.size(); set_idx-- > 0;) {
                    BinBundle &bundle = bundle_set[set_idx];
                    if (has_room(bundle, bin_idx, felt_count, max_bin_size)) {
                        destinations.push_back(set_idx);
                        continue;
                    }

                    int32_t new_size = bundle.multi_insert_dry_run(item, bin_idx);
                    if ((new_size > 0) && (static_cast<size_t>(new_size) <= max_bin_size + 1)) {
                        sources.push_back(set_idx);
                    }
                }

                if (sources.empty() || destinations.empty()) {
                    return Relocation::impossible;
                }

                // Each destination's field elements at the location, collected once per call
                unordered_map<size_t, vector<unordered_set<felt_t>>> destination_felts;

                // Whether a move was declined as it would change a BinBundle the batch has not
                bool declined = false;

                for (size_t source_idx : sources) {
                    for (size_t destination_idx : destinations) {
                        BinBundle &source = bundle_set[source_idx];
                        BinBundle &destination = bundle_set[destination_idx];

                        // A BinBundle's cache is invalid exactly when this batch has changed it,
                        // or made it, so that the batch regenerates it anyway
                        if (!source.cache_invalid() || !destination.cache_invalid()) {
                            declined = true;
                            continue;
                        }

                        // Collect the destination's field elements the first time it is tried
                        auto [felts_it, felts_new] = destination_felts.try_emplace(destination_idx);
                        vector<unordered_set<felt_t>> &dest_felts = felts_it->second;
                        if (felts_new) {
                            dest_felts.resize(felt_count);
                            for (size_t felt_idx = 0; felt_idx < felt_count; felt_idx++) {
                                const vector<felt_t> &bin =
                                    destination.get_item_bins()[bin_idx + felt_idx];
                                dest_felts[felt_idx].reserve(bin.size());
                                dest_felts[felt_idx].insert(bin.begin(), bin.end());
                            }
                        }

                        // Try the stored items in the order they are stored. One can move if the
                        // destination holds none of its field elements.
                        const vector<vector<felt_t>> &source_bins = source.get_item_bins();
                        size_t stored_count = source_bins[bin_idx].size();
                        for (size_t pos = 0; pos < stored_count; pos++) {
                            bool movable = true;
                            for (size_t felt_idx = 0; movable && (felt_idx < felt_count);
                                 felt_idx++) {
                                const vector<felt_t> &bin = source_bins[bin_idx + felt_idx];
                                movable =
                                    (pos < bin.size()) && !dest_felts[felt_idx].count(bin[pos]);
                            }
                            if (!movable) {
                                continue;
                            }

                            TaggedAlgItemLabel stored_item;
                            if (!read_stored_item(source, bin_idx, felt_count, pos, stored_item)) {
                                log_noexcept([&] {
                                    APSI_LOG_ERROR(
                                        "Insert-or-Assign worker: the bins beginning at index "
                                        << bin_idx
                                        << " of a BinBundle do not hold one item at the same "
                                           "position; the internal state of the BinBundle has "
                                           "been corrupted");
                                });
                                return Relocation::not_found;
                            }

                            // Check the whole move before changing anything
                            int32_t new_dest_size =
                                destination.multi_insert_dry_run(stored_item, bin_idx);
                            if ((new_dest_size <= 0) ||
                                (static_cast<size_t>(new_dest_size) > max_bin_size) ||
                                !source.try_multi_replace(
                                    stored_item.item, pos, item, bin_idx, true)) {
                                continue;
                            }

                            // Add the moved item to the destination before replacing it in the
                            // source, so that nothing ever needs to be undone; see above.
                            if (destination.multi_insert_for_real(stored_item, bin_idx) < 0) {
                                APSI_LOG_ERROR(
                                    "Insert-or-Assign worker: failed to move an item to another "
                                    "BinBundle at bin index "
                                    << bin_idx);
                                throw logic_error("failed to move an item to another BinBundle");
                            }
                            if (!source.try_multi_replace(
                                    stored_item.item, pos, item, bin_idx, false)) {
                                APSI_LOG_ERROR(
                                    "Insert-or-Assign worker: failed to put an item in place of "
                                    "one moved to another BinBundle at bin index "
                                    << bin_idx);
                                throw logic_error(
                                    "failed to put an item in place of one moved out of its way");
                            }

                            return Relocation::moved;
                        }
                    }
                }

                return declined ? Relocation::declined : Relocation::not_found;
            }

            /**
            Places the new items at a bundle index that holds no BinBundles, for a SenderDB with
            match tags and one field element per item, in as few BinBundles as any placement of
            them can use. entries are the positions in data_with_indices of the items at this
            bundle index, in the order in which they are to be stored.

            A bin of n items in which no field element appears more than m times needs
            max(ceil(n / K), m) BinBundles, for a capacity K: no BinBundle holds more than K items
            in a bin or one field element twice. This uses B BinBundles, the largest of those
            numbers over the bins of the bundle index, and is therefore optimal. In each bin, the
            items are sorted by field element, so that equal ones are adjacent, and dealt to the
            B BinBundles in turn. Equal field elements, at most B of them, go to distinct
            BinBundles, and each BinBundle gets at most ceil(n / B) <= K items. The bins of all B
            BinBundles are then about equally full, which also keeps the interpolation, whose
            cost grows with the square of the number of items in a bin, cheaper than filling the
            BinBundles one after another, and leaves room in each of them for items inserted
            later.

            Placing items one at a time, newest BinBundle first, can need more BinBundles: an
            item whose field element is in the one BinBundle with room opens a new one, although
            an older, full one could have taken it had a stored item been moved. Nothing is moved
            here, and every BinBundle is new, so no cache is regenerated more than once.
            */
            void pack_tagged_items(
                const vector<pair<TaggedAlgItemLabel, size_t>> &data_with_indices,
                const vector<size_t> &entries,
                vector<BinBundle> &bundle_set,
                CryptoContext &crypto_context,
                uint32_t bins_per_bundle,
                size_t label_size,
                size_t tag_part_count,
                size_t max_bin_size,
                size_t ps_low_degree,
                bool compressed)
            {
                // Each item here has one field element, by which it is sorted and dealt
                auto felt_of = [&](size_t entry) {
                    return data_with_indices[entry].first.alg_item_label[0].first;
                };

                // Group the items by bin
                vector<vector<size_t>> bins(bins_per_bundle);
                for (size_t entry : entries) {
                    size_t bin_idx = data_with_indices[entry].second % bins_per_bundle;
                    bins[bin_idx].push_back(entry);
                }

                // Sort each bin by field element, and find how many BinBundles the fullest bin, or
                // the most repeated field element, needs
                size_t bundle_count = 0;
                for (auto &bin : bins) {
                    if (bin.empty()) {
                        continue;
                    }

                    stable_sort(bin.begin(), bin.end(), [&](size_t a, size_t b) {
                        return felt_of(a) < felt_of(b);
                    });

                    size_t repeat_count = 1;
                    size_t max_repeat_count = 1;
                    for (size_t i = 1; i < bin.size(); i++) {
                        repeat_count =
                            (felt_of(bin[i]) == felt_of(bin[i - 1])) ? repeat_count + 1 : 1;
                        max_repeat_count = max(max_repeat_count, repeat_count);
                    }

                    size_t fill_count = (bin.size() + max_bin_size - 1) / max_bin_size;
                    bundle_count = max({ bundle_count, fill_count, max_repeat_count });
                }

                // Make the BinBundles. They are added to the bundle index only once all of them
                // hold their items.
                vector<BinBundle> packed;
                packed.reserve(bundle_count);
                for (size_t i = 0; i < bundle_count; i++) {
                    packed.emplace_back(
                        crypto_context,
                        label_size,
                        max_bin_size,
                        ps_low_degree,
                        bins_per_bundle,
                        compressed,
                        false,
                        tag_part_count);
                }

                // Deal each bin's items to the BinBundles in turn
                for (size_t bin_idx = 0; bin_idx < bins.size(); bin_idx++) {
                    const vector<size_t> &bin = bins[bin_idx];
                    for (size_t i = 0; i < bin.size(); i++) {
                        int32_t new_size = packed[i % bundle_count].multi_insert_for_real(
                            data_with_indices[bin[i]].first, bin_idx);
                        if ((new_size <= 0) || (static_cast<size_t>(new_size) > max_bin_size)) {
                            APSI_LOG_ERROR(
                                "Insert-or-Assign worker: failed to insert an item into a new "
                                "BinBundle while packing the bin at index "
                                << bin_idx);
                            throw logic_error("failed to insert item into a new BinBundle");
                        }
                    }
                }

                bundle_set = std::move(packed);
            }

            /**
            Inserts the given items and corresponding labels into bin_bundles at their respective
            cuckoo indices, for the items whose bundle index is bundle_index. An item goes into the
            newest BinBundle that accepts it, or into a new BinBundle if none does. A bin holds at
            most max_bin_size - 1 items, or max_bin_size with match tags, which a non-zero
            tag_part_count selects. If overwrite is set, every item must already be stored in the
            BinBundles at its bundle index; its labels are overwritten in every one of them that
            holds it, and nothing is inserted. With match tags, new items at a bundle index without
            BinBundles are packed into as few as possible (see pack_tagged_items), and an item that
            no BinBundle accepts goes into a new BinBundle only if moving a stored item between
            BinBundles this batch has already changed cannot make room for it in one of them (see
            insert_by_relocation).
            */
            template <typename T>
            void insert_or_assign_worker(
                const vector<pair<T, size_t>> &data_with_indices,
                vector<vector<BinBundle>> &bin_bundles,
                CryptoContext &crypto_context,
                uint32_t bundle_index,
                uint32_t bins_per_bundle,
                size_t label_size,
                size_t tag_part_count,
                size_t max_bin_size,
                size_t ps_low_degree,
                bool overwrite,
                bool compressed)
            {
                STOPWATCH(sender_stopwatch, "insert_or_assign_worker");
                log_noexcept([&] {
                    APSI_LOG_DEBUG(
                        "Insert-or-Assign worker for bundle index "
                        << bundle_index << "; mode of operation: "
                        << (overwrite ? "overwriting existing" : "inserting new"));
                });

                constexpr bool with_tags = is_same_v<T, TaggedAlgItemLabel>;

                // With match tags and one field element per item, the new items at a bundle index
                // that holds no BinBundles, as after set_data has cleared the SenderDB, are all
                // known before any is placed, and are packed into as few BinBundles as possible
                if constexpr (with_tags) {
                    vector<BinBundle> &bundle_set = bin_bundles[bundle_index];
                    if (!overwrite && bundle_set.empty()) {
                        vector<size_t> entries;
                        bool one_felt = true;
                        for (size_t entry = 0; entry < data_with_indices.size(); entry++) {
                            const auto &data_with_idx = data_with_indices[entry];
                            if (unpack_cuckoo_idx(data_with_idx.second, bins_per_bundle).second ==
                                bundle_index) {
                                entries.push_back(entry);
                                one_felt =
                                    one_felt && (data_with_idx.first.alg_item_label.size() == 1);
                            }
                        }

                        if (one_felt && !entries.empty()) {
                            pack_tagged_items(
                                data_with_indices,
                                entries,
                                bundle_set,
                                crypto_context,
                                bins_per_bundle,
                                label_size,
                                tag_part_count,
                                max_bin_size,
                                ps_low_degree,
                                compressed);
                            log_noexcept([&] {
                                APSI_LOG_DEBUG(
                                    "Insert-or-Assign worker: finished processing bundle index "
                                    << bundle_index << "; packed " << entries.size()
                                    << " items into " << bundle_set.size() << " new BinBundles");
                            });
                            return;
                        }
                    }
                }

                // With match tags, how many BinBundles were opened, how many items were inserted by
                // moving another, how many moves were declined as they would have changed a
                // BinBundle this batch had not, and how many searches found no move
                size_t opened_count = 0;
                size_t moved_count = 0;
                size_t declined_count = 0;
                size_t not_found_count = 0;

                // Iteratively insert each item-label pair at the given cuckoo index
                for (auto &data_with_idx : data_with_indices) {
                    const T &data = data_with_idx.first;

                    // Get the bundle index
                    size_t cuckoo_idx = data_with_idx.second;

                    auto [bin_idx, bundle_idx] = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);

                    // If the bundle_idx isn't in the prescribed range, don't try to insert this
                    // data
                    if (bundle_idx != bundle_index) {
                        // Dealing with this bundle index is not our job
                        continue;
                    }

                    // Get the bundle set at the given bundle index
                    vector<BinBundle> &bundle_set = bin_bundles[bundle_idx];

                    // Overwrite the item in every BinBundle that holds it, all found before any is
                    // changed, and in no other. Trying them one at a time, as APSI 1.x did, can
                    // store a second copy with the new label and leave the old one to answer
                    // queries, so an item can be stored more than once; every copy is overwritten,
                    // so that whichever one a query matches gives the new label.
                    if (overwrite) {
                        vector<BinBundle *> holders;
                        for (auto &bundle : bundle_set) {
                            if (bundle.multi_contains(data, bin_idx)) {
                                holders.push_back(&bundle);
                            }
                        }

                        // The item is in the database, so this should never happen
                        if (holders.empty()) {
                            APSI_LOG_ERROR(
                                "Insert-or-Assign worker: "
                                "failed to overwrite item at bundle index "
                                << bundle_idx << " because no BinBundle there holds it");
                            throw logic_error("tried to overwrite non-existent item");
                        }

                        if (holders.size() > 1) {
                            log_noexcept([&] {
                                APSI_LOG_WARNING(
                                    "Insert-or-Assign worker: overwriting all "
                                    << holders.size() << " copies of an item at bundle index "
                                    << bundle_index
                                    << "; an older version of APSI stored the item more than "
                                       "once when it updated its label. Removing the item and "
                                       "inserting it again drops the extra copies.");
                            });
                        }

                        for (BinBundle *holder : holders) {
                            if (!holder->try_multi_overwrite(data, bin_idx)) {
                                APSI_LOG_ERROR(
                                    "Insert-or-Assign worker: "
                                    "failed to overwrite item at bundle index "
                                    << bundle_idx << " although it was found there");
                                throw logic_error("failed to overwrite item");
                            }
                        }

                        continue;
                    }

                    // Try to insert these field elements in an existing BinBundle at this bundle
                    // index. Keep track of whether or not we succeed.
                    bool written = false;
                    for (auto bundle_it = bundle_set.rbegin(); bundle_it != bundle_set.rend();
                         bundle_it++) {
                        // Do a dry-run insertion and see if the new largest bin size in the range
                        // exceeds the limit
                        int32_t new_largest_bin_size =
                            bundle_it->multi_insert_dry_run(data, bin_idx);

                        // Check if inserting would violate the max bin size constraint. Without
                        // match tags a bin holds fewer than max_bin_size items, as in APSI 1.x.
                        // With them it may hold max_bin_size, as its label polynomials then have
                        // degree below max_bin_size, which the query powers cover. A negative size
                        // means the dry run failed.
                        bool fits = false;
                        if (new_largest_bin_size > 0) {
                            auto new_bin_size = static_cast<size_t>(new_largest_bin_size);
                            fits = tag_part_count ? (new_bin_size <= max_bin_size)
                                                  : (new_bin_size < max_bin_size);
                        }
                        if (fits) {
                            // All good
                            bundle_it->multi_insert_for_real(data, bin_idx);
                            written = true;
                            break;
                        }
                    }

                    // With match tags, an item can fail to fit only because its field elements
                    // are in the bins with room, and moving a stored item may make room for it
                    if constexpr (with_tags) {
                        if (!written) {
                            switch (insert_by_relocation(bundle_set, data, bin_idx, max_bin_size)) {
                            case Relocation::moved:
                                written = true;
                                moved_count++;
                                break;
                            case Relocation::declined:
                                declined_count++;
                                break;
                            case Relocation::not_found:
                                not_found_count++;
                                break;
                            case Relocation::impossible:
                                break;
                            }
                        }
                    }

                    // If we had conflicts everywhere when trying to insert, then we need to make a
                    // new BinBundle and insert the data there
                    if (!written) {
                        // Make a fresh BinBundle and insert
                        BinBundle new_bin_bundle(
                            crypto_context,
                            label_size,
                            max_bin_size,
                            ps_low_degree,
                            bins_per_bundle,
                            compressed,
                            false,
                            tag_part_count);
                        int res = new_bin_bundle.multi_insert_for_real(data, bin_idx);

                        // If even that failed, I don't know what could've happened
                        if (res < 0) {
                            APSI_LOG_ERROR(
                                "Insert-or-Assign worker: "
                                "failed to insert item into a new BinBundle at bundle index "
                                << bundle_idx);
                            throw logic_error("failed to insert item into a new BinBundle");
                        }

                        // Push a new BinBundle to the set of BinBundles at this bundle index
                        bundle_set.push_back(std::move(new_bin_bundle));
                        opened_count++;
                    }
                }

                if constexpr (with_tags) {
                    log_noexcept([&] {
                        APSI_LOG_DEBUG(
                            "Insert-or-Assign worker: finished processing bundle index "
                            << bundle_index << "; opened " << opened_count << " BinBundles; moved "
                            << moved_count << " items to make room; declined " << declined_count
                            << " moves through BinBundles the batch had not changed; "
                               "found no move for "
                            << not_found_count << " items");
                    });
                } else {
                    log_noexcept([&] {
                        APSI_LOG_DEBUG(
                            "Insert-or-Assign worker: finished processing bundle index "
                            << bundle_index);
                    });
                }
            }

            /**
            Takes algebraized data to be inserted, splits it up, and distributes it so that
            thread_count many threads can all insert in parallel. If overwrite is set, this will
            overwrite the labels if it finds an AlgItemLabel that matches the input perfectly.
            */
            template <typename T>
            void dispatch_insert_or_assign(
                vector<pair<T, size_t>> &data_with_indices,
                vector<vector<BinBundle>> &bin_bundles,
                CryptoContext &crypto_context,
                uint32_t bins_per_bundle,
                size_t label_size,
                size_t tag_part_count,
                uint32_t max_bin_size,
                uint32_t ps_low_degree,
                bool overwrite,
                bool compressed)
            {
                ThreadPoolMgr tpm;

                // Collect the bundle indices and partition them into thread_count many partitions.
                // By some uniformity assumption, the number of things to insert per partition
                // should be roughly the same. Note that the contents of bundle_indices is always
                // sorted (increasing order).
                set<size_t> bundle_indices_set;
                for (auto &data_with_idx : data_with_indices) {
                    size_t cuckoo_idx = data_with_idx.second;

                    auto [bin_idx, bundle_idx] = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);
                    bundle_indices_set.insert(bundle_idx);
                }

                // Copy the set of indices into a vector and sort so each thread processes a range
                // of indices
                vector<size_t> bundle_indices;
                bundle_indices.reserve(bundle_indices_set.size());
                copy(
                    bundle_indices_set.begin(),
                    bundle_indices_set.end(),
                    back_inserter(bundle_indices));
                sort(bundle_indices.begin(), bundle_indices.end());

                // Run the threads on the partitions
                TaskGroup tasks(tpm.thread_pool());
                tasks.reserve(bundle_indices.size());
                log_noexcept([&] {
                    APSI_LOG_INFO(
                        "Launching " << bundle_indices.size() << " insert-or-assign worker tasks");
                });
                for (auto &bundle_idx : bundle_indices) {
                    tasks.add([&, bundle_idx] {
                        insert_or_assign_worker(
                            data_with_indices,
                            bin_bundles,
                            crypto_context,
                            static_cast<uint32_t>(bundle_idx),
                            bins_per_bundle,
                            label_size,
                            tag_part_count,
                            max_bin_size,
                            ps_low_degree,
                            overwrite,
                            compressed);
                    });
                }

                // Wait for the tasks to finish
                tasks.join();

                log_noexcept([] { APSI_LOG_INFO("Finished insert-or-assign worker tasks"); });
            }

            /**
            Checks, without changing anything, that each of the given items is stored at its
            respective cuckoo index in at least one of bin_bundles. Only the data with bundle index
            bundle_index is checked. Throws std::logic_error if an item is missing.
            */
            template <typename T>
            void remove_check_worker(
                const vector<pair<T, size_t>> &data_with_indices,
                const vector<vector<BinBundle>> &bin_bundles,
                uint32_t bundle_index,
                uint32_t bins_per_bundle)
            {
                STOPWATCH(sender_stopwatch, "remove_check_worker");

                for (const auto &data_with_idx : data_with_indices) {
                    // Get the bundle index
                    size_t cuckoo_idx = data_with_idx.second;

                    auto [bin_idx, bundle_idx] = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);

                    // If the bundle_idx isn't in the prescribed range, don't check this data
                    if (bundle_idx != bundle_index) {
                        // Dealing with this bundle index is not our job
                        continue;
                    }

                    const vector<BinBundle> &bundle_set = bin_bundles[bundle_idx];
                    bool found = false;
                    for (const BinBundle &bundle : bundle_set) {
                        if (bundle_contains(bundle, data_with_idx.first, bin_idx)) {
                            found = true;
                            break;
                        }
                    }

                    // SenderDB::remove has checked that the item is in the SenderDB, so this means
                    // the item set and the bin bundles disagree. Nothing has been removed yet.
                    if (!found) {
                        APSI_LOG_ERROR(
                            "Remove worker: the item to remove at bundle index "
                            << bundle_idx << " was not found; nothing has been removed");
                        throw logic_error("failed to remove item");
                    }
                }
            }

            /**
            Removes the given items and corresponding labels from bin_bundles at their respective
            cuckoo indices. An item found in more than one BinBundle at its bundle index, as
            APSI 1.x could leave one behind when it updated a label, is removed from every one of
            them.
            */
            template <typename T>
            void remove_worker(
                const vector<pair<T, size_t>> &data_with_indices,
                vector<vector<BinBundle>> &bin_bundles,
                uint32_t bundle_index,
                uint32_t bins_per_bundle)
            {
                STOPWATCH(sender_stopwatch, "remove_worker");
                log_noexcept([&] { APSI_LOG_INFO("Remove worker [" << bundle_index << "]"); });

                // Iteratively remove each item-label pair at the given cuckoo index
                for (const auto &data_with_idx : data_with_indices) {
                    // Get the bundle index
                    size_t cuckoo_idx = data_with_idx.second;

                    auto [bin_idx, bundle_idx] = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);

                    // If the bundle_idx isn't in the prescribed range, don't try to remove this
                    // data
                    if (bundle_idx != bundle_index) {
                        // Dealing with this bundle index is not our job
                        continue;
                    }

                    // Get the bundle set at the given bundle index
                    vector<BinBundle> &bundle_set = bin_bundles[bundle_idx];

                    // Remove these field elements from every BinBundle at this bundle index that
                    // holds them, and count the BinBundles that did
                    size_t removed_count = 0;
                    for (BinBundle &bundle : bundle_set) {
                        if (bundle_remove(bundle, data_with_idx.first, bin_idx)) {
                            removed_count++;
                        }
                    }

                    if (removed_count > 1) {
                        log_noexcept([&] {
                            APSI_LOG_WARNING(
                                "Remove worker: removed an item stored in "
                                << removed_count << " BinBundles at bundle index " << bundle_index
                                << " instead of one");
                        });
                    }

                    // We may have produced some empty BinBundles so just remove them all
                    auto rem_it = remove_if(bundle_set.begin(), bundle_set.end(), [](auto &bundle) {
                        return bundle.empty();
                    });
                    bundle_set.erase(rem_it, bundle_set.end());

                    // We tried to remove an item that doesn't exist. The check that runs before
                    // any removal makes this impossible.
                    if (!removed_count) {
                        APSI_LOG_ERROR(
                            "Remove worker: "
                            "failed to remove item at bundle index "
                            << bundle_idx
                            << " "
                               "because the item was not found");
                        throw logic_error("failed to remove item");
                    }
                }

                log_noexcept([&] {
                    APSI_LOG_INFO(
                        "Remove worker: finished processing bundle index " << bundle_index);
                });
            }

            /**
            Takes algebraized data to be removed, splits it up, and distributes it so that worker
            threads can all remove in parallel. Every item is first checked to be present, and
            nothing is removed unless all of them are: a removal cannot be undone partway, so a
            batch that cannot be removed in full has to be refused before it has had any effect.
            */
            template <typename T>
            void dispatch_remove(
                const vector<pair<T, size_t>> &data_with_indices,
                vector<vector<BinBundle>> &bin_bundles,
                uint32_t bins_per_bundle)
            {
                ThreadPoolMgr tpm;

                // Collect the bundle indices and partition them into thread_count many partitions.
                // By some uniformity assumption, the number of things to remove per partition
                // should be roughly the same. Note that the contents of bundle_indices is always
                // sorted (increasing order).
                set<size_t> bundle_indices_set;
                for (const auto &data_with_idx : data_with_indices) {
                    size_t cuckoo_idx = data_with_idx.second;

                    auto [bin_idx, bundle_idx] = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);
                    bundle_indices_set.insert(bundle_idx);
                }

                // Copy the set of indices into a vector and sort so each thread processes a range
                // of indices
                vector<size_t> bundle_indices;
                bundle_indices.reserve(bundle_indices_set.size());
                copy(
                    bundle_indices_set.begin(),
                    bundle_indices_set.end(),
                    back_inserter(bundle_indices));
                sort(bundle_indices.begin(), bundle_indices.end());

                // Check that everything to remove is present before removing anything
                {
                    TaskGroup check_tasks(tpm.thread_pool());
                    check_tasks.reserve(bundle_indices.size());
                    for (auto &bundle_idx : bundle_indices) {
                        check_tasks.add([&, bundle_idx] {
                            remove_check_worker(
                                data_with_indices,
                                bin_bundles,
                                static_cast<uint32_t>(bundle_idx),
                                bins_per_bundle);
                        });
                    }

                    // Wait for the tasks to finish
                    check_tasks.join();
                }

                // Run the threads on the partitions
                TaskGroup tasks(tpm.thread_pool());
                tasks.reserve(bundle_indices.size());
                APSI_LOG_INFO("Launching " << bundle_indices.size() << " remove worker tasks");
                for (auto &bundle_idx : bundle_indices) {
                    tasks.add([&, bundle_idx] {
                        remove_worker(
                            data_with_indices,
                            bin_bundles,
                            static_cast<uint32_t>(bundle_idx),
                            bins_per_bundle);
                    });
                }

                // Wait for the tasks to finish
                tasks.join();
            }

            /**
            Returns a set of DB cache references corresponding to the bundles in the given set
            */
            vector<reference_wrapper<const BinBundleCache>> collect_caches(
                vector<BinBundle> &bin_bundles)
            {
                vector<reference_wrapper<const BinBundleCache>> result;
                result.reserve(bin_bundles.size());
                for (const auto &bundle : bin_bundles) {
                    result.emplace_back(cref(bundle.get_cache()));
                }

                return result;
            }
        } // namespace

        SenderDB::SenderDB(
            const PSIParams &params,
            size_t label_byte_count,
            size_t nonce_byte_count,
            bool compressed)
            : params_(params), crypto_context_(params_), label_byte_count_(label_byte_count),
              nonce_byte_count_(label_byte_count_ ? nonce_byte_count : 0), item_count_(0),
              compressed_(compressed)
        {
            // The labels cannot be more than 1 KB.
            if (label_byte_count_ > 1024) {
                APSI_LOG_ERROR(
                    "Requested label byte count " << label_byte_count_
                                                  << " exceeds the maximum (1024)");
                throw invalid_argument("label_byte_count is too large");
            }

            if (nonce_byte_count_ > max_nonce_byte_count) {
                APSI_LOG_ERROR(
                    "Request nonce byte count " << nonce_byte_count_ << " exceeds the maximum ("
                                                << max_nonce_byte_count << ")");
                throw invalid_argument("nonce_byte_count is too large");
            }

            // If the nonce byte count is less than max_nonce_byte_count, print a warning; this is a
            // labeled SenderDB but may not be safe to use for arbitrary label changes. A nonce of
            // zero is called out separately because it differs in kind rather than in degree: a
            // shorter nonce makes a repeated keystream likelier, while no nonce makes it certain.
            if (label_byte_count_ && !nonce_byte_count_) {
                APSI_LOG_WARNING(
                    "You have instantiated a labeled SenderDB instance with a nonce byte count of "
                    "zero, so label encryption is deterministic. Encrypting a label for the same "
                    "item a second time -- by updating it, or by removing the item and "
                    "reinserting it -- will reproduce the same keystream, and the two ciphertexts "
                    "together reveal the two labels. This is safe only for a SenderDB whose "
                    "labels are never rewritten.");
            } else if (label_byte_count_ && nonce_byte_count_ < max_nonce_byte_count) {
                APSI_LOG_WARNING(
                    "You have instantiated a labeled SenderDB instance with a nonce byte count "
                    << nonce_byte_count_ << ", which is less than the safe default value "
                    << max_nonce_byte_count
                    << ". Updating labels for existing items in the SenderDB or removing and "
                       "reinserting items with "
                       "different labels may leak information about the labels.");
            }

            // Set the evaluator. This will be used for BatchedPlaintextPolyn::eval.
            crypto_context_.set_evaluator();

            // Reset the SenderDB data structures
            clear();
        }

        SenderDB::SenderDB(
            const PSIParams &params,
            OPRFKey oprf_key,
            size_t label_byte_count,
            size_t nonce_byte_count,
            bool compressed)
            : SenderDB(params, label_byte_count, nonce_byte_count, compressed)
        {
            // Initialize oprf key with the one given to this constructor
            oprf_key_ = std::move(oprf_key);
        }

        // Acquiring the source's writer lock can in principle throw; a lock failure is
        // unrecoverable, so terminating (rather than dropping noexcept) is acceptable here.
        // NOLINTNEXTLINE(bugprone-exception-escape)
        SenderDB::SenderDB(SenderDB &&source) noexcept
            : SenderDB(std::move(source), source.get_writer_lock())
        {}

        // NOLINTNEXTLINE(bugprone-exception-escape)
        SenderDB::SenderDB(
            SenderDB &&source, unique_lock<shared_mutex> source_lock [[maybe_unused]]) noexcept
            : hashed_items_(std::move(source.hashed_items_)), params_(source.params_),
              crypto_context_(source.crypto_context_), label_byte_count_(source.label_byte_count_),
              nonce_byte_count_(source.nonce_byte_count_), item_count_(source.item_count_),
              compressed_(source.compressed_), stripped_(source.stripped_),
              bin_bundles_(std::move(source.bin_bundles_)), oprf_key_(std::move(source.oprf_key_))
        {
            // source_lock is held for the whole of this constructor, including the member
            // initializers above: it was acquired when the delegating constructor's arguments
            // were evaluated. The destination is not yet reachable by another thread and needs
            // no lock of its own.
            source.oprf_key_ = OPRFKey();

            // Reset the source data structures
            source.clear_internal();
        }

        // Acquiring the writer locks can in principle throw; a lock failure is unrecoverable, so
        // terminating (rather than dropping noexcept) is acceptable here.
        // NOLINTNEXTLINE(bugprone-exception-escape)
        SenderDB &SenderDB::operator=(SenderDB &&source) noexcept
        {
            // Do nothing if moving to self
            if (&source == this) {
                return *this;
            }

            // Both objects must be locked before either is read or written. scoped_lock takes
            // both without imposing an order, so two threads assigning in opposite directions
            // cannot each end up holding the lock the other waits for.
            scoped_lock lock(db_lock_, source.db_lock_);

            params_ = source.params_;
            crypto_context_ = source.crypto_context_;
            label_byte_count_ = source.label_byte_count_;
            nonce_byte_count_ = source.nonce_byte_count_;
            item_count_ = source.item_count_;
            compressed_ = source.compressed_;
            stripped_ = source.stripped_;

            hashed_items_ = std::move(source.hashed_items_);
            bin_bundles_ = std::move(source.bin_bundles_);
            oprf_key_ = std::move(source.oprf_key_);
            source.oprf_key_ = OPRFKey();

            // Reset the source data structures
            source.clear_internal();

            return *this;
        }

        size_t SenderDB::get_bin_bundle_count(uint32_t bundle_idx) const
        {
            // Lock the database for reading
            auto lock = get_reader_lock();

            return bin_bundles_.at(safe_cast<size_t>(bundle_idx)).size();
        }

        double SenderDB::log2_fpp(size_t query_item_count) const
        {
            if (!query_item_count) {
                throw invalid_argument("query_item_count cannot be zero");
            }

            // Lock the database for reading
            auto lock = get_reader_lock();

            // A receiver's item is tested against every bin bundle at its bundle index, so the
            // probability is that of one bundle multiplied by however many the busiest index
            // holds. A stripped database keeps its bundles, so this remains meaningful.
            size_t max_bundles = 0;
            for (const auto &bundles : bin_bundles_) {
                max_bundles = max(max_bundles, bundles.size());
            }

            double result = params_.log2_fpp_per_bin_bundle() +
                            std::log2(static_cast<double>(query_item_count));
            if (max_bundles) {
                result += std::log2(static_cast<double>(max_bundles));
            }

            // A probability cannot exceed one, however loose the terms above are.
            return min<double>(0.0, result);
        }

        size_t SenderDB::get_bin_bundle_count_unlocked() const
        {
            // Assume the SenderDB is already locked

            // Compute the total number of BinBundles
            return accumulate(
                bin_bundles_.cbegin(),
                bin_bundles_.cend(),
                static_cast<size_t>(0),
                [](auto a, const auto &b) { return a + b.size(); });
        }

        size_t SenderDB::get_bin_bundle_count() const
        {
            // Lock the database for reading
            auto lock = get_reader_lock();

            return get_bin_bundle_count_unlocked();
        }

        double SenderDB::get_packing_rate() const
        {
            // Lock the database for reading
            auto lock = get_reader_lock();

            uint64_t item_count = mul_safe(
                static_cast<uint64_t>(item_count_),
                static_cast<uint64_t>(params_.table_params().hash_func_count));
            uint64_t max_item_count = mul_safe(
                static_cast<uint64_t>(get_bin_bundle_count_unlocked()),
                static_cast<uint64_t>(params_.items_per_bundle()),
                static_cast<uint64_t>(params_.table_params().max_items_per_bin));

            return max_item_count
                       ? static_cast<double>(item_count) / static_cast<double>(max_item_count)
                       : 0.0;
        }

        void SenderDB::clear_internal()
        {
            // Assume the SenderDB is already locked for writing

            // Clear the set of inserted items
            hashed_items_.clear();
            item_count_ = 0;

            // Clear the BinBundles
            bin_bundles_.clear();
            bin_bundles_.resize(params_.bundle_idx_count());

            // Reset the stripped_ flag
            stripped_ = false;
        }

        void SenderDB::clear()
        {
            // Lock the database for writing
            auto lock = get_writer_lock();

            if (!hashed_items_.empty()) {
                APSI_LOG_INFO("Removing " << hashed_items_.size() << " items pairs from SenderDB");
            }

            clear_internal();
        }

        void SenderDB::generate_caches()
        {
            STOPWATCH(sender_stopwatch, "SenderDB::generate_caches");
            log_noexcept([] { APSI_LOG_INFO("Start generating bin bundle caches"); });

            // Only the bin bundles changed since their caches were last generated are regenerated.
            size_t regen_count = 0;
            size_t bundle_count = 0;
            for (auto &bundle_idx : bin_bundles_) {
                for (auto &bb : bundle_idx) {
                    bundle_count++;
                    if (bb.cache_invalid()) {
                        regen_count++;
                    }
                    bb.regen_cache();
                }
            }

            log_noexcept([&] {
                APSI_LOG_DEBUG(
                    "Regenerated the caches of " << regen_count << " of " << bundle_count
                                                 << " bin bundles");
            });
            log_noexcept([] { APSI_LOG_INFO("Finished generating bin bundle caches"); });
        }

        void SenderDB::generate_caches_after_failure() noexcept
        {
            try {
                generate_caches();
            } catch (...) { // NOLINT(bugprone-empty-catch): the update's exception is passed on
            }
        }

        vector<reference_wrapper<const BinBundleCache>> SenderDB::get_cache_at(uint32_t bundle_idx)
        {
            return collect_caches(bin_bundles_.at(safe_cast<size_t>(bundle_idx)));
        }

        OPRFKey SenderDB::strip()
        {
            // Lock the database for writing
            auto lock = get_writer_lock();

            stripped_ = true;

            OPRFKey oprf_key_copy = std::move(oprf_key_);
            oprf_key_.clear();
            hashed_items_.clear();

            // Regenerate any stale caches here, on this thread, before fanning out below.
            // BinBundle::strip must not be the one to discover a stale cache: it would call
            // regen_cache from inside a pool task, and regenerating enqueues further tasks and
            // blocks on them, so every worker would sit in an inner wait while the work it waits
            // for is queued behind it. This call is a no-op whenever the caches are already
            // valid, which is the normal case; it costs something only after an operation that
            // left them stale, and that is exactly the case that would otherwise deadlock.
            generate_caches();

            ThreadPoolMgr tpm;

            TaskGroup tasks(tpm.thread_pool());
            for (auto &bundle_idx : bin_bundles_) {
                for (auto &bb : bundle_idx) {
                    // Capture the element's address by value. bb is a loop reference variable
                    // whose lifetime ends when the iteration does, while the task it was handed
                    // to may still be running; the element itself lives in bin_bundles_ and
                    // outlives the join() below.
                    tasks.add([bb_ptr = &bb] { bb_ptr->strip(); });
                }
            }

            // Wait for the tasks to finish
            tasks.join();

            log_noexcept([] { APSI_LOG_INFO("SenderDB has been stripped"); });

            return oprf_key_copy;
        }

        OPRFKey SenderDB::get_oprf_key() const
        {
            // Lock the database for reading. strip() clears oprf_key_ under the writer lock, so
            // the check and the copy must both happen under this lock.
            auto lock = get_reader_lock();

            if (stripped_) {
                APSI_LOG_ERROR("Cannot return the OPRF key from a stripped SenderDB");
                throw logic_error("failed to return OPRF key");
            }
            return oprf_key_;
        }

        void SenderDB::insert_or_assign(const vector<pair<Item, Label>> &data)
        {
            // Lock the database for writing. The lock must span the stripped_ check, the hashing
            // and the insertion: strip() clears oprf_key_ under this same lock, so hashing
            // outside it can read a key that is being destroyed, and items hashed under a key
            // the database no longer holds would be committed under hashes no receiver can match.
            auto lock = get_writer_lock();

            if (stripped_) {
                APSI_LOG_ERROR("Cannot insert data to a stripped SenderDB");
                throw logic_error("failed to insert data");
            }
            if (!is_labeled()) {
                APSI_LOG_ERROR(
                    "Attempted to insert labeled data but this is an unlabeled SenderDB");
                throw logic_error("failed to insert data");
            }

            STOPWATCH(sender_stopwatch, "SenderDB::insert_or_assign (labeled)");
            APSI_LOG_INFO("Start inserting " << data.size() << " items in SenderDB");

            // Validate the whole batch before anything is computed or modified. Insertion fans
            // out across worker threads and cannot be unwound partway, so the only point at which
            // a bad batch can be rejected cleanly is before it has had any effect.
            {
                unordered_set<Item> batch_items;
                batch_items.reserve(data.size());
                for (const auto &item_label : data) {
                    if (item_label.second.size() > label_byte_count_) {
                        // Truncating here instead would store a label the receiver cannot
                        // distinguish from a correct one.
                        APSI_LOG_ERROR(
                            "Attempted to insert a label of "
                            << item_label.second.size()
                            << " bytes but this SenderDB holds labels of " << label_byte_count_
                            << " bytes");
                        throw invalid_argument("failed to insert data: label is too long");
                    }
                    if (!batch_items.insert(item_label.first).second) {
                        // Two labels for one item in a single batch: which one was meant cannot
                        // be known, so neither is chosen.
                        APSI_LOG_ERROR(
                            "Attempted to insert the same item twice in one batch, so the "
                            "intended label is ambiguous");
                        throw invalid_argument("failed to insert data: duplicate item in batch");
                    }
                }
            }

            if (params_.uses_tags()) {
                insert_or_assign_with_tags(data);
                return;
            }

            // Compute the hashes for the input data
            auto hashed_data =
                OPRFSender::ComputeHashes(data, oprf_key_, label_byte_count_, nonce_byte_count_);

            // We need to know which items are new and which are old, since we have to tell
            // dispatch_insert_or_assign when to have an overwrite-on-collision versus
            // add-binbundle-on-collision policy. Partition without recording anything: an item
            // registered in hashed_items_ before it is actually in a bin bundle is what leaves
            // has_item answering yes while get_label throws, and that state survives a save.
            auto new_data_end =
                partition(hashed_data.begin(), hashed_data.end(), [&](const auto &item_label_pair) {
                    return hashed_items_.find(item_label_pair.first) == hashed_items_.end();
                });

            // Dispatch the insertion, first for the data we're gonna overwrite, then for the new
            // data
            uint32_t bins_per_bundle = params_.bins_per_bundle();
            uint32_t max_bin_size = params_.table_params().max_items_per_bin;
            uint32_t ps_low_degree = params_.query_params().ps_low_degree;

            // Compute the label size; this ceil(effective_label_bit_count / item_bit_count)
            size_t label_size = compute_label_size(nonce_byte_count_ + label_byte_count_, params_);

            auto new_item_count = distance(hashed_data.begin(), new_data_end);
            auto existing_item_count = distance(new_data_end, hashed_data.end());

            try {
                if (existing_item_count) {
                    APSI_LOG_INFO(
                        "Found " << existing_item_count
                                 << " existing items to replace in SenderDB");

                    // Break the data into field element representation. Also compute the items'
                    // cuckoo indices.
                    vector<pair<AlgItemLabel, size_t>> data_with_indices =
                        preprocess_labeled_data(new_data_end, hashed_data.end(), params_);

                    dispatch_insert_or_assign(
                        data_with_indices,
                        bin_bundles_,
                        crypto_context_,
                        bins_per_bundle,
                        label_size,
                        0, /* tag part count */
                        max_bin_size,
                        ps_low_degree,
                        true, /* overwrite items */
                        compressed_);
                }

                if (new_item_count) {
                    log_noexcept([&] {
                        APSI_LOG_INFO(
                            "Found " << new_item_count << " new items to insert in SenderDB");
                    });

                    // Process and add the new data. Break the data into field element
                    // representation. Also compute the items' cuckoo indices.
                    vector<pair<AlgItemLabel, size_t>> data_with_indices =
                        preprocess_labeled_data(hashed_data.begin(), new_data_end, params_);

                    dispatch_insert_or_assign(
                        data_with_indices,
                        bin_bundles_,
                        crypto_context_,
                        bins_per_bundle,
                        label_size,
                        0, /* tag part count */
                        max_bin_size,
                        ps_low_degree,
                        false, /* don't overwrite items */
                        compressed_);
                }

                // Both dispatches have succeeded, so the new items can be recorded. Recording them
                // only now keeps the item set from naming an item that no bin bundle holds; a
                // dispatch that throws partway can leave new items stored but not recorded.
                for (auto it = hashed_data.begin(); it != new_data_end; it++) {
                    hashed_items_.insert(it->first);
                }
                item_count_ += static_cast<size_t>(new_item_count);
            } catch (...) {
                generate_caches_after_failure();
                throw;
            }

            // Generate the BinBundle caches
            generate_caches();

            APSI_LOG_INFO("Finished inserting " << data.size() << " items in SenderDB");
        }

        void SenderDB::insert_or_assign(const vector<Item> &data)
        {
            // Lock the database for writing. See the labeled overload above for why the lock must
            // span the stripped_ check, the hashing and the insertion.
            auto lock = get_writer_lock();

            if (stripped_) {
                APSI_LOG_ERROR("Cannot insert data to a stripped SenderDB");
                throw logic_error("failed to insert data");
            }
            if (is_labeled()) {
                APSI_LOG_ERROR("Attempted to insert unlabeled data but this is a labeled SenderDB");
                throw logic_error("failed to insert data");
            }

            STOPWATCH(sender_stopwatch, "SenderDB::insert_or_assign (unlabeled)");
            APSI_LOG_INFO("Start inserting " << data.size() << " items in SenderDB");

            if (params_.uses_tags()) {
                insert_or_assign_with_tags(data);
                return;
            }

            // Compute the hashes for the input data
            auto hashed_data = OPRFSender::ComputeHashes(data, oprf_key_);

            // We are not going to insert items that already appear in the database. Partition
            // without recording anything: an item registered in hashed_items_ before it is
            // actually in a bin bundle is what leaves the item set describing a database that
            // does not exist if the insertion below throws.
            //
            // Repeats within the batch are collapsed rather than refused. Inserting the same
            // unlabeled item twice is idempotent, so a repeat carries no ambiguity -- unlike a
            // labeled batch, where two labels for one item cannot both be meant. remove_if
            // applies its predicate exactly once per element, which is what makes using it to
            // deduplicate sound.
            unordered_set<HashedItem> batch_items;
            batch_items.reserve(hashed_data.size());
            hashed_data.erase(
                remove_if(
                    hashed_data.begin(),
                    hashed_data.end(),
                    [&](const auto &item) { return !batch_items.insert(item).second; }),
                hashed_data.end());

            auto new_data_end =
                partition(hashed_data.begin(), hashed_data.end(), [&](const auto &item) {
                    return hashed_items_.find(item) == hashed_items_.end();
                });

            auto new_item_count = distance(hashed_data.begin(), new_data_end);

            APSI_LOG_INFO("Found " << new_item_count << " new items to insert in SenderDB");

            // Break the new data down into its field element representation. Also compute the
            // items' cuckoo indices.
            vector<pair<AlgItem, size_t>> data_with_indices =
                preprocess_unlabeled_data(hashed_data.begin(), new_data_end, params_);

            // Dispatch the insertion
            uint32_t bins_per_bundle = params_.bins_per_bundle();
            uint32_t max_bin_size = params_.table_params().max_items_per_bin;
            uint32_t ps_low_degree = params_.query_params().ps_low_degree;

            try {
                dispatch_insert_or_assign(
                    data_with_indices,
                    bin_bundles_,
                    crypto_context_,
                    bins_per_bundle,
                    0, /* label size */
                    0, /* tag part count */
                    max_bin_size,
                    ps_low_degree,
                    false, /* don't overwrite items */
                    compressed_);

                // The dispatch has succeeded, so the new items can be recorded. Recording them
                // only now keeps the item set from naming an item that no bin bundle holds; a
                // dispatch that throws partway can leave new items stored but not recorded.
                for (auto it = hashed_data.begin(); it != new_data_end; it++) {
                    hashed_items_.insert(*it);
                }
                item_count_ += static_cast<size_t>(new_item_count);
            } catch (...) {
                generate_caches_after_failure();
                throw;
            }

            // Generate the BinBundle caches
            generate_caches();

            APSI_LOG_INFO("Finished inserting " << data.size() << " items in SenderDB");
        }

        void SenderDB::insert_or_assign_with_tags(const vector<pair<Item, Label>> &data)
        {
            // Compute the hashes and encrypt the labels as without match tags, and derive each
            // item's match tag from its label key as well
            uint32_t bits_per_felt = params_.item_bit_count_per_felt();
            size_t tag_felt_count =
                mul_safe<size_t>(params_.tag_part_count(), params_.item_params().felts_per_item);
            vector<TaggedHashedItem> hashed_data = OPRFSender::ComputeHashesAndMatchTags(
                data,
                oprf_key_,
                label_byte_count_,
                nonce_byte_count_,
                tag_felt_count,
                bits_per_felt);

            // As without match tags, partition the new items from the ones to overwrite without
            // recording anything yet
            auto new_data_end =
                partition(hashed_data.begin(), hashed_data.end(), [&](const auto &tagged_item) {
                    return hashed_items_.find(get<0>(tagged_item)) == hashed_items_.end();
                });

            uint32_t bins_per_bundle = params_.bins_per_bundle();
            uint32_t max_bin_size = params_.table_params().max_items_per_bin;
            uint32_t ps_low_degree = params_.query_params().ps_low_degree;
            size_t label_size =
                compute_label_part_count(label_byte_count_, nonce_byte_count_, params_);

            auto new_item_count = distance(hashed_data.begin(), new_data_end);
            auto existing_item_count = distance(new_data_end, hashed_data.end());

            // Overwrite the existing items before inserting the new ones, as without match tags.
            // The BinBundles the overwrites change are regenerated anyway, so placing the new items
            // can then move stored items through them as well; see insert_by_relocation.
            try {
                if (existing_item_count) {
                    APSI_LOG_INFO(
                        "Found " << existing_item_count
                                 << " existing items to replace in SenderDB");

                    vector<pair<TaggedAlgItemLabel, size_t>> data_with_indices =
                        preprocess_tagged_data(new_data_end, hashed_data.end(), params_);

                    dispatch_insert_or_assign(
                        data_with_indices,
                        bin_bundles_,
                        crypto_context_,
                        bins_per_bundle,
                        label_size,
                        params_.tag_part_count(),
                        max_bin_size,
                        ps_low_degree,
                        true, /* overwrite items */
                        compressed_);
                }

                if (new_item_count) {
                    log_noexcept([&] {
                        APSI_LOG_INFO(
                            "Found " << new_item_count << " new items to insert in SenderDB");
                    });

                    vector<pair<TaggedAlgItemLabel, size_t>> data_with_indices =
                        preprocess_tagged_data(hashed_data.begin(), new_data_end, params_);

                    dispatch_insert_or_assign(
                        data_with_indices,
                        bin_bundles_,
                        crypto_context_,
                        bins_per_bundle,
                        label_size,
                        params_.tag_part_count(),
                        max_bin_size,
                        ps_low_degree,
                        false, /* don't overwrite items */
                        compressed_);
                }

                // Both dispatches have succeeded, so the new items can be recorded; see the
                // overload without match tags
                for (auto it = hashed_data.begin(); it != new_data_end; it++) {
                    hashed_items_.insert(get<0>(*it));
                }
                item_count_ += static_cast<size_t>(new_item_count);
            } catch (...) {
                generate_caches_after_failure();
                throw;
            }

            // Generate the BinBundle caches
            generate_caches();

            APSI_LOG_INFO("Finished inserting " << data.size() << " items in SenderDB");
        }

        void SenderDB::insert_or_assign_with_tags(const vector<Item> &data)
        {
            // Compute the hashes as without match tags, and derive each item's match tag from its
            // label key as well
            uint32_t bits_per_felt = params_.item_bit_count_per_felt();
            size_t tag_felt_count =
                mul_safe<size_t>(params_.tag_part_count(), params_.item_params().felts_per_item);
            vector<pair<HashedItem, vector<felt_t>>> tagged_data =
                OPRFSender::ComputeHashesAndMatchTags(
                    data, oprf_key_, tag_felt_count, bits_per_felt);

            // As without match tags, repeats within the batch are collapsed, and items already in
            // the database are left as they are: there is no label to update, and the tag of an
            // item never changes
            unordered_set<HashedItem> batch_items;
            batch_items.reserve(tagged_data.size());
            vector<TaggedHashedItem> hashed_data;
            hashed_data.reserve(tagged_data.size());
            for (auto &[item, tag] : tagged_data) {
                if (batch_items.insert(item).second &&
                    (hashed_items_.find(item) == hashed_items_.end())) {
                    hashed_data.emplace_back(item, EncryptedLabel(), std::move(tag));
                }
            }

            auto new_item_count = hashed_data.size();
            APSI_LOG_INFO("Found " << new_item_count << " new items to insert in SenderDB");

            vector<pair<TaggedAlgItemLabel, size_t>> data_with_indices =
                preprocess_tagged_data(hashed_data.begin(), hashed_data.end(), params_);

            uint32_t bins_per_bundle = params_.bins_per_bundle();
            uint32_t max_bin_size = params_.table_params().max_items_per_bin;
            uint32_t ps_low_degree = params_.query_params().ps_low_degree;

            try {
                dispatch_insert_or_assign(
                    data_with_indices,
                    bin_bundles_,
                    crypto_context_,
                    bins_per_bundle,
                    compute_label_part_count(label_byte_count_, nonce_byte_count_, params_),
                    params_.tag_part_count(),
                    max_bin_size,
                    ps_low_degree,
                    false, /* don't overwrite items */
                    compressed_);

                // The dispatch has succeeded, so the new items can be recorded; see the overload
                // without match tags
                for (const auto &tagged_item : hashed_data) {
                    hashed_items_.insert(get<0>(tagged_item));
                }
                item_count_ += new_item_count;
            } catch (...) {
                generate_caches_after_failure();
                throw;
            }

            // Generate the BinBundle caches
            generate_caches();

            APSI_LOG_INFO("Finished inserting " << data.size() << " items in SenderDB");
        }

        void SenderDB::remove(const vector<Item> &data)
        {
            // Lock the database for writing. See insert_or_assign for why the lock must span the
            // stripped_ check, the hashing and the removal.
            auto lock = get_writer_lock();

            if (stripped_) {
                APSI_LOG_ERROR("Cannot remove data from a stripped SenderDB");
                throw logic_error("failed to remove data");
            }

            STOPWATCH(sender_stopwatch, "SenderDB::remove");
            APSI_LOG_INFO("Start removing " << data.size() << " items from SenderDB");

            // Compute the hashes for the input data
            auto hashed_data = OPRFSender::ComputeHashes(data, oprf_key_);

            // Removing an item twice in one batch is the same as removing it once, so repeats are
            // collapsed. remove_if applies its predicate exactly once per element, which is what
            // makes using it to deduplicate sound.
            unordered_set<HashedItem> batch_items;
            batch_items.reserve(hashed_data.size());
            hashed_data.erase(
                remove_if(
                    hashed_data.begin(),
                    hashed_data.end(),
                    [&](const auto &item) { return !batch_items.insert(item).second; }),
                hashed_data.end());

            // An item that is not in the database cannot be removed. Removal fans out across
            // worker threads and cannot be unwound partway, so the batch is refused before it has
            // had any effect, and the item set is changed only once the removal below has
            // succeeded; a removal that throws partway can leave items removed from the bin
            // bundles but still in the item set.
            auto missing_item_count =
                count_if(hashed_data.begin(), hashed_data.end(), [&](const auto &item) {
                    return hashed_items_.find(item) == hashed_items_.end();
                });
            if (missing_item_count) {
                APSI_LOG_ERROR(
                    "Cannot remove " << missing_item_count
                                     << " items that are not present in the SenderDB");
                throw logic_error("failed to remove item");
            }

            // Break the data down into its field element representation. Also compute the items'
            // cuckoo indices. Then dispatch the removal, which changes nothing unless every item
            // can be removed. With match tags, an item is found by its HashedItem.
            uint32_t bins_per_bundle = params_.bins_per_bundle();
            try {
                if (params_.uses_tags()) {
                    vector<pair<AlgItemWithHash, size_t>> data_with_indices =
                        preprocess_tagged_lookup_data(
                            hashed_data.begin(), hashed_data.end(), params_);
                    dispatch_remove(data_with_indices, bin_bundles_, bins_per_bundle);
                } else {
                    vector<pair<AlgItem, size_t>> data_with_indices =
                        preprocess_unlabeled_data(hashed_data.begin(), hashed_data.end(), params_);
                    dispatch_remove(data_with_indices, bin_bundles_, bins_per_bundle);
                }
            } catch (...) {
                generate_caches_after_failure();
                throw;
            }

            // The items are gone from the bin bundles, so they can now be removed from the item
            // set as well
            for (const auto &item : hashed_data) {
                hashed_items_.erase(item);
                item_count_--;
            }

            // Generate the BinBundle caches
            generate_caches();

            APSI_LOG_INFO("Finished removing " << data.size() << " items from SenderDB");
        }

        bool SenderDB::has_item(const Item &item) const
        {
            // Lock the database for reading. The lock must span the stripped_ check, the hashing
            // and the lookup: strip() clears oprf_key_ under the writer lock, so hashing outside
            // the lock can read a key that is being destroyed, and a hash computed under one key
            // cannot be looked up in an item set built under another.
            auto lock = get_reader_lock();

            if (stripped_) {
                APSI_LOG_ERROR("Cannot retrieve the presence of an item from a stripped SenderDB");
                throw logic_error("failed to retrieve the presence of item");
            }

            // Compute the hash for the input item
            auto hashed_item = OPRFSender::ComputeHashes({ &item, 1 }, oprf_key_)[0];

            return hashed_items_.find(hashed_item) != hashed_items_.end();
        }

        Label SenderDB::get_label(const Item &item) const
        {
            // Lock the database for reading. The lock must span the stripped_ check, the hashing
            // and the lookup: strip() clears oprf_key_ under the writer lock, so hashing outside
            // the lock can read a key that is being destroyed, and a hash computed under one key
            // cannot be looked up in an item set built under another.
            auto lock = get_reader_lock();

            if (stripped_) {
                APSI_LOG_ERROR("Cannot retrieve a label from a stripped SenderDB");
                throw logic_error("failed to retrieve label");
            }
            if (!is_labeled()) {
                APSI_LOG_ERROR("Attempted to retrieve a label but this is an unlabeled SenderDB");
                throw logic_error("failed to retrieve label");
            }

            // Compute the hash for the input item

            auto [hashed_item, key] = OPRFSender::GetItemHash(item, oprf_key_);

            // key decrypts this item's label, and the lookups below can throw before reaching
            // the decryption, so wipe it however this returns.
            SecureZeroGuard key_guard(key.data(), key.size());

            // Check if this item is in the DB. If not, throw an exception
            if (hashed_items_.find(hashed_item) == hashed_items_.end()) {
                APSI_LOG_ERROR("Cannot retrieve label for an item that is not in the SenderDB");
                throw invalid_argument("failed to retrieve label");
            }

            uint32_t bins_per_bundle = params_.bins_per_bundle();

            // Preprocess a single element. This algebraizes the item and gives back its field
            // element representation as well as its cuckoo hash. We only read one of the locations
            // because the labels are the same in each location.

            auto [alg_item, cuckoo_idx] = preprocess_unlabeled_data(hashed_item, params_)[0];

            // Now figure out where to look to get the label

            auto [bin_idx, bundle_idx] = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);

            // Retrieve the algebraic labels from one of the BinBundles at this index. With match
            // tags, the item is found by its HashedItem.
            const vector<BinBundle> &bundle_set = bin_bundles_[bundle_idx];
            vector<felt_t> alg_label;
            bool got_labels = false;
            for (const BinBundle &bundle : bundle_set) {
                // Try to retrieve the contiguous labels from this BinBundle
                bool found =
                    params_.uses_tags()
                        ? bundle.try_get_multi_label(alg_item, hashed_item, bin_idx, alg_label)
                        : bundle.try_get_multi_label(alg_item, bin_idx, alg_label);
                if (found) {
                    got_labels = true;
                    break;
                }
            }

            // It shouldn't be possible to have items in your set but be unable to retrieve the
            // associated label. Throw an exception because something is terribly wrong.
            if (!got_labels) {
                APSI_LOG_ERROR(
                    "Failed to retrieve label for an item that was supposed to be in the SenderDB");
                throw logic_error("failed to retrieve label");
            }

            // With match tags, the label parts begin with the parts of the item's tag, which is
            // not part of its label
            if (params_.uses_tags()) {
                size_t tag_felt_count = mul_safe<size_t>(
                    params_.tag_part_count(), params_.item_params().felts_per_item);
                alg_label.erase(
                    alg_label.begin(), alg_label.begin() + static_cast<ptrdiff_t>(tag_felt_count));
            }

            // All good. Now just reconstruct the big label from its split-up parts
            EncryptedLabel encrypted_label = dealgebraize_label(
                alg_label,
                alg_label.size() * static_cast<size_t>(params_.item_bit_count_per_felt()),
                params_.seal_params().plain_modulus());

            // Resize down to the effective byte count
            encrypted_label.resize(nonce_byte_count_ + label_byte_count_);

            // Decrypt the label
            return decrypt_label(encrypted_label, key, nonce_byte_count_);
        }

        size_t SenderDB::save(ostream &out) const
        {
            // Lock the database for reading
            auto lock = get_reader_lock();

            STOPWATCH(sender_stopwatch, "SenderDB::save");
            APSI_LOG_DEBUG("Start saving SenderDB");

            // First save the PSIParam
            stringstream ss;
            params_.save(ss);
            string params_str = ss.str();

            flatbuffers::FlatBufferBuilder fbs_builder(1024);

            auto params = fbs_builder.CreateVector(
                reinterpret_cast<const uint8_t *>(params_str.data()), params_str.size());
            fbs::SenderDBInfo info(
                safe_cast<uint32_t>(label_byte_count_),
                safe_cast<uint32_t>(nonce_byte_count_),
                safe_cast<uint32_t>(item_count_),
                compressed_,
                stripped_);
            auto oprf_key_span = oprf_key_.key_span();
            auto oprf_key = fbs_builder.CreateVector(oprf_key_span.data(), oprf_key_span.size());
            auto hashed_items = fbs_builder.CreateVectorOfStructs([&] {
                // The HashedItems vector is populated with an immediately-invoked lambda
                vector<fbs::HashedItem> ret;
                ret.reserve(get_hashed_items().size());
                for (const auto &it : get_hashed_items()) {
                    // Read out the two 64-bit halves with memcpy to avoid strict-aliasing UB.
                    const auto &v = it.value();
                    uint64_t lw = 0;
                    uint64_t hw = 0;
                    std::memcpy(&lw, v.data(), sizeof(lw));
                    std::memcpy(&hw, v.data() + sizeof(lw), sizeof(hw));
                    ret.emplace_back(lw, hw);
                }
                return ret;
            }());

            auto bin_bundle_count = get_bin_bundle_count_unlocked();

            fbs::SenderDBBuilder sender_db_builder(fbs_builder);
            sender_db_builder.add_params(params);
            sender_db_builder.add_info(&info);
            sender_db_builder.add_oprf_key(oprf_key);
            sender_db_builder.add_hashed_items(hashed_items);
            sender_db_builder.add_bin_bundle_count(safe_cast<uint32_t>(bin_bundle_count));
            auto sdb = sender_db_builder.Finish();
            fbs_builder.FinishSizePrefixed(sdb);

            out.write(
                reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));
            size_t total_size = fbs_builder.GetSize();

            // Finally write the BinBundles
            size_t bin_bundle_data_size = 0;
            for (size_t bundle_idx = 0; bundle_idx < bin_bundles_.size(); bundle_idx++) {
                for (const auto &bb : bin_bundles_[bundle_idx]) {
                    auto size = bb.save(out, static_cast<uint32_t>(bundle_idx));
                    APSI_LOG_DEBUG(
                        "Saved BinBundle at bundle index " << bundle_idx << " (" << size
                                                           << " bytes)");
                    bin_bundle_data_size += size;
                }
            }

            total_size += bin_bundle_data_size;
            APSI_LOG_DEBUG(
                "Saved SenderDB with " << get_item_count() << " items (" << total_size
                                       << " bytes)");

            APSI_LOG_DEBUG("Finished saving SenderDB");

            return total_size;
        }

        pair<SenderDB, size_t> SenderDB::Load(istream &in)
        {
            STOPWATCH(sender_stopwatch, "SenderDB::Load");
            APSI_LOG_DEBUG("Start loading SenderDB");

            vector<unsigned char> in_data(apsi::util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(
                reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedSenderDBBuffer(verifier);
            if (!safe) {
                APSI_LOG_ERROR("Failed to load SenderDB: the buffer is invalid");
                throw runtime_error("failed to load SenderDB");
            }

            const auto *sdb = fbs::GetSizePrefixedSenderDB(in_data.data());

            // The schema marks each of these required, so a buffer reaching this point has been
            // through a verifier that rejects any omission. Checking again keeps the guarantee
            // local to the code that relies on it: these accessors are dereferenced
            // unconditionally below, and a SenderDB is loaded from a file whose integrity this
            // function cannot assume.
            if (!sdb->params() || !sdb->info() || !sdb->oprf_key() || !sdb->hashed_items()) {
                APSI_LOG_ERROR("Failed to load SenderDB: the buffer is missing a required field");
                throw runtime_error("failed to load SenderDB");
            }

            // Load the PSIParams; this will automatically check version compatibility
            unique_ptr<PSIParams> params;
            try {
                ArrayGetBuffer agbuf(
                    reinterpret_cast<const char *>(sdb->params()->data()),
                    static_cast<streamsize>(sdb->params()->size()));
                istream params_stream(&agbuf);
                params = make_unique<PSIParams>(PSIParams::Load(params_stream).first);
            } catch (const runtime_error &ex) {
                APSI_LOG_ERROR("APSI threw an exception creating PSIParams: " << ex.what());
                throw runtime_error("failed to load SenderDB");
            }

            // Load the info so we know what kind of SenderDB to create
            size_t item_count = static_cast<size_t>(sdb->info()->item_count());
            size_t label_byte_count = static_cast<size_t>(sdb->info()->label_byte_count());
            size_t nonce_byte_count = static_cast<size_t>(sdb->info()->nonce_byte_count());

            bool compressed = sdb->info()->compressed();
            bool stripped = sdb->info()->stripped();

            APSI_LOG_DEBUG(
                "Loaded SenderDB properties: "
                "item_count: "
                << item_count
                << "; "
                   "label_byte_count: "
                << label_byte_count
                << "; "
                   "nonce_byte_count: "
                << nonce_byte_count
                << "; "
                   "compressed: "
                << boolalpha << compressed
                << "; "
                   "stripped: "
                << boolalpha << stripped);

            // Create the correct kind of SenderDB
            unique_ptr<SenderDB> sender_db;
            try {
                sender_db =
                    make_unique<SenderDB>(*params, label_byte_count, nonce_byte_count, compressed);
                sender_db->stripped_ = stripped;
                sender_db->item_count_ = item_count;
            } catch (const invalid_argument &ex) {
                APSI_LOG_ERROR("APSI threw an exception creating SenderDB: " << ex.what());
                throw runtime_error("failed to load SenderDB");
            }

            // Check that the OPRF key size is correct
            size_t loaded_oprf_key_size = sdb->oprf_key()->size();
            if (loaded_oprf_key_size != oprf_key_size) {
                APSI_LOG_ERROR(
                    "The loaded OPRF key has invalid size ("
                    << loaded_oprf_key_size << " bytes; expected " << oprf_key_size << " bytes)");
                throw runtime_error("failed to load SenderDB");
            }

            // Copy over the OPRF key
            sender_db->oprf_key_.load(oprf_key_span_const_type(
                reinterpret_cast<const unsigned char *>(sdb->oprf_key()->data()), oprf_key_size));

            // Load the hashed items if this SenderDB is not stripped
            if (!stripped) {
                const auto &hashed_items = *sdb->hashed_items();
                sender_db->hashed_items_.reserve(hashed_items.size());
                for (const auto &it : hashed_items) {
                    sender_db->hashed_items_.insert({ it->low_word(), it->high_word() });
                }

                // Check that item_count matches the number of hashed items
                if (item_count != hashed_items.size()) {
                    APSI_LOG_ERROR(
                        "The item count indicated in the loaded SenderDB ("
                        << item_count << ") does not match the size of the loaded data ("
                        << hashed_items.size() << ")");
                    throw runtime_error("failed to load SenderDB");
                }
            }

            uint32_t bin_bundle_count = sdb->bin_bundle_count();

            // Cap bin_bundle_count to a sane upper bound before reading any BinBundle. The
            // legitimate value is at most a small multiple of bundle_idx_count; cap at 64K *
            // bundle_idx_count which leaves enormous headroom over realistic configurations.
            uint64_t max_bin_bundle_count = mul_safe<uint64_t>(
                static_cast<uint64_t>(params->bundle_idx_count()), static_cast<uint64_t>(65536));
            if (bin_bundle_count > max_bin_bundle_count) {
                APSI_LOG_ERROR(
                    "The loaded SenderDB declares " << bin_bundle_count
                                                    << " bin bundles, exceeding the upper bound ("
                                                    << max_bin_bundle_count << ")");
                throw runtime_error("failed to load SenderDB");
            }

            size_t bin_bundle_data_size = 0;
            uint32_t max_bin_size = params->table_params().max_items_per_bin;
            uint32_t ps_low_degree = params->query_params().ps_low_degree;
            uint32_t bins_per_bundle = params->bins_per_bundle();
            size_t label_size =
                compute_label_part_count(label_byte_count, nonce_byte_count, *params);

            // Load all BinBundle data. The count comes from the file, so nothing is reserved for
            // it: the vector grows only as BinBundles are actually read. A file that ends early is
            // reported at the first BinBundle missing from it.
            vector<vector<unsigned char>> bin_bundle_data;
            for (uint32_t bb_idx = 0; bb_idx < bin_bundle_count; bb_idx++) {
                try {
                    bin_bundle_data.push_back(read_from_stream(in));
                } catch (const runtime_error &ex) {
                    APSI_LOG_ERROR(
                        "Failed to read BinBundle " << bb_idx + 1 << " of the " << bin_bundle_count
                                                    << " the SenderDB declares: " << ex.what());
                    if (in.eof()) {
                        throw runtime_error("failed to load SenderDB: the data is truncated");
                    }
                    throw runtime_error("failed to load SenderDB");
                }
            }

            // Use multiple threads to recreate the BinBundles
            ThreadPoolMgr tpm;

            vector<mutex> bundle_idx_mtxs(sender_db->bin_bundles_.size());
            mutex bin_bundle_data_size_mtx;
            TaskGroup tasks(tpm.thread_pool());
            tasks.reserve(bin_bundle_data.size());
            // A range-for here would force the task to capture the loop's reference variable,
            // which is rebound on every iteration while earlier tasks are still running.
            // Indexing lets the task capture bb_data_idx by value instead.
            // NOLINTNEXTLINE(modernize-loop-convert)
            for (size_t bb_data_idx = 0; bb_data_idx < bin_bundle_data.size(); bb_data_idx++) {
                tasks.add([&, bb_data_idx] {
                    BinBundle bb(
                        sender_db->crypto_context_,
                        label_size,
                        max_bin_size,
                        ps_low_degree,
                        bins_per_bundle,
                        compressed,
                        stripped,
                        params->tag_part_count());
                    auto &raw_bb_data = bin_bundle_data[bb_data_idx];
                    auto bb_data = bb.load(raw_bb_data);

                    // Clear the data buffer since we have now loaded the BinBundle
                    raw_bb_data.clear();

                    // Check that the loaded bundle index is not out of range
                    if (bb_data.first >= sender_db->bin_bundles_.size()) {
                        APSI_LOG_ERROR(
                            "The bundle index of the loaded BinBundle ("
                            << bb_data.first << ") exceeds the maximum ("
                            << params->bundle_idx_count() - 1 << ")");
                        throw runtime_error("failed to load SenderDB");
                    }

                    // Add the loaded BinBundle to the correct location in bin_bundles_. The lock
                    // must be released even if push_back throws: the tasks are waited on as a
                    // group, so a mutex left locked here would hang every other task that needs
                    // this bundle index rather than just failing this one.
                    {
                        lock_guard<mutex> bundle_idx_lock(bundle_idx_mtxs[bb_data.first]);
                        sender_db->bin_bundles_[bb_data.first].push_back(std::move(bb));
                    }

                    APSI_LOG_DEBUG(
                        "Loaded BinBundle at bundle index " << bb_data.first << " ("
                                                            << bb_data.second << " bytes)");

                    lock_guard<mutex> bin_bundle_data_size_lock(bin_bundle_data_size_mtx);
                    bin_bundle_data_size += bb_data.second;
                });
            }

            // Wait for the tasks to finish
            tasks.join();

            size_t total_size = in_data.size() + bin_bundle_data_size;
            APSI_LOG_DEBUG(
                "Loaded SenderDB with " << sender_db->get_item_count() << " items (" << total_size
                                        << " bytes)");

            // Make sure the BinBundle caches are valid
            sender_db->generate_caches();

            APSI_LOG_DEBUG("Finished loading SenderDB");

            return { std::move(*sender_db), total_size };
        }
    } // namespace sender
} // namespace apsi
