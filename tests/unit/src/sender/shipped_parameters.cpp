// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// APSI
#include "apsi/bin_bundle.h"
#include "apsi/crypto_context.h"
#include "apsi/plaintext_powers.h"
#include "apsi/powers.h"
#include "apsi/psi_params.h"
#include "apsi/util/db_encoding.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/ciphertext.h"
#include "seal/keygenerator.h"
#include "seal/memorymanager.h"
#include "seal/plaintext.h"
#include "seal/relinkeys.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::sender;
using namespace apsi::util;
using namespace seal;

namespace APSITests {
    namespace {
        PSIParams load_shipped_params(const string &name)
        {
            ifstream file(filesystem::path(APSI_PARAMETERS_DIR) / (name + ".json"));
            if (!file.is_open()) {
                throw runtime_error("cannot open " + name + ".json");
            }
            stringstream json;
            json << file.rdbuf();
            return PSIParams::Load(json.str());
        }

        /**
        Answers a query for an item in a full bin as a sender with the given parameters does, and
        checks that the receiver decrypts what the bin holds for the item with noise budget left.

        A BinBundle is filled at its first location with as many items as a SenderDB puts in a bin,
        max_items_per_bin with match tags and one fewer without, with distinct field elements, and
        its cache is generated, so that every polynomial has the largest degree the parameters
        allow. The receiver encrypts the source powers of a query holding one of the items under
        keys of its own, and the sender computes the other powers through the PowersDag, as
        Sender::RunQuery does, and evaluates each polynomial of the BinBundle with eval or
        eval_patstock, which switch the result to the last level of the modulus chain. Without match
        tags the matching polynomial then gives zero for the item, and with or without them the
        label polynomial gives the item's part.

        The items have one part: with match tags a tag part, which is what any label part is to a
        BinBundle, and without them a label part beside the matching polynomial. Every part is
        evaluated alike, so one is enough, and with one the largest sets need about a gigabyte.
        */
        void check_full_bin_answer(const PSIParams &params)
        {
            const size_t felts_per_item = params.item_params().felts_per_item;
            const uint32_t max_items_per_bin = params.table_params().max_items_per_bin;
            const uint32_t ps_low_degree = params.query_params().ps_low_degree;
            const size_t tag_part_count = params.uses_tags() ? 1 : 0;
            const size_t label_size = 1;

            mt19937_64 rng(1);
            uniform_int_distribution<felt_t> random_felt(
                0, (felt_t(1) << params.item_bit_count_per_felt()) - 1);

            // The receiver's keys, and the sender's evaluator, which has the relinearization keys a
            // query brings along if the parameters allow relinearization
            CryptoContext receiver_context(params);
            KeyGenerator keygen(*receiver_context.seal_context());
            receiver_context.set_secret(keygen.secret_key());
            bool relinearize = receiver_context.seal_context()->using_keyswitching();
            RelinKeys relin_keys;
            if (relinearize) {
                keygen.create_relin_keys(relin_keys);
            }
            CryptoContext sender_context(params);
            sender_context.set_evaluator(relin_keys);

            // A full bin at the first location, of items with distinct field elements in each bin
            // and random parts
            size_t bin_size = params.uses_tags() ? max_items_per_bin : max_items_per_bin - 1;
            vector<vector<pair<felt_t, vector<felt_t>>>> items(bin_size);
            vector<set<felt_t>> bin_felts(felts_per_item);
            for (auto &item : items) {
                for (size_t s = 0; s < felts_per_item; s++) {
                    felt_t felt = random_felt(rng);
                    while (!bin_felts[s].insert(felt).second) {
                        felt = random_felt(rng);
                    }
                    item.emplace_back(felt, vector<felt_t>{ random_felt(rng) });
                }
            }

            BinBundle bundle(
                sender_context,
                label_size,
                max_items_per_bin,
                ps_low_degree,
                params.bins_per_bundle(),
                true,
                false,
                tag_part_count);
            for (size_t i = 0; i < bin_size; i++) {
                int32_t size = -1;
                if (params.uses_tags()) {
                    TaggedAlgItemLabel tagged;
                    tagged.item = HashedItem(i + 1, 0);
                    tagged.alg_item_label = items[i];
                    size = bundle.multi_insert_for_real(tagged, 0);
                } else {
                    size = bundle.multi_insert_for_real(items[i], 0);
                }
                ASSERT_EQ(static_cast<int32_t>(i + 1), size);
            }
            bundle.regen_cache();
            const BinBundleCache &cache = bundle.get_cache();

            // The receiver queries the item in the middle of the bin, with random field elements
            // in the other slots, as for other items
            const auto &queried = items[bin_size / 2];
            vector<uint64_t> values(params.bins_per_bundle());
            for (auto &value : values) {
                value = random_felt(rng);
            }
            for (size_t s = 0; s < felts_per_item; s++) {
                values[s] = queried[s].first;
            }

            PowersDag pd;
            ASSERT_TRUE(pd.configure(
                params.query_params().query_powers,
                create_powers_set(ps_low_degree, max_items_per_bin)));
            auto encrypted_powers =
                receiver::PlaintextPowers(values, params, pd).encrypt(receiver_context);

            // The sender computes the other powers, and switches them to the levels the plaintexts
            // are at, as Sender::ComputePowers does
            auto evaluator = sender_context.evaluator();
            vector<Ciphertext> powers(static_cast<size_t>(max_items_per_bin) + 1);
            for (auto &[power, ct] : encrypted_powers) {
                powers[power] = ct.extract(sender_context.seal_context());
            }

            pd.apply([&](const PowersDag::PowersNode &node) {
                if (node.is_source()) {
                    return;
                }

                auto [first, second] = node.parents;
                if (first == second) {
                    evaluator->square(powers[first], powers[node.power]);
                } else {
                    evaluator->multiply(powers[first], powers[second], powers[node.power]);
                }
                if (relinearize) {
                    evaluator->relinearize_inplace(
                        powers[node.power], *sender_context.relin_keys());
                }
            });

            auto high_powers_parms_id =
                get_parms_id_for_chain_idx(*sender_context.seal_context(), 1);
            auto low_powers_parms_id =
                get_parms_id_for_chain_idx(*sender_context.seal_context(), 2);
            for (uint32_t power : pd.target_powers()) {
                if (ps_low_degree && (power > ps_low_degree)) {
                    evaluator->mod_switch_to_inplace(powers[power], high_powers_parms_id);
                    continue;
                }

                evaluator->mod_switch_to_inplace(
                    powers[power], ps_low_degree ? low_powers_parms_id : high_powers_parms_id);
                evaluator->transform_to_ntt_inplace(powers[power]);
            }

            // Evaluates a polynomial of the BinBundle as Sender::RunQuery does, and decrypts the
            // result, which must be at the last level and have noise budget left
            MemoryPoolHandle pool = MemoryManager::GetPool();
            auto answer = [&](const BatchedPlaintextPolyn &polyn, vector<uint64_t> &slots) {
                size_t degree = polyn.batched_coeffs.size() - 1;
                bool using_ps = (ps_low_degree > 1) && (ps_low_degree < degree);
                Ciphertext result =
                    using_ps ? polyn.eval_patstock(sender_context, powers, ps_low_degree, pool)
                             : polyn.eval(powers, pool);
                ASSERT_EQ(sender_context.seal_context()->last_parms_id(), result.parms_id());
                ASSERT_LT(0, receiver_context.decryptor()->invariant_noise_budget(result));

                Plaintext plain;
                receiver_context.decryptor()->decrypt(result, plain);
                receiver_context.encoder()->decode(plain, slots);
            };

            // Without match tags, the matching polynomial, whose roots are the bin's items,
            // vanishes at the item
            if (!params.uses_tags()) {
                SCOPED_TRACE("matching polynomial");
                ASSERT_EQ(bin_size + 1, cache.batched_matching_polyn.batched_coeffs.size());

                vector<uint64_t> slots;
                ASSERT_NO_FATAL_FAILURE(answer(cache.batched_matching_polyn, slots));
                for (size_t s = 0; s < felts_per_item; s++) {
                    ASSERT_EQ(0, slots[s]) << "slot " << s;
                }
            }

            // The label polynomial, which takes the parts of the bin's items at their field
            // elements, gives the item's part
            SCOPED_TRACE("label polynomial");
            const BatchedPlaintextPolyn &label_polyn = cache.batched_interp_polyns.at(0);
            ASSERT_EQ(bin_size, label_polyn.batched_coeffs.size());

            vector<uint64_t> slots;
            ASSERT_NO_FATAL_FAILURE(answer(label_polyn, slots));
            for (size_t s = 0; s < felts_per_item; s++) {
                ASSERT_EQ(queried[s].second[0], slots[s]) << "slot " << s;
            }
        }

        void check_full_bin_answers(const vector<string> &names)
        {
            for (const auto &name : names) {
                SCOPED_TRACE(name);
                PSIParams params = load_shipped_params(name);
                ASSERT_NO_FATAL_FAILURE(check_full_bin_answer(params));
            }
        }
    } // namespace

    TEST(ShippedParametersTests, FullBinIsAnsweredWithNoiseBudgetLeft)
    {
        // The parameter sets checked by default: every set with a single prime, which has the
        // least noise budget to spare and is the cheapest to check, and one with more, which
        // relinearizes and uses Paterson-Stockmeyer. The other sets take minutes in a Debug
        // build, so DISABLED_FullBinIsAnsweredForEverySet checks every set.
        check_full_bin_answers(
            { "100K-1",
              "100K-1-16",
              "256K-1",
              "256K-2048-cmp",
              "256K-4096-cmp",
              "1M-1",
              "1M-512-cmp",
              "1M-1024-cmp",
              "1M-2048-cmp",
              "1M-4096-cmp",
              "1M-11041" });
    }

    TEST(ShippedParametersTests, DISABLED_FullBinIsAnsweredForEverySet)
    {
        // Every parameter set in the parameters directory. It takes far longer than the other
        // tests, and the largest sets need about a gigabyte of memory. Run it after a change to a
        // parameter set, or to how a query is evaluated, with
        //
        //     unit_tests --gtest_also_run_disabled_tests --gtest_filter=ShippedParametersTests.*
        vector<string> names;
        for (const auto &entry :
             filesystem::directory_iterator(filesystem::path(APSI_PARAMETERS_DIR))) {
            if (entry.path().extension() == ".json") {
                names.push_back(entry.path().stem().string());
            }
        }
        sort(names.begin(), names.end());
        ASSERT_LE(size_t(36), names.size()) << "expected to find the shipped parameter sets";

        check_full_bin_answers(names);
    }
} // namespace APSITests
