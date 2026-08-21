// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

// APSI
#include "apsi/log.h"
#include "apsi/network/channel.h"
#include "apsi/oprf/oprf_common.h"
#include "apsi/plaintext_powers.h"
#include "apsi/receiver.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/db_encoding.h"
#include "apsi/util/label_encryptor.h"
#include "apsi/util/task_group.h"
#include "apsi/util/utils.h"

// Kuku
#include "kuku/kuku.h"

// SEAL
#include "seal/ciphertext.h"
#include "seal/keygenerator.h"
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace kuku;

namespace apsi {
    using namespace util;
    using namespace network;
    using namespace oprf;

    namespace {
        template <typename T>
        bool has_n_zeros(T *ptr, size_t count)
        {
            return all_of(ptr, ptr + count, [](auto a) { return a == T(0); });
        }

        /**
        Decides whether a result package carrying the given sender-chosen bundle index is worth
        processing. Returns false, having logged why, for a bundle index outside the range this
        query covers.

        Note this cannot deduplicate bundle indices. A sender legitimately sends one package per
        bin bundle and may hold several bin bundles at a single bundle index, so "already seen"
        is not an error -- Sender::RunQuery announces get_bin_bundle_count() packages, which
        exceeds bundle_idx_count as soon as any bundle index overflows one bin bundle. Duplicate
        and replayed packages are therefore handled where they actually conflict, by the
        keep-first merge under the merge lock.

        An out-of-range index is hostile input rather than an internal error, so it must not
        abort the query.
        */
        bool bundle_idx_in_range(uint32_t bundle_idx, uint32_t bundle_idx_count)
        {
            if (bundle_idx >= bundle_idx_count) {
                APSI_LOG_ERROR(
                    "Received a result package for bundle index "
                    << bundle_idx << " but this query covers only " << bundle_idx_count
                    << " bundle indices; ignoring the package");
                return false;
            }

            return true;
        }

        /**
        Aborts the exchange if the channel reports that a receive failed in a way that retrying
        cannot repair. Callers wait for a message by looping on a null return, so without this
        check a single malformed or mistyped message from the sender holds the receiver for its
        whole deadline -- and indefinitely where the caller asked to wait indefinitely -- for data
        the sender has already sent and will not send again.

        Aborting is louder than returning what was collected so far. A partial result set is
        indistinguishable from a genuine "no match" at every call site, so quietly returning one
        would turn a transport failure into a wrong answer.
        */
        void throw_if_receive_failed(const Channel &chl, const char *what)
        {
            if (!chl.receive_failed()) {
                return;
            }

            APSI_LOG_ERROR("Channel failed while waiting for the " << what);
            throw runtime_error(string("failed to receive the ") + what);
        }
    } // namespace

    namespace receiver {
        size_t IndexTranslationTable::find_item_idx(size_t table_idx) const noexcept
        {
            auto item_idx = table_idx_to_item_idx_.find(table_idx);
            if (item_idx == table_idx_to_item_idx_.cend()) {
                return item_count();
            }

            return item_idx->second;
        }

        Receiver::ReceiveDeadline::ReceiveDeadline(chrono::milliseconds timeout)
            : timeout_(timeout),
              last_progress_(chrono::steady_clock::now().time_since_epoch().count())
        {}

        void Receiver::ReceiveDeadline::note_progress() noexcept
        {
            last_progress_.store(
                chrono::steady_clock::now().time_since_epoch().count(), memory_order_relaxed);
        }

        void Receiver::ReceiveDeadline::throw_if_expired(const char *what) const
        {
            // Exactly zero, and only exactly zero, asks for an indefinite wait. A negative
            // timeout is treated as one already spent, which is what makes the natural way of
            // passing on a remaining budget -- deadline minus now -- safe: once that budget runs
            // out the subtraction goes negative, and a caller doing the more careful thing must
            // not thereby switch the deadline off.
            if (timeout_ == chrono::milliseconds::zero()) {
                return;
            }

            chrono::steady_clock::time_point last_progress{ chrono::steady_clock::duration{
                last_progress_.load(memory_order_relaxed) } };
            auto silent_for = chrono::duration_cast<chrono::milliseconds>(
                chrono::steady_clock::now() - last_progress);
            if (silent_for < timeout_) {
                return;
            }

            APSI_LOG_ERROR(
                "Gave up waiting for the " << what << " after " << silent_for.count()
                                           << " ms without hearing from the sender");
            throw runtime_error(string("timed out waiting for the ") + what);
        }

        Receiver::Receiver(const PSIParams &params) : params_(params)
        {
            initialize();
        }

        void Receiver::reset_keys()
        {
            // Generate new keys
            KeyGenerator generator(*get_seal_context());

            // Set the symmetric key, encryptor, and decryptor
            crypto_context_.set_secret(generator.secret_key());

            // Create Serializable<RelinKeys> and move to relin_keys_ for storage
            relin_keys_.clear();
            if (get_seal_context()->using_keyswitching()) {
                Serializable<RelinKeys> relin_keys(generator.create_relin_keys());
                relin_keys_.set(std::move(relin_keys));
            }
        }

        uint32_t Receiver::reset_powers_dag(const set<uint32_t> &source_powers)
        {
            // First compute the target powers
            set<uint32_t> target_powers = create_powers_set(
                params_.query_params().ps_low_degree, params_.table_params().max_items_per_bin);

            // Configure the PowersDag
            pd_.configure(source_powers, target_powers);

            // Check that the PowersDag is valid
            if (!pd_.is_configured()) {
                APSI_LOG_ERROR(
                    "Failed to configure PowersDag ("
                    << "source_powers: " << to_string(source_powers) << ", "
                    << "target_powers: " << to_string(target_powers) << ")");
                throw logic_error("failed to configure PowersDag");
            }
            APSI_LOG_DEBUG("Configured PowersDag with depth " << pd_.depth());

            return pd_.depth();
        }

        void Receiver::initialize()
        {
            APSI_LOG_DEBUG("PSI parameters set to: " << params_.to_string());
            APSI_LOG_DEBUG(
                "Derived parameters: " << "item_bit_count_per_felt: "
                                       << params_.item_bit_count_per_felt()
                                       << "; item_bit_count: " << params_.item_bit_count()
                                       << "; bins_per_bundle: " << params_.bins_per_bundle()
                                       << "; bundle_idx_count: " << params_.bundle_idx_count());

            STOPWATCH(recv_stopwatch, "Receiver::initialize");

            // Initialize the CryptoContext with a new SEALContext
            crypto_context_ = CryptoContext(params_);

            // Set up the PowersDag
            reset_powers_dag(params_.query_params().query_powers);

            // Create new keys
            reset_keys();
        }

        unique_ptr<SenderOperation> Receiver::CreateParamsRequest()
        {
            auto sop = make_unique<SenderOperationParms>();
            APSI_LOG_INFO("Created parameter request");

            return sop;
        }

        PSIParams Receiver::RequestParams(NetworkChannel &chl, chrono::milliseconds timeout)
        {
            // Create parameter request and send to Sender
            chl.send(CreateParamsRequest());

            // Only one message is expected, so nothing restarts this clock: it bounds the wait
            // from the moment the request went out.
            ReceiveDeadline deadline(timeout);

            // Wait for a valid message of the right type. Naming the expected type lets the
            // channel reject a response of any other type as a failure; left unnamed, a
            // mismatched response would be discarded silently and waited for again forever.
            ParamsResponse response;
            bool logged_waiting = false;
            while (
                !(response =
                      to_params_response(chl.receive_response(SenderOperationType::sop_parms)))) {
                throw_if_receive_failed(chl, "response to the parameter request");
                deadline.throw_if_expired("response to the parameter request");

                if (!logged_waiting) {
                    // We want to log 'Waiting' only once, even if we have to wait for several
                    // sleeps.
                    logged_waiting = true;
                    APSI_LOG_INFO("Waiting for response to parameter request");
                }

                this_thread::sleep_for(50ms);
            }

            return *response->params;
        }

        OPRFReceiver Receiver::CreateOPRFReceiver(const vector<Item> &items)
        {
            STOPWATCH(recv_stopwatch, "Receiver::CreateOPRFReceiver");

            OPRFReceiver oprf_receiver(items);
            APSI_LOG_INFO("Created OPRFReceiver for " << oprf_receiver.item_count() << " items");

            return oprf_receiver;
        }

        pair<vector<HashedItem>, LabelKeyVector> Receiver::ExtractHashes(
            const OPRFResponse &oprf_response, const OPRFReceiver &oprf_receiver)
        {
            STOPWATCH(recv_stopwatch, "Receiver::ExtractHashes");

            if (!oprf_response) {
                APSI_LOG_ERROR("Failed to extract OPRF hashes for items: oprf_response is null");
                return {};
            }

            auto response_size = oprf_response->data.size();
            size_t oprf_response_item_count = response_size / oprf_response_size;
            if ((response_size % oprf_response_size) ||
                (oprf_response_item_count != oprf_receiver.item_count())) {
                APSI_LOG_ERROR(
                    "Failed to extract OPRF hashes for items: unexpected OPRF response size ("
                    << response_size << " B)");
                return {};
            }

            vector<HashedItem> items(oprf_receiver.item_count());
            LabelKeyVector label_keys(oprf_receiver.item_count());
            oprf_receiver.process_responses(
                oprf_response->data,
                items,
                gsl::span<LabelKey>(label_keys.data(), label_keys.size()));
            APSI_LOG_INFO("Extracted OPRF hashes for " << oprf_response_item_count << " items");

            return make_pair(std::move(items), std::move(label_keys));
        }

        unique_ptr<SenderOperation> Receiver::CreateOPRFRequest(const OPRFReceiver &oprf_receiver)
        {
            auto sop = make_unique<SenderOperationOPRF>();
            sop->data = oprf_receiver.query_data();
            APSI_LOG_INFO("Created OPRF request for " << oprf_receiver.item_count() << " items");

            return sop;
        }

        pair<vector<HashedItem>, LabelKeyVector> Receiver::RequestOPRF(
            const vector<Item> &items, NetworkChannel &chl, chrono::milliseconds timeout)
        {
            auto oprf_receiver = CreateOPRFReceiver(items);

            // Create OPRF request and send to Sender
            chl.send(CreateOPRFRequest(oprf_receiver));

            // Only one message is expected, so nothing restarts this clock: it bounds the wait
            // from the moment the request went out.
            ReceiveDeadline deadline(timeout);

            // Wait for a valid message of the right type. Naming the expected type lets the
            // channel reject a response of any other type as a failure.
            OPRFResponse response;
            bool logged_waiting = false;
            while (!(
                response = to_oprf_response(chl.receive_response(SenderOperationType::sop_oprf)))) {
                throw_if_receive_failed(chl, "response to the OPRF request");
                deadline.throw_if_expired("response to the OPRF request");

                if (!logged_waiting) {
                    // We want to log 'Waiting' only once, even if we have to wait for several
                    // sleeps.
                    logged_waiting = true;
                    APSI_LOG_INFO("Waiting for response to OPRF request");
                }

                this_thread::sleep_for(50ms);
            }

            // Extract the OPRF hashed items
            auto hashes = ExtractHashes(response, oprf_receiver);

            // ExtractHashes reports an unusable response by returning nothing, which the channel
            // has no reason to record as a failure: the message itself was well formed, it just
            // did not answer the question asked. Left to propagate, an empty result is
            // indistinguishable from a genuine empty intersection at every call site downstream,
            // so a sender could turn a transport-level failure into a wrong answer by replying
            // with the wrong number of hashes.
            if (hashes.first.size() != items.size()) {
                throw runtime_error("failed to extract OPRF hashes from the sender's response");
            }

            return hashes;
        }

        pair<Request, IndexTranslationTable> Receiver::create_query(const vector<HashedItem> &items)
        {
            APSI_LOG_INFO("Creating encrypted query for " << items.size() << " items");
            STOPWATCH(recv_stopwatch, "Receiver::create_query");

            IndexTranslationTable itt;
            itt.item_count_ = items.size();

            // Create the cuckoo table
            KukuTable cuckoo(
                params_.table_params().table_size,      // Size of the hash table
                0,                                      // Not using a stash
                params_.table_params().hash_func_count, // Number of hash functions
                { 0, 0 },                               // Hardcoded { 0, 0 } as the seed
                cuckoo_table_insert_attempts,           // The number of insertion attempts
                { 0, 0 });                              // The empty element can be set to anything

            // Hash the data into a cuckoo hash table
            // cuckoo_hashing
            {
                STOPWATCH(recv_stopwatch, "Receiver::create_query::cuckoo_hashing");
                APSI_LOG_DEBUG(
                    "Inserting " << items.size() << " items into cuckoo table of size "
                                 << cuckoo.table_size() << " with " << cuckoo.loc_func_count()
                                 << " hash functions");
                for (size_t item_idx = 0; item_idx < items.size(); item_idx++) {
                    const auto &item = items[item_idx];
                    kuku::item_type kuku_item;
                    std::memcpy(&kuku_item, item.value().data(), sizeof(kuku_item));
                    if (!cuckoo.insert(kuku_item)) {
                        // Insertion can fail for two reasons:
                        //
                        //     (1) The item was already in the table, in which case the "leftover
                        //     item" is empty; (2) Cuckoo hashing failed due to too small table or
                        //     too few hash functions.
                        //
                        // In case (1) simply move on to the next item and log this issue. Case (2)
                        // is a critical issue so we throw and exception.
                        if (cuckoo.is_empty_item(cuckoo.leftover_item())) {
                            APSI_LOG_DEBUG(
                                "Skipping repeated insertion of items["
                                << item_idx << "]: " << item.to_string());
                        } else {
                            // We redact the item (OPRF value) from the log message to avoid leaking
                            // information about the receiver's input in case of errors.
                            APSI_LOG_ERROR(
                                "Failed to insert items["
                                << item_idx << "] (item value redacted); cuckoo table fill-rate: "
                                << cuckoo.fill_rate());
                            throw runtime_error("failed to insert item into cuckoo table");
                        }
                    }
                }
                APSI_LOG_DEBUG(
                    "Finished inserting items with "
                    << cuckoo.loc_func_count()
                    << " hash functions; cuckoo table fill-rate: " << cuckoo.fill_rate());
            }

            // Once the table is filled, fill the table_idx_to_item_idx map
            for (size_t item_idx = 0; item_idx < items.size(); item_idx++) {
                kuku::item_type kuku_item;
                std::memcpy(&kuku_item, items[item_idx].value().data(), sizeof(kuku_item));
                auto item_loc = cuckoo.query(kuku_item);
                itt.table_idx_to_item_idx_[item_loc.location()] = item_idx;
            }

            // Set up unencrypted query data
            vector<PlaintextPowers> plain_powers;

            // prepare_data
            {
                STOPWATCH(recv_stopwatch, "Receiver::create_query::prepare_data");
                for (uint32_t bundle_idx = 0; bundle_idx < params_.bundle_idx_count();
                     bundle_idx++) {
                    APSI_LOG_DEBUG("Preparing data for bundle index " << bundle_idx);

                    // First, find the items for this bundle index
                    gsl::span<const item_type> bundle_items(
                        cuckoo.table().data() +
                            (static_cast<size_t>(bundle_idx * params_.items_per_bundle())),
                        params_.items_per_bundle());

                    vector<uint64_t> alg_items;
                    for (const auto &item : bundle_items) {
                        // Now set up a BitstringView to this item
                        gsl::span<const unsigned char> item_bytes(
                            reinterpret_cast<const unsigned char *>(item.data()), sizeof(item));
                        BitstringView<const unsigned char> item_bits(
                            item_bytes, params_.item_bit_count());

                        // Create an algebraic item by breaking up the item into modulo
                        // plain_modulus parts
                        vector<uint64_t> alg_item =
                            bits_to_field_elts(item_bits, params_.seal_params().plain_modulus());
                        copy(alg_item.cbegin(), alg_item.cend(), back_inserter(alg_items));
                    }

                    // Now that we have the algebraized items for this bundle index, we create a
                    // PlaintextPowers object that computes all necessary powers of the algebraized
                    // items.
                    plain_powers.emplace_back(std::move(alg_items), params_, pd_);
                }
            }

            // The very last thing to do is encrypt the plain_powers and consolidate the matching
            // powers for different bundle indices
            unordered_map<uint32_t, vector<SEALObject<Ciphertext>>> encrypted_powers;

            // encrypt_data
            {
                STOPWATCH(recv_stopwatch, "Receiver::create_query::encrypt_data");
                for (uint32_t bundle_idx = 0; bundle_idx < params_.bundle_idx_count();
                     bundle_idx++) {
                    APSI_LOG_DEBUG("Encoding and encrypting data for bundle index " << bundle_idx);

                    // Encrypt the data for this power
                    auto encrypted_power(plain_powers[bundle_idx].encrypt(crypto_context_));

                    // Move the encrypted data to encrypted_powers
                    for (auto &e : encrypted_power) {
                        encrypted_powers[e.first].emplace_back(std::move(e.second));
                    }
                }
            }

            // Set up the return value
            auto sop_query = make_unique<SenderOperationQuery>();
            sop_query->compr_mode = Serialization::compr_mode_default;
            sop_query->relin_keys = relin_keys_;
            sop_query->data = std::move(encrypted_powers);
            auto sop = to_request(std::move(sop_query));

            APSI_LOG_INFO("Finished creating encrypted query");

            return { std::move(sop), itt };
        }

        vector<MatchRecord> Receiver::request_query(
            const vector<HashedItem> &items,
            const LabelKeyVector &label_keys,
            NetworkChannel &chl,
            chrono::milliseconds timeout)
        {
            ThreadPoolMgr tpm;

            // Create query and send to Sender
            auto query = create_query(items);
            chl.send(std::move(query.first));
            auto itt = std::move(query.second);

            // One deadline covers both phases of the exchange. The query response restarts it, so
            // the sender gets the full window again for the first result package, and each package
            // restarts it for the next. Sending is asynchronous, so this first window also covers
            // uploading the query; see Receiver::default_receive_timeout.
            ReceiveDeadline deadline(timeout);

            // Wait for query response. Naming the expected type lets the channel reject a
            // response of any other type as a failure.
            QueryResponse response;
            bool logged_waiting = false;
            while (
                !(response =
                      to_query_response(chl.receive_response(SenderOperationType::sop_query)))) {
                throw_if_receive_failed(chl, "response to the query request");
                deadline.throw_if_expired("response to the query request");

                if (!logged_waiting) {
                    // We want to log 'Waiting' only once, even if we have to wait for several
                    // sleeps.
                    logged_waiting = true;
                    APSI_LOG_INFO("Waiting for response to query request");
                }

                this_thread::sleep_for(50ms);
            }

            deadline.note_progress();

            // Set up the result. Note itt, not query.second, which was moved from above.
            ResultMergeState merge_state(itt.item_count());

            // Get the number of ResultPackages we expect to receive
            atomic<uint32_t> package_count{ response->package_count };

            // Launch threads to receive ResultPackages and decrypt results
            size_t task_count = min<size_t>(ThreadPoolMgr::GetThreadCount(), package_count);
            TaskGroup tasks(tpm.thread_pool());
            APSI_LOG_INFO(
                "Launching " << task_count << " result worker tasks to handle " << package_count
                             << " result parts");
            for (size_t t = 0; t < task_count; t++) {
                tasks.add([&]() {
                    process_result_worker(
                        package_count, merge_state, deadline, label_keys, itt, chl);
                });
            }

            tasks.join();

            auto &mrs = merge_state.mrs;
            APSI_LOG_INFO(
                "Found " << accumulate(mrs.begin(), mrs.end(), 0, [](auto acc, auto &curr) {
                    return acc + curr.found;
                }) << " matches");

            return std::move(mrs);
        }

        vector<MatchRecord> Receiver::process_result_part(
            const LabelKeyVector &label_keys,
            const IndexTranslationTable &itt,
            const ResultPart &result_part) const
        {
            STOPWATCH(recv_stopwatch, "Receiver::process_result_part");

            if (!result_part) {
                APSI_LOG_ERROR("Failed to process result: result_part is null");
                return {};
            }

            // The number of items that were submitted in the query
            size_t item_count = itt.item_count();

            // Decrypt and decode the result; the result vector will have full batch size
            PlainResultPackage plain_rp = result_part->extract(crypto_context_);

            size_t felts_per_item = safe_cast<size_t>(params_.item_params().felts_per_item);
            size_t items_per_bundle = safe_cast<size_t>(params_.items_per_bundle());
            size_t bundle_start =
                mul_safe(safe_cast<size_t>(plain_rp.bundle_idx), items_per_bundle);

            // Check if we are supposed to have label data present but don't have for some reason
            size_t label_byte_count = safe_cast<size_t>(plain_rp.label_byte_count);
            if (label_byte_count && plain_rp.label_result.empty()) {
                APSI_LOG_WARNING(
                    "Expected " << label_byte_count
                                << "-byte labels in this result part, "
                                   "but label data is missing entirely");

                // Just ignore the label data
                label_byte_count = 0;
            }

            // Read the nonce byte count and compute the effective label byte count; set the nonce
            // byte count to zero if no label is expected anyway.
            size_t nonce_byte_count =
                label_byte_count ? safe_cast<size_t>(plain_rp.nonce_byte_count) : 0;
            size_t effective_label_byte_count = add_safe(nonce_byte_count, label_byte_count);

            // How much label data did we actually receive?
            size_t received_label_bit_count =
                mul_safe(safe_cast<size_t>(params_.item_bit_count()), plain_rp.label_result.size());

            // Compute the received label byte count and check that it is not less than what was
            // expected
            size_t received_label_byte_count = received_label_bit_count / 8;
            if (received_label_byte_count < nonce_byte_count) {
                APSI_LOG_WARNING(
                    "Expected " << nonce_byte_count
                                << " bytes of nonce data in this result part but only "
                                << received_label_byte_count
                                << " bytes were received; ignoring the label data");

                // Just ignore the label data
                label_byte_count = 0;
                effective_label_byte_count = 0;
            } else if (received_label_byte_count < effective_label_byte_count) {
                APSI_LOG_WARNING(
                    "Expected " << label_byte_count
                                << " bytes of label data in this result part but only "
                                << received_label_byte_count - nonce_byte_count
                                << " bytes were received");

                // Reset our expectations to what was actually received
                label_byte_count = received_label_byte_count - nonce_byte_count;
                effective_label_byte_count = received_label_byte_count;
            }

            // If there is a label, then we better have the appropriate label encryption keys
            // available
            if (label_byte_count && label_keys.size() != item_count) {
                APSI_LOG_WARNING(
                    "Expected " << item_count << " label encryption keys but only "
                                << label_keys.size() << " were given; ignoring the label data");

                // Just ignore the label data
                label_byte_count = 0;
                effective_label_byte_count = 0;
            }

            // Set up the result vector
            vector<MatchRecord> mrs(item_count);

            // Iterate over the decoded data to find consecutive zeros indicating a match
            StrideIter<const uint64_t *> plain_rp_iter(plain_rp.psi_result.data(), felts_per_item);
            seal_for_each_n(
                iter(plain_rp_iter, static_cast<size_t>(0)), items_per_bundle, [&](auto &&I) {
                    // Find felts_per_item consecutive zeros
                    bool match = has_n_zeros(get<0>(I).ptr(), felts_per_item);
                    if (!match) {
                        return;
                    }

                    // Compute the cuckoo table index for this item. Then find the corresponding
                    // index in the input items vector so we know where to place the result.
                    size_t table_idx = add_safe(get<1>(I), bundle_start);
                    auto item_idx = itt.find_item_idx(table_idx);

                    // If this table_idx doesn't match any item_idx, ignore the result no matter
                    // what it is
                    if (item_idx == itt.item_count()) {
                        return;
                    }

                    // Two cuckoo table indices in this one package translated to the same item.
                    // The translation table is built by the receiver and maps each item to a
                    // single location, so this indicates the table has been corrupted rather than
                    // anything the sender did. Report it and keep the match already recorded; a
                    // package arriving over the network must never abort the query.
                    if (mrs[item_idx]) {
                        APSI_LOG_ERROR(
                            "The table index -> item index translation table indicated a "
                            "location that was already filled by another match from this "
                            "result package; the translation table (query) has probably "
                            "been corrupted; keeping the first match");

                        return;
                    }

                    APSI_LOG_DEBUG(
                        "Match found for items[" << item_idx << "] at cuckoo table index "
                                                 << table_idx);

                    // Create a new MatchRecord
                    MatchRecord mr;
                    mr.found = true;

                    // Next, extract the label results, if any
                    if (label_byte_count) {
                        APSI_LOG_DEBUG(
                            "Found " << plain_rp.label_result.size() << " label parts for items["
                                     << item_idx << "]; expecting " << label_byte_count
                                     << "-byte label");

                        // Collect the entire label into this vector
                        AlgLabel alg_label;

                        size_t label_offset = mul_safe(get<1>(I), felts_per_item);
                        for (auto &label_parts : plain_rp.label_result) {
                            gsl::span<felt_t> label_part(
                                label_parts.data() + label_offset, felts_per_item);
                            copy(label_part.begin(), label_part.end(), back_inserter(alg_label));
                        }

                        // Create the label
                        EncryptedLabel encrypted_label = dealgebraize_label(
                            alg_label,
                            received_label_bit_count,
                            params_.seal_params().plain_modulus());

                        // Resize down to the effective byte count
                        encrypted_label.resize(effective_label_byte_count);

                        // Decrypt the label
                        Label label =
                            decrypt_label(encrypted_label, label_keys[item_idx], nonce_byte_count);

                        // Set the label
                        mr.label.set(std::move(label));
                    }

                    // We are done with the MatchRecord, so add it to the mrs vector
                    mrs[item_idx] = std::move(mr);
                });

            return mrs;
        }

        vector<MatchRecord> Receiver::process_result(
            const LabelKeyVector &label_keys,
            const IndexTranslationTable &itt,
            const vector<ResultPart> &result) const
        {
            APSI_LOG_INFO("Processing " << result.size() << " result parts");
            STOPWATCH(recv_stopwatch, "Receiver::process_result");

            vector<MatchRecord> mrs(itt.item_count());

            for (const auto &result_part : result) {
                if (!result_part) {
                    APSI_LOG_ERROR("Failed to process result: result_part is null");
                    continue;
                }

                if (!bundle_idx_in_range(result_part->bundle_idx, params_.bundle_idx_count())) {
                    continue;
                }

                auto this_mrs = process_result_part(label_keys, itt, result_part);
                if (this_mrs.size() != mrs.size()) {
                    // Something went wrong with process_result; error is already logged
                    continue;
                }

                // Merge the new MatchRecords with mrs
                seal_for_each_n(
                    iter(mrs, this_mrs, static_cast<size_t>(0)), mrs.size(), [](auto &&I) {
                        if (get<1>(I) && !get<0>(I)) {
                            // This match needs to be merged into mrs
                            get<0>(I) = std::move(get<1>(I));
                        } else if (get<1>(I) && get<0>(I)) {
                            // Two result parts claim the same item. An honest sender cannot do
                            // this: the receiver's cuckoo table maps each item to exactly one
                            // table index, so exactly one bin bundle can match it. So this is a
                            // repeated or forged package. Report it, keep the match already
                            // recorded, and carry on -- the caller assembled this vector, possibly
                            // from a hostile sender, so it must not be able to abort the query.
                            APSI_LOG_ERROR(
                                "Found a match for items[" << get<2>(I)
                                                           << "] but an existing match for this "
                                                              "location was already found before "
                                                              "from a different result part; "
                                                              "keeping the first match");
                        }
                    });
            }

            APSI_LOG_INFO(
                "Found " << accumulate(mrs.begin(), mrs.end(), 0, [](auto acc, auto &curr) {
                    return acc + curr.found;
                }) << " matches");

            return mrs;
        }

        void Receiver::process_result_worker(
            atomic<uint32_t> &package_count,
            ResultMergeState &merge_state,
            ReceiveDeadline &deadline,
            const LabelKeyVector &label_keys,
            const IndexTranslationTable &itt,
            Channel &chl) const
        {
            stringstream sw_ss;
            sw_ss << "Receiver::process_result_worker [" << this_thread::get_id() << "]";
            STOPWATCH(recv_stopwatch, sw_ss.str());

            APSI_LOG_DEBUG("Result worker [" << this_thread::get_id() << "]: starting");

            auto seal_context = get_seal_context();

            while (true) {
                // Return if all packages have been claimed
                uint32_t curr_package_count = package_count;
                if (curr_package_count == 0) {
                    APSI_LOG_DEBUG(
                        "Result worker [" << this_thread::get_id()
                                          << "]: all packages claimed; exiting");
                    return;
                }

                // If there has been no change to package_count, then decrement atomically
                if (!package_count.compare_exchange_strong(
                        curr_package_count, curr_package_count - 1)) {
                    continue;
                }

                // Wait for a valid ResultPart. A null return either means nothing has arrived
                // yet, which is worth waiting out, or that the channel consumed a package it
                // could not parse, which is not: this worker has already claimed a slot in
                // package_count, and the package that would have filled it no longer exists.
                // Sleeping between attempts keeps an idle wait off the CPU.
                ResultPart result_part;
                while (!(result_part = chl.receive_result(seal_context))) {
                    throw_if_receive_failed(chl, "result package");
                    deadline.throw_if_expired("result package");

                    this_thread::sleep_for(50ms);
                }

                // Every package is evidence for all the workers that the sender is still there,
                // not just for the one that happened to read it.
                deadline.note_progress();

                // The bundle index is readable before the package is decrypted, so screen it
                // first: a package for an index this query does not cover costs us no decryption.
                if (!bundle_idx_in_range(result_part->bundle_idx, params_.bundle_idx_count())) {
                    continue;
                }

                // Process the ResultPart to get the corresponding vector of MatchRecords
                auto this_mrs = process_result_part(label_keys, itt, result_part);
                if (this_mrs.size() != merge_state.mrs.size()) {
                    // Something went wrong with process_result_part; error is already logged
                    continue;
                }

                // Merge the new MatchRecords with mrs
                lock_guard<mutex> merge_lock(merge_state.mtx);
                seal_for_each_n(
                    iter(merge_state.mrs, this_mrs, static_cast<size_t>(0)),
                    merge_state.mrs.size(),
                    [](auto &&I) {
                        if (get<1>(I) && !get<0>(I)) {
                            // This match needs to be merged into mrs
                            get<0>(I) = std::move(get<1>(I));
                        } else if (get<1>(I) && get<0>(I)) {
                            // A repeated or forged package; see the note on the same case in
                            // Receiver::process_result. This branch is the reason the merge runs
                            // under the lock: reaching it means two workers are writing the same
                            // MatchRecord, and doing that unsynchronized corrupts the label's
                            // vector. Keep the match already recorded and carry on.
                            APSI_LOG_ERROR(
                                "Result worker ["
                                << this_thread::get_id() << "]: found a match for items["
                                << get<2>(I)
                                << "] but an existing match for this location was "
                                   "already found before from a different result "
                                   "part; keeping the first match");
                        }
                    });
            }
        }
    } // namespace receiver
} // namespace apsi
