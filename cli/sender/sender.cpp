// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <csignal>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#if defined(__GNUC__) && (__GNUC__ < 8) && !defined(__clang__)
#include <experimental/filesystem>
#else
#include <filesystem>
#endif

// APSI
#include "apsi/log.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/version.h"
#include "apsi/zmq/sender_dispatcher.h"
#include "common/common_utils.h"
#include "common/csv_reader.h"
#include "sender/clp.h"
#include "sender/sender_utils.h"

using namespace std;
#if defined(__GNUC__) && (__GNUC__ < 8) && !defined(__clang__)
namespace fs = std::experimental::filesystem;
#else
namespace fs = std::filesystem;
#endif
using namespace apsi;
using namespace apsi::sender;
using namespace apsi::network;
using namespace apsi::oprf;

int start_sender(const CLP &cmd);

unique_ptr<CSVReader::DBData> load_db(const string &db_file);

shared_ptr<SenderDB> create_sender_db(
    const CSVReader::DBData &db_data,
    unique_ptr<PSIParams> psi_params,
    OPRFKey &oprf_key,
    size_t nonce_byte_count,
    bool compress);

int main(int argc, char *argv[])
{
    prepare_console();

    CLP cmd("Example of a Sender implementation", APSI_VERSION);
    if (!cmd.parse_args(argc, argv)) {
        APSI_LOG_ERROR("Failed parsing command line arguments");
        return -1;
    }

    return start_sender(cmd);
}

void sigint_handler(int param [[maybe_unused]])
{
    APSI_LOG_WARNING("Sender interrupted");
    print_timing_report(sender_stopwatch);
    exit(0);
}

shared_ptr<SenderDB> try_load_sender_db(const CLP &cmd, OPRFKey &oprf_key)
{
    shared_ptr<SenderDB> result = nullptr;

    ifstream fs(cmd.db_file(), ios::binary);
    fs.exceptions(ios_base::badbit | ios_base::failbit);
    try {
        auto [data, size] = SenderDB::Load(fs);
        APSI_LOG_INFO("Loaded SenderDB (" << size << " bytes) from " << cmd.db_file());
        if (!cmd.params_file().empty()) {
            APSI_LOG_WARNING(
                "PSI parameters were loaded with the SenderDB; ignoring given PSI parameters");
        }
        result = make_shared<SenderDB>(move(data));

        // Load also the OPRF key
        oprf_key.load(fs);
        APSI_LOG_INFO("Loaded OPRF key (" << oprf_key_size << " bytes) from " << cmd.db_file());
    } catch (const exception &e) {
        // Failed to load SenderDB
        APSI_LOG_DEBUG("Failed to load SenderDB: " << e.what());
    }

    return result;
}

shared_ptr<SenderDB> try_load_csv_db(const CLP &cmd, OPRFKey &oprf_key)
{
    unique_ptr<PSIParams> params = build_psi_params(cmd);
    if (!params) {
        // We must have valid parameters given
        APSI_LOG_ERROR("Failed to set PSI parameters");
        return nullptr;
    }

    unique_ptr<CSVReader::DBData> db_data;
    if (cmd.db_file().empty() || !(db_data = load_db(cmd.db_file()))) {
        // Failed to read db file
        APSI_LOG_DEBUG("Failed to load data from a CSV file");
        return nullptr;
    }

    return create_sender_db(
        *db_data, move(params), oprf_key, cmd.nonce_byte_count(), cmd.compress());
}

bool try_save_sender_db(const CLP &cmd, shared_ptr<SenderDB> sender_db, const OPRFKey &oprf_key)
{
    if (!sender_db) {
        return false;
    }

    ofstream fs(cmd.sdb_out_file(), ios::binary);
    fs.exceptions(ios_base::badbit | ios_base::failbit);
    try {
        size_t size = sender_db->save(fs);
        APSI_LOG_INFO("Saved SenderDB (" << size << " bytes) to " << cmd.sdb_out_file());

        // Save also the OPRF key (fixed size: oprf_key_size bytes)
        oprf_key.save(fs);
        APSI_LOG_INFO("Saved OPRF key (" << oprf_key_size << " bytes) to " << cmd.sdb_out_file());

    } catch (const exception &e) {
        APSI_LOG_WARNING("Failed to save SenderDB: " << e.what());
        return false;
    }

    return true;
}

int start_sender(const CLP &cmd)
{
    ThreadPoolMgr::SetThreadCount(cmd.threads());
    APSI_LOG_INFO("Setting thread count to " << ThreadPoolMgr::GetThreadCount());
    signal(SIGINT, sigint_handler);

    // Check that the database file is valid
    throw_if_file_invalid(cmd.db_file());

    // Try loading first as a SenderDB, then as a CSV file
    shared_ptr<SenderDB> sender_db;
    OPRFKey oprf_key;
    if (!(sender_db = try_load_sender_db(cmd, oprf_key)) &&
        !(sender_db = try_load_csv_db(cmd, oprf_key))) {
        APSI_LOG_ERROR("Failed to create SenderDB: terminating");
        return -1;
    }

    // Print the total number of bin bundles and the largest number of bin bundles for any bundle
    // index
    uint32_t max_bin_bundles_per_bundle_idx = 0;
    for (uint32_t bundle_idx = 0; bundle_idx < sender_db->get_params().bundle_idx_count();
         bundle_idx++) {
        max_bin_bundles_per_bundle_idx =
            max(max_bin_bundles_per_bundle_idx,
                static_cast<uint32_t>(sender_db->get_bin_bundle_count(bundle_idx)));
    }
    APSI_LOG_INFO(
        "SenderDB holds a total of " << sender_db->get_bin_bundle_count() << " bin bundles across "
                                     << sender_db->get_params().bundle_idx_count()
                                     << " bundle indices");
    APSI_LOG_INFO(
        "The largest bundle index holds " << max_bin_bundles_per_bundle_idx << " bin bundles");

    // Try to save the SenderDB if a save file was given
    if (!cmd.sdb_out_file().empty() && !try_save_sender_db(cmd, sender_db, oprf_key)) {
        return -1;
    }

    // Run the dispatcher
    atomic<bool> stop = false;
    ZMQSenderDispatcher dispatcher(sender_db, oprf_key);

    // The dispatcher will run until stopped.
    dispatcher.run(stop, cmd.net_port());

    return 0;
}

unique_ptr<CSVReader::DBData> load_db(const string &db_file)
{
    CSVReader::DBData db_data;
    try {
        CSVReader reader(db_file);
        tie(db_data, ignore) = reader.read();
    } catch (const exception &ex) {
        APSI_LOG_WARNING("Could not open or read file `" << db_file << "`: " << ex.what());
        return nullptr;
    }

    return make_unique<CSVReader::DBData>(move(db_data));
}

shared_ptr<SenderDB> create_sender_db(
    const CSVReader::DBData &db_data,
    unique_ptr<PSIParams> psi_params,
    OPRFKey &oprf_key,
    size_t nonce_byte_count,
    bool compress)
{
    if (!psi_params) {
        APSI_LOG_ERROR("No PSI parameters were given");
        return nullptr;
    }

    shared_ptr<SenderDB> sender_db;
    if (holds_alternative<CSVReader::UnlabeledData>(db_data)) {
        try {
            sender_db = make_shared<SenderDB>(*psi_params, 0, 0, compress);
            sender_db->set_data(get<CSVReader::UnlabeledData>(db_data));

            APSI_LOG_INFO(
                "Created unlabeled SenderDB with " << sender_db->get_item_count() << " items");
        } catch (const exception &ex) {
            APSI_LOG_ERROR("Failed to create SenderDB: " << ex.what());
            return nullptr;
        }
    } else if (holds_alternative<CSVReader::LabeledData>(db_data)) {
        try {
            auto &labeled_db_data = get<CSVReader::LabeledData>(db_data);

            // Find the longest label and use that as label size
            size_t label_byte_count =
                max_element(labeled_db_data.begin(), labeled_db_data.end(), [](auto &a, auto &b) {
                    return a.second.size() < b.second.size();
                })->second.size();

            sender_db =
                make_shared<SenderDB>(*psi_params, label_byte_count, nonce_byte_count, compress);
            sender_db->set_data(labeled_db_data);
            APSI_LOG_INFO(
                "Created labeled SenderDB with " << sender_db->get_item_count() << " items and "
                                                 << label_byte_count << "-byte labels ("
                                                 << nonce_byte_count << "-byte nonces)");
        } catch (const exception &ex) {
            APSI_LOG_ERROR("Failed to create SenderDB: " << ex.what());
            return nullptr;
        }
    } else {
        // Should never reach this point
        APSI_LOG_ERROR("Loaded database is in an invalid state");
        return nullptr;
    }

    if (compress) {
        APSI_LOG_INFO("Using in-memory compression to reduce memory footprint");
    }

    // Read the OPRFKey and strip the SenderDB to reduce memory use
    oprf_key = sender_db->strip();

    APSI_LOG_INFO("SenderDB packing rate: " << sender_db->get_packing_rate());

    return sender_db;
}
