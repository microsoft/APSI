// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <iostream>
#include <fstream>
#include <string>
#include <csignal>
#include <functional>
#if defined(__GNUC__) && (__GNUC__ < 8) && !defined(__clang__)
#include <experimental/filesystem>
#else
#include <filesystem>
#endif

// APSI
#include "apsi/log.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/version.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/zmq/sender_dispatcher.h"
#include "common/common_utils.h"
#include "common/csv_reader.h"
#include "sender/sender_utils.h"
#include "sender/clp.h"

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
    size_t nonce_byte_count);

int main(int argc, char *argv[])
{
    prepare_console();

    CLP cmd("Example of a Sender implementation", APSI_VERSION);
    if (!cmd.parse_args(argc, argv))
    {
        APSI_LOG_ERROR("Failed parsing command line arguments");
        return -1;
    }

    return start_sender(cmd);
}

void sigint_handler(int param)
{
    APSI_LOG_WARNING("Sender interrupted");
    print_timing_report(sender_stopwatch);
    exit(0);
}

shared_ptr<SenderDB> try_load_sender_db(const CLP &cmd)
{
    shared_ptr<SenderDB> result = nullptr;

    ifstream fs(cmd.db_file(), ios::binary);
    fs.exceptions(ios_base::badbit | ios_base::failbit);
    try
    {
        auto [data, size] = SenderDB::Load(fs);
        APSI_LOG_INFO("Loaded SenderDB (" << size << " bytes) from " << cmd.db_file());
        if (!cmd.params_file().empty())
        {
            APSI_LOG_WARNING("PSI parameters were loaded with the SenderDB; ignoring given PSI parameters");
        }
        result = make_shared<SenderDB>(move(data));
    }
    catch(const exception &e)
    {
        // Failed to load SenderDB
        APSI_LOG_DEBUG("Failed to load SenderDB: " << e.what());
    }

    return result;
}

shared_ptr<SenderDB> try_load_csv_db(const CLP &cmd)
{
    unique_ptr<PSIParams> params = build_psi_params(cmd);
    if (!params)
    {
        // We must have valid parameters given
        return nullptr;
    }

    unique_ptr<CSVReader::DBData> db_data;
    if (cmd.db_file().empty() || !(db_data = load_db(cmd.db_file())))
    {
        // Failed to read db file
        APSI_LOG_DEBUG("Failed to load data from a CSV file");
        return nullptr;
    }

    return create_sender_db(*db_data, move(params), cmd.nonce_byte_count());
}

bool try_save_sender_db(const CLP &cmd, shared_ptr<SenderDB> sender_db)
{
    if (!sender_db)
    {
        return false;
    }

    ofstream fs(cmd.sdb_out_file(), ios::binary);
    fs.exceptions(ios_base::badbit | ios_base::failbit);
    try
    {
        size_t size = sender_db->save(fs);
        APSI_LOG_INFO("Saved SenderDB (" << size << " bytes) to " << cmd.sdb_out_file());
    }
    catch(const exception &e)
    {
        APSI_LOG_WARNING("Failed to save SenderDB: " << e.what());
        return false;
    }

    return true;
}

int start_sender(const CLP &cmd)
{
    // Set up parameters according to command line input
    unique_ptr<PSIParams> params = build_psi_params(cmd);
    if (!params)
    {
        // Failed to set parameters
        APSI_LOG_ERROR("Failed to set PSI parameters: terminating");
        return -1;
    }

    ThreadPoolMgr::SetThreadCount(cmd.threads());
    APSI_LOG_INFO("Thread count is set to " << ThreadPoolMgr::GetThreadCount());
    signal(SIGINT, sigint_handler);

    // Try loading first as a SenderDB, then as a CSV file
    shared_ptr<SenderDB> sender_db;
    if (!(sender_db = try_load_sender_db(cmd)) && !(sender_db = try_load_csv_db(cmd)))
    {
        APSI_LOG_ERROR("Failed to create SenderDB: terminating");
        return -1;
    }

    // Check that the database file is valid
    throw_if_file_invalid(cmd.db_file());

    // Try to save the SenderDB if a save file was given
    if (!cmd.sdb_out_file().empty() && !try_save_sender_db(cmd, sender_db))
    {
        return -1;
    }

    // Run the dispatcher
    atomic<bool> stop = false;
    ZMQSenderDispatcher dispatcher(sender_db);

    // The dispatcher will run until stopped.
    dispatcher.run(stop, cmd.net_port());

    return 0;
}

unique_ptr<CSVReader::DBData> load_db(const string &db_file)
{
    CSVReader::DBData db_data;
    try
    {
        CSVReader reader(db_file);
        tie(db_data, ignore) = reader.read();
    }
    catch (const exception &ex)
    {
        APSI_LOG_WARNING("Could not open or read file `" << db_file << "`: " << ex.what());
        return nullptr;
    }

    return make_unique<CSVReader::DBData>(move(db_data));
}

shared_ptr<SenderDB> create_sender_db(
    const CSVReader::DBData &db_data,
    unique_ptr<PSIParams> psi_params,
    size_t nonce_byte_count)
{
    if (!psi_params)
    {
        APSI_LOG_ERROR("No PSI parameters were given");
        return nullptr;
    }

    shared_ptr<SenderDB> sender_db;
    if (holds_alternative<CSVReader::UnlabeledData>(db_data))
    {
        try
        {
            sender_db = make_shared<SenderDB>(*psi_params, 0, 0, true);
            sender_db->set_data(get<CSVReader::UnlabeledData>(db_data));

            APSI_LOG_INFO("Created unlabeled SenderDB with " << sender_db->get_item_count() << " items");
        }
        catch (const exception &ex)
        {
            APSI_LOG_ERROR("Failed to create SenderDB: " << ex.what());
            return nullptr;
        }
    }
    else if (holds_alternative<CSVReader::LabeledData>(db_data))
    {
        try
        {
            auto &labeled_db_data = get<CSVReader::LabeledData>(db_data);

            // Find the longest label and use that as label size
            size_t label_byte_count = max_element(
                labeled_db_data.begin(),
                labeled_db_data.end(),
                [](auto &a, auto &b) { return a.second.size() < b.second.size(); }
            )->second.size();

            sender_db = make_shared<SenderDB>(*psi_params, label_byte_count, nonce_byte_count, true);
            sender_db->set_data(labeled_db_data);
            APSI_LOG_INFO("Created labeled SenderDB with "
                << sender_db->get_item_count() << " items and " << label_byte_count << "-byte labels ("
                << nonce_byte_count << "-byte nonces)");
        }
        catch (const exception &ex)
        {
            APSI_LOG_ERROR("Failed to create SenderDB: " << ex.what());
            return nullptr;
        }
    }
    else
    {
        // Should never reach this point
        APSI_LOG_ERROR("Loaded database is in an invalid state");
        return nullptr;
    }

    // Strip all unnecessary data from the SenderDB to reduce memory use
    sender_db->strip();

    APSI_LOG_INFO("SenderDB packing rate: " << sender_db->get_packing_rate());

    return sender_db ;
}
