// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <iostream>
#include <fstream>
#include <string>
#include <csignal>
#include <functional>

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
namespace fs = std::filesystem;
using namespace apsi;
using namespace apsi::sender;
using namespace apsi::network;
using namespace apsi::oprf;

int run_sender_dispatcher(const CLP &cmd);

unique_ptr<CSVReader::DBData> load_db(const string &db_file);

shared_ptr<SenderDB> create_sender_db(
    const CSVReader::DBData &db_data,
    const PSIParams &psi_params,
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

    return run_sender_dispatcher(cmd);
}

void sigint_handler(int param)
{
    APSI_LOG_WARNING("Sender interrupted");
    print_timing_report(sender_stopwatch);
    exit(0);
}

int run_sender_dispatcher(const CLP &cmd)
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

    shared_ptr<SenderDB> sender_db;
    if (!cmd.db_file().empty())
    {
        unique_ptr<CSVReader::DBData> db_data = load_db(cmd.db_file());
        if (!db_data)
        {
            // Failed to read db file
            APSI_LOG_ERROR("Failed to read database: terminating");
            return -1;
        }

        sender_db = create_sender_db(*db_data, *params, cmd.nonce_byte_count());
        db_data = nullptr;
    }
    else if (!cmd.sender_db_load_file().empty())
    {
        ifstream fs(cmd.sender_db_load_file(), ios::binary);
        try
        {
            auto [data, size] = SenderDB::Load(fs);
            sender_db = make_shared<SenderDB>(move(data));
            APSI_LOG_INFO("Loaded SenderDB (" << size << " bytes) from " << cmd.sender_db_load_file());
        }
        catch(const exception &e)
        {
            // Failed to load SenderDB
            APSI_LOG_ERROR("Failed to load SenderDB: terminating");
            return -1;
        }
    }
    else
    {
        // No input given
        return -1;
    }

    // Try to save the SenderDB if a save file was given
    if (!cmd.sender_db_save_file().empty())
    {
        ofstream fs(cmd.sender_db_save_file(), ios::binary);
        try
        {
            size_t size = sender_db->save(fs);
            APSI_LOG_INFO("Saved SenderDB (" << size << " bytes) to " << cmd.sender_db_save_file());
        }
        catch(const exception &e)
        {
            // Failed to load SenderDB
            APSI_LOG_WARNING("Failed to save SenderDB");
        }
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
    const PSIParams &psi_params,
    size_t nonce_byte_count)
{
    shared_ptr<SenderDB> sender_db;
    if (holds_alternative<CSVReader::UnlabeledData>(db_data))
    {
        try
        {
            sender_db = make_shared<SenderDB>(psi_params, 0, 0, true);
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

            sender_db = make_shared<SenderDB>(psi_params, label_byte_count, nonce_byte_count, true);
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

    APSI_LOG_INFO("SenderDB packing rate: " << sender_db->get_packing_rate());

    return sender_db ;
}
