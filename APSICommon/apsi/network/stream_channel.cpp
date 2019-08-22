// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

// STD
#include <mutex>

// APSI
#include "stream_channel.h"
#include "network_utils.h"

using namespace std;
using namespace apsi;
using namespace apsi::network;
using namespace seal;


StreamChannel::StreamChannel(istream& istream, ostream& ostream)
    : istream_(istream),
      ostream_(ostream),
      receive_mutex_(make_unique<mutex>()),
      send_mutex_(make_unique<mutex>())
{
}

StreamChannel::~StreamChannel()
{
}

bool StreamChannel::receive(shared_ptr<SenderOperation>& sender_op)
{
    // Get the type
    SenderOperationType type = read_operation_type();

    switch (type)
    {
    case SOP_get_parameters:
        sender_op = decode_get_parameters();
        break;

    case SOP_preprocess:
        sender_op = decode_preprocess();
        break;

    case SOP_query:
        sender_op = decode_query();
        break;

    default:
        throw runtime_error("Invalid SenderOperationType");
    }

    bytes_received_ += sizeof(SenderOperationType);

    return true;
}

void StreamChannel::receive(SenderResponseGetParameters& response)
{
    // First part is message type
    SenderOperationType senderOpType = read_operation_type();

    if (senderOpType != SOP_get_parameters)
        throw runtime_error("Should be get parameters type");

    // PSIConfParams
    istream_.read(reinterpret_cast<char*>(&response.psiconf_params), sizeof(PSIParams::PSIConfParams));

    // TableParams
    istream_.read(reinterpret_cast<char*>(&response.table_params), sizeof(PSIParams::TableParams));

    // CuckooParams
    istream_.read(reinterpret_cast<char*>(&response.cuckoo_params), sizeof(PSIParams::CuckooParams));

    // SEALParams
    response.seal_params.encryption_params = EncryptionParameters::Load(istream_);
    istream_.read(reinterpret_cast<char*>(&response.seal_params.decomposition_bit_count), sizeof(unsigned));

    // ExFieldParams
    istream_.read(reinterpret_cast<char*>(&response.exfield_params), sizeof(PSIParams::ExFieldParams));

    bytes_received_ += sizeof(PSIParams::PSIConfParams);
    bytes_received_ += sizeof(PSIParams::TableParams);
    bytes_received_ += sizeof(PSIParams::CuckooParams);
    bytes_received_ += sizeof(PSIParams::SEALParams);
    bytes_received_ += sizeof(PSIParams::ExFieldParams);
}

void StreamChannel::send_get_parameters()
{
    // We only need the type.
    write_operation_type(SOP_get_parameters);
}

void StreamChannel::send_get_parameters_response(const vector<u8>& client_id, const PSIParams& params)
{
    // client_id is unused for StreamChannel.
    write_operation_type(SOP_get_parameters);

    // PSIConfParams
    const PSIParams::PSIConfParams& psiconfparams = params.get_psiconf_params();
    ostream_.write(reinterpret_cast<const char*>(&psiconfparams), sizeof(PSIParams::PSIConfParams));

    // TableParams
    const PSIParams::TableParams& tableparams = params.get_table_params();
    ostream_.write(reinterpret_cast<const char*>(&tableparams), sizeof(PSIParams::TableParams));

    // CuckooParams
    const PSIParams::CuckooParams& cuckooparams = params.get_cuckoo_params();
    ostream_.write(reinterpret_cast<const char*>(&cuckooparams), sizeof(PSIParams::CuckooParams));

    // SEALParams
    unsigned dbc = params.decomposition_bit_count();
    EncryptionParameters::Save(params.get_seal_params().encryption_params, ostream_);
    ostream_.write(reinterpret_cast<const char*>(&dbc), sizeof(unsigned));

    // ExFieldParams
    const PSIParams::ExFieldParams& exfieldparams = params.get_exfield_params();
    ostream_.write(reinterpret_cast<const char*>(&exfieldparams), sizeof(PSIParams::ExFieldParams));

    bytes_sent_ += sizeof(PSIParams::PSIConfParams);
    bytes_sent_ += sizeof(PSIParams::TableParams);
    bytes_sent_ += sizeof(PSIParams::CuckooParams);
    bytes_sent_ += sizeof(PSIParams::SEALParams);
    bytes_sent_ += sizeof(PSIParams::ExFieldParams);
}

void StreamChannel::receive(SenderResponsePreprocess& response)
{
    // First part is message type
    SenderOperationType type = read_operation_type();

    if (type != SOP_preprocess)
        throw runtime_error("Should be preprocess type");

    // Size of buffer
    size_t size;
    istream_.read(reinterpret_cast<char*>(&size), sizeof(size_t));

    // Actual buffer
    response.buffer.resize(size);
    istream_.read(reinterpret_cast<char*>(response.buffer.data()), size);

    bytes_received_ += sizeof(size_t);
    bytes_received_ += size;
}

void StreamChannel::send_preprocess(const vector<u8>& buffer)
{
    // Type
    write_operation_type(SOP_preprocess);

    // Size of buffer
    size_t size = buffer.size();
    ostream_.write(reinterpret_cast<const char*>(&size), sizeof(size_t));

    // Actual buffer
    ostream_.write(reinterpret_cast<const char*>(buffer.data()), size);

    bytes_sent_ += sizeof(size_t);
    bytes_sent_ += size;
}

void StreamChannel::send_preprocess_response(const vector<u8>& client_id, const vector<u8>& buffer)
{
    // client_id is ignored

    // Type
    write_operation_type(SOP_preprocess);

    // Size of buffer
    size_t size = buffer.size();
    ostream_.write(reinterpret_cast<const char*>(&size), sizeof(size_t));

    // Actual buffer
    ostream_.write(reinterpret_cast<const char*>(buffer.data()), size);

    bytes_sent_ += sizeof(size_t);
    bytes_sent_ += size;
}

void StreamChannel::receive(SenderResponseQuery& response)
{
    SenderOperationType type = read_operation_type();

    if (type != SOP_query)
        throw runtime_error("Type should be query");

    // Package count
    istream_.read(reinterpret_cast<char*>(&response.package_count), sizeof(u64));
    bytes_received_ += sizeof(u64);
}

void StreamChannel::send_query(
    const RelinKeys& relin_keys,
    const map<u64, vector<SeededCiphertext>>& query,
    const seed128 relin_key_seeds)
{
    write_operation_type(SOP_query);

    string str;
    get_string(str, relin_keys);
    write_string(str);

    size_t size = query.size();
    ostream_.write(reinterpret_cast<const char*>(&size), sizeof(size_t));
    bytes_sent_ += sizeof(size_t);

    for (const auto& pair : query)
    {
        u64 power = pair.first;
        size = pair.second.size();

        ostream_.write(reinterpret_cast<const char*>(&power), sizeof(u64));
        ostream_.write(reinterpret_cast<const char*>(&size), sizeof(size_t));
        bytes_sent_ += sizeof(u64);
        bytes_sent_ += sizeof(size_t);

        for (const auto& seededcipher : pair.second)
        {
            u64 seed;
            seed = seededcipher.first.first;
            ostream_.write(reinterpret_cast<const char*>(&seed), sizeof(u64));
            seed = seededcipher.first.second;
            ostream_.write(reinterpret_cast<const char*>(&seed), sizeof(u64));
            bytes_sent_ += (sizeof(u64) * 2);

            get_string(str, seededcipher.second);
            write_string(str);
        }
    }

    u64 seed;
    seed = relin_key_seeds.first;
    ostream_.write(reinterpret_cast<const char*>(&seed), sizeof(u64));
    seed = relin_key_seeds.second;
    ostream_.write(reinterpret_cast<const char*>(&seed), sizeof(u64));
    bytes_sent_ += (sizeof(u64) * 2);
}

void StreamChannel::send_query_response(const vector<u8>& client_id, const size_t package_count)
{
    // client_id is ignored
    write_operation_type(SOP_query);

    ostream_.write(reinterpret_cast<const char*>(&package_count), sizeof(size_t));
    bytes_sent_ += sizeof(size_t);
}

void StreamChannel::receive(apsi::ResultPackage& pkg)
{
    unique_lock<mutex> rec_lock(*receive_mutex_);

    istream_.read(reinterpret_cast<char*>(&pkg.batch_idx), sizeof(int));
    istream_.read(reinterpret_cast<char*>(&pkg.split_idx), sizeof(int));
    
    read_string(pkg.data);
    read_string(pkg.label_data);

    bytes_received_ += (sizeof(int) * 2);
}

void StreamChannel::send(const vector<u8>& client_id, const ResultPackage& pkg)
{
    unique_lock<mutex> snd_lock(*send_mutex_);

    // client_id is ignored
    ostream_.write(reinterpret_cast<const char*>(&pkg.batch_idx), sizeof(int));
    ostream_.write(reinterpret_cast<const char*>(&pkg.split_idx), sizeof(int));

    write_string(pkg.data);
    write_string(pkg.label_data);

    bytes_sent_ += (sizeof(int) * 2);
}

void StreamChannel::write_operation_type(const SenderOperationType type)
{
    ostream_.write(reinterpret_cast<const char*>(&type), sizeof(SenderOperationType));
    bytes_sent_ += sizeof(SenderOperationType);
}

SenderOperationType StreamChannel::read_operation_type()
{
    SenderOperationType type;
    istream_.read(reinterpret_cast<char*>(&type), sizeof(SenderOperationType));
    bytes_received_ += sizeof(SenderOperationType);

    return type;
}


void StreamChannel::write_string(const std::string& str)
{
    size_t size = str.length();
    ostream_.write(reinterpret_cast<const char*>(&size), sizeof(size_t));
    ostream_.write(str.data(), size);

    bytes_sent_ += sizeof(size_t);
    bytes_sent_ += size;
}

void StreamChannel::read_string(std::string& str)
{
    size_t size;
    istream_.read(reinterpret_cast<char*>(&size), sizeof(size_t));

    str.resize(size);
    istream_.read(str.data(), size);

    bytes_received_ += sizeof(size_t);
    bytes_received_ += size;
}

shared_ptr<SenderOperation> StreamChannel::decode_get_parameters()
{
    // Nothing to decode
    return make_shared<SenderOperationGetParameters>();
}

shared_ptr<SenderOperation> StreamChannel::decode_preprocess()
{
    vector<u8> buffer;
    size_t size;
    istream_.read(reinterpret_cast<char*>(&size), sizeof(size_t));
    
    buffer.resize(size);
    istream_.read(reinterpret_cast<char*>(buffer.data()), size);

    return make_shared<SenderOperationPreprocess>(move(buffer));
}

shared_ptr<SenderOperation> StreamChannel::decode_query()
{
    string relin_keys;
    read_string(relin_keys);

    size_t qsize;
    istream_.read(reinterpret_cast<char*>(&qsize), sizeof(size_t));
    bytes_received_ += sizeof(size_t);

    map<u64, vector<pair<seed128, string>>> query;

    for (size_t qidx = 0; qidx < qsize; qidx++)
    {
        u64 power;
        size_t vecsize;

        istream_.read(reinterpret_cast<char*>(&power), sizeof(u64));
        istream_.read(reinterpret_cast<char*>(&vecsize), sizeof(size_t));
        bytes_received_ += sizeof(u64);
        bytes_received_ += sizeof(size_t);

        vector<pair<seed128, string>> power_entry(vecsize);

        for (size_t vecidx = 0; vecidx < vecsize; vecidx++)
        {
            seed128 seed;
            istream_.read(reinterpret_cast<char*>(&seed.first), sizeof(u64));
            istream_.read(reinterpret_cast<char*>(&seed.second), sizeof(u64));
            bytes_received_ += (sizeof(u64) * 2);

            string cipher;
            read_string(cipher);

            power_entry[vecidx] = make_pair(seed, cipher);
        }

        query[power] = power_entry;
    }

    seed128 relin_seeds;
    istream_.read(reinterpret_cast<char*>(&relin_seeds.first), sizeof(u64));
    istream_.read(reinterpret_cast<char*>(&relin_seeds.second), sizeof(u64));
    bytes_received_ += (sizeof(u64) * 2);

    return make_shared<SenderOperationQuery>(relin_keys, move(query), relin_seeds);
}
