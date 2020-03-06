// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

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

bool StreamChannel::receive(SenderResponseGetParameters& response)
{
    // First part is message type
    SenderOperationType senderOpType = read_operation_type();

    if (senderOpType != SOP_get_parameters)
        return false;

    // PSIConfParams
    istream_.read(reinterpret_cast<char*>(&response.psiconf_params), sizeof(PSIParams::PSIConfParams));

    // TableParams
    istream_.read(reinterpret_cast<char*>(&response.table_params), sizeof(PSIParams::TableParams));

    // CuckooParams
    istream_.read(reinterpret_cast<char*>(&response.cuckoo_params), sizeof(PSIParams::CuckooParams));

    // SEALParams
    response.seal_params.encryption_params.load(istream_);
    istream_.read(reinterpret_cast<char*>(&response.seal_params.max_supported_degree), sizeof(u32));

    // ExFieldParams
    istream_.read(reinterpret_cast<char*>(&response.exfield_params), sizeof(PSIParams::ExFieldParams));

    bytes_received_ += sizeof(PSIParams::PSIConfParams);
    bytes_received_ += sizeof(PSIParams::TableParams);
    bytes_received_ += sizeof(PSIParams::CuckooParams);
    bytes_received_ += sizeof(PSIParams::SEALParams);
    bytes_received_ += sizeof(PSIParams::ExFieldParams);

    return true;
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
    u32 maxsd = params.max_supported_degree();
    params.get_seal_params().encryption_params.save(ostream_);
    ostream_.write(reinterpret_cast<const char*>(&maxsd), sizeof(u32));

    // ExFieldParams
    const PSIParams::ExFieldParams& exfieldparams = params.get_exfield_params();
    ostream_.write(reinterpret_cast<const char*>(&exfieldparams), sizeof(PSIParams::ExFieldParams));

    bytes_sent_ += sizeof(PSIParams::PSIConfParams);
    bytes_sent_ += sizeof(PSIParams::TableParams);
    bytes_sent_ += sizeof(PSIParams::CuckooParams);
    bytes_sent_ += sizeof(PSIParams::SEALParams);
    bytes_sent_ += sizeof(PSIParams::ExFieldParams);
}

bool StreamChannel::receive(SenderResponsePreprocess& response)
{
    // First part is message type
    SenderOperationType type = read_operation_type();

    if (type != SOP_preprocess)
        return false;

    // Size of buffer
    u64 size;
    istream_.read(reinterpret_cast<char*>(&size), sizeof(u64));

    // Actual buffer
    response.buffer.resize(static_cast<size_t>(size));
    istream_.read(reinterpret_cast<char*>(response.buffer.data()), size);

    bytes_received_ += sizeof(u64);
    bytes_received_ += size;

    return true;
}

void StreamChannel::send_preprocess(const vector<u8>& buffer)
{
    // Type
    write_operation_type(SOP_preprocess);

    // Size of buffer
    u64 size = static_cast<u64>(buffer.size());
    ostream_.write(reinterpret_cast<const char*>(&size), sizeof(u64));

    // Actual buffer
    ostream_.write(reinterpret_cast<const char*>(buffer.data()), size);

    bytes_sent_ += sizeof(u64);
    bytes_sent_ += size;
}

void StreamChannel::send_preprocess_response(const vector<u8>& client_id, const vector<u8>& buffer)
{
    // client_id is ignored

    // Type
    write_operation_type(SOP_preprocess);

    // Size of buffer
    u64 size = static_cast<u64>(buffer.size());
    ostream_.write(reinterpret_cast<const char*>(&size), sizeof(u64));

    // Actual buffer
    ostream_.write(reinterpret_cast<const char*>(buffer.data()), size);

    bytes_sent_ += sizeof(u64);
    bytes_sent_ += size;
}

bool StreamChannel::receive(SenderResponseQuery& response)
{
    SenderOperationType type = read_operation_type();

    if (type != SOP_query)
        return false;

    // Package count
    istream_.read(reinterpret_cast<char*>(&response.package_count), sizeof(u64));
    bytes_received_ += sizeof(u64);

    return true;
}

void StreamChannel::send_query(
    const string& relin_keys,
    const map<u64, vector<string>>& query)
{
    write_operation_type(SOP_query);

    write_string(relin_keys);

    u64 size = query.size();
    ostream_.write(reinterpret_cast<const char*>(&size), sizeof(u64));
    bytes_sent_ += sizeof(u64);

    for (const auto& q : query)
    {
        u64 power = q.first;
        size = q.second.size();

        ostream_.write(reinterpret_cast<const char*>(&power), sizeof(u64));
        bytes_sent_ += sizeof(u64);

        ostream_.write(reinterpret_cast<const char*>(&size), sizeof(u64));
        bytes_sent_ += sizeof(u64);

        for (const auto& seededcipher : q.second)
        {
            write_string(seededcipher);
        }
    }
}

void StreamChannel::send_query_response(const vector<u8>& client_id, const size_t package_count)
{
    // client_id is ignored
    write_operation_type(SOP_query);

    u64 pkg_count = static_cast<u64>(package_count);
    ostream_.write(reinterpret_cast<const char*>(&pkg_count), sizeof(u64));
    bytes_sent_ += sizeof(u64);
}

bool StreamChannel::receive(apsi::ResultPackage& pkg)
{
    unique_lock<mutex> rec_lock(*receive_mutex_);

    istream_.read(reinterpret_cast<char*>(&pkg.batch_idx), sizeof(i64));
    istream_.read(reinterpret_cast<char*>(&pkg.split_idx), sizeof(i64));
    
    read_string(pkg.data);
    read_string(pkg.label_data);

    bytes_received_ += (sizeof(i64) * 2);

    return true;
}

void StreamChannel::send(const vector<u8>& client_id, const ResultPackage& pkg)
{
    unique_lock<mutex> snd_lock(*send_mutex_);

    // client_id is ignored
    ostream_.write(reinterpret_cast<const char*>(&pkg.batch_idx), sizeof(i64));
    ostream_.write(reinterpret_cast<const char*>(&pkg.split_idx), sizeof(i64));

    write_string(pkg.data);
    write_string(pkg.label_data);

    bytes_sent_ += (sizeof(i64) * 2);
}

void StreamChannel::write_operation_type(const SenderOperationType type)
{
    u32 sotype = static_cast<u32>(type);
    ostream_.write(reinterpret_cast<const char*>(&sotype), sizeof(u32));
    bytes_sent_ += sizeof(u32);
}

SenderOperationType StreamChannel::read_operation_type()
{
    u32 type;
    istream_.read(reinterpret_cast<char*>(&type), sizeof(u32));
    bytes_received_ += sizeof(u32);

    return static_cast<SenderOperationType>(type);
}

void StreamChannel::write_string(const std::string& str)
{
    u64 size = static_cast<u64>(str.length());
    ostream_.write(reinterpret_cast<const char*>(&size), sizeof(u64));
    ostream_.write(str.data(), size);

    bytes_sent_ += sizeof(u64);
    bytes_sent_ += size;
}

void StreamChannel::read_string(std::string& str)
{
    u64 size;
    istream_.read(reinterpret_cast<char*>(&size), sizeof(u64));

    str.resize(static_cast<size_t>(size));
    istream_.read(&str[0], size);

    bytes_received_ += sizeof(u64);
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
    u64 size;
    istream_.read(reinterpret_cast<char*>(&size), sizeof(u64));
    
    buffer.resize(static_cast<size_t>(size));
    istream_.read(reinterpret_cast<char*>(buffer.data()), size);

    return make_shared<SenderOperationPreprocess>(move(buffer));
}

shared_ptr<SenderOperation> StreamChannel::decode_query()
{
    string relin_keys;
    read_string(relin_keys);

    u64 qsize;
    istream_.read(reinterpret_cast<char*>(&qsize), sizeof(u64));
    bytes_received_ += sizeof(u64);

    map<u64, vector<string>> query;

    for (u64 qidx = 0; qidx < qsize; qidx++)
    {
        u64 power;
        u64 vecsize;

        istream_.read(reinterpret_cast<char*>(&power), sizeof(u64));
        istream_.read(reinterpret_cast<char*>(&vecsize), sizeof(u64));
        bytes_received_ += (sizeof(u64) * 2);

        vector<string> power_entry;
        power_entry.reserve(static_cast<size_t>(vecsize));

        for (u64 vecidx = 0; vecidx < vecsize; vecidx++)
        {
            string cipher;
            read_string(cipher);
            power_entry.emplace_back(move(cipher));
        }

        query[power] = power_entry;
    }

    return make_shared<SenderOperationQuery>(relin_keys, move(query));
}
