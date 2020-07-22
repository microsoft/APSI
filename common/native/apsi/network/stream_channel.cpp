// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "stream_channel.h"
#include "network_utils.h"

using namespace std;
using namespace seal;

namespace apsi
{
    namespace network
    {
        StreamChannel::StreamChannel(istream &istream, ostream &ostream)
            : istream_(istream), ostream_(ostream), receive_mutex_(make_unique<mutex>()),
              send_mutex_(make_unique<mutex>())
        {}

        StreamChannel::~StreamChannel()
        {}

        bool StreamChannel::receive(shared_ptr<SenderOperation> &sender_op)
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

        bool StreamChannel::receive(SenderResponseGetParameters &response)
        {
            // First part is message type
            SenderOperationType senderOpType = read_operation_type();

            if (senderOpType != SOP_get_parameters)
                return false;

            // PSIConfParams
            istream_.read(reinterpret_cast<char *>(&response.psiconf_params), sizeof(PSIParams::PSIConfParams));

            // TableParams
            istream_.read(reinterpret_cast<char *>(&response.table_params), sizeof(PSIParams::TableParams));

            // CuckooParams
            istream_.read(reinterpret_cast<char *>(&response.cuckoo_params), sizeof(PSIParams::CuckooParams));

            // SEALParams
            response.seal_params.encryption_params.load(istream_);
            istream_.read(reinterpret_cast<char *>(&response.seal_params.max_supported_degree), sizeof(uint32_t));

            // FFieldParams
            istream_.read(reinterpret_cast<char *>(&response.ffield_params), sizeof(PSIParams::FFieldParams));

            bytes_received_ += sizeof(PSIParams::PSIConfParams);
            bytes_received_ += sizeof(PSIParams::TableParams);
            bytes_received_ += sizeof(PSIParams::CuckooParams);
            bytes_received_ += sizeof(PSIParams::SEALParams);
            bytes_received_ += sizeof(PSIParams::FFieldParams);

            return true;
        }

        void StreamChannel::send_get_parameters()
        {
            // We only need the type.
            write_operation_type(SOP_get_parameters);
        }

        void StreamChannel::send_get_parameters_response(const vector<SEAL_BYTE> &client_id, const PSIParams &params)
        {
            // client_id is unused for StreamChannel.
            write_operation_type(SOP_get_parameters);

            // PSIConfParams
            const PSIParams::PSIConfParams &psiconfparams = params.psiconf_params();
            ostream_.write(reinterpret_cast<const char *>(&psiconfparams), sizeof(PSIParams::PSIConfParams));

            // TableParams
            const PSIParams::TableParams &tableparams = params.table_params();
            ostream_.write(reinterpret_cast<const char *>(&tableparams), sizeof(PSIParams::TableParams));

            // CuckooParams
            const PSIParams::CuckooParams &cuckooparams = params.cuckoo_params();
            ostream_.write(reinterpret_cast<const char *>(&cuckooparams), sizeof(PSIParams::CuckooParams));

            // SEALParams
            uint32_t maxsd = params.max_supported_degree();
            params.seal_params().encryption_params.save(ostream_);
            ostream_.write(reinterpret_cast<const char *>(&maxsd), sizeof(uint32_t));

            // FFieldParams
            const PSIParams::FFieldParams &ffieldparams = params.ffield_params();
            ostream_.write(reinterpret_cast<const char *>(&ffieldparams), sizeof(PSIParams::FFieldParams));

            bytes_sent_ += sizeof(PSIParams::PSIConfParams);
            bytes_sent_ += sizeof(PSIParams::TableParams);
            bytes_sent_ += sizeof(PSIParams::CuckooParams);
            bytes_sent_ += sizeof(PSIParams::SEALParams);
            bytes_sent_ += sizeof(PSIParams::FFieldParams);
        }

        bool StreamChannel::receive(SenderResponsePreprocess &response)
        {
            // First part is message type
            SenderOperationType type = read_operation_type();

            if (type != SOP_preprocess)
                return false;

            // Size of buffer
            streamsize size;
            istream_.read(reinterpret_cast<char *>(&size), sizeof(streamsize));

            // Actual buffer
            response.buffer.resize(static_cast<size_t>(size));
            istream_.read(reinterpret_cast<char *>(response.buffer.data()), size);

            bytes_received_ += sizeof(streamsize);
            bytes_received_ += static_cast<uint64_t>(size);

            return true;
        }

        void StreamChannel::send_preprocess(const vector<SEAL_BYTE> &buffer)
        {
            // Type
            write_operation_type(SOP_preprocess);

            // Size of buffer
            streamsize size = static_cast<streamsize>(buffer.size());
            ostream_.write(reinterpret_cast<const char *>(&size), sizeof(streamsize));

            // Actual buffer
            ostream_.write(reinterpret_cast<const char *>(buffer.data()), size);

            bytes_sent_ += sizeof(streamsize);
            bytes_sent_ += static_cast<uint64_t>(size);
        }

        void StreamChannel::send_preprocess_response(
            const vector<SEAL_BYTE> &client_id, const vector<SEAL_BYTE> &buffer)
        {
            // client_id is ignored

            // Type
            write_operation_type(SOP_preprocess);

            // Size of buffer
            streamsize size = static_cast<streamsize>(buffer.size());
            ostream_.write(reinterpret_cast<const char *>(&size), sizeof(streamsize));

            // Actual buffer
            ostream_.write(reinterpret_cast<const char *>(buffer.data()), size);

            bytes_sent_ += sizeof(streamsize);
            bytes_sent_ += static_cast<uint64_t>(size);
        }

        bool StreamChannel::receive(SenderResponseQuery &response)
        {
            SenderOperationType type = read_operation_type();

            if (type != SOP_query)
                return false;

            // Package count
            istream_.read(reinterpret_cast<char *>(&response.package_count), sizeof(uint64_t));
            bytes_received_ += sizeof(uint64_t);

            return true;
        }

        void StreamChannel::send_query(const string &relin_keys, const map<uint64_t, vector<string>> &query)
        {
            write_operation_type(SOP_query);

            write_string(relin_keys);

            uint64_t size = query.size();
            ostream_.write(reinterpret_cast<const char *>(&size), sizeof(uint64_t));
            bytes_sent_ += sizeof(uint64_t);

            for (const auto &q : query)
            {
                uint64_t power = q.first;
                size = q.second.size();

                ostream_.write(reinterpret_cast<const char *>(&power), sizeof(uint64_t));
                bytes_sent_ += sizeof(uint64_t);

                ostream_.write(reinterpret_cast<const char *>(&size), sizeof(uint64_t));
                bytes_sent_ += sizeof(uint64_t);

                for (const auto &seededcipher : q.second)
                {
                    write_string(seededcipher);
                }
            }
        }

        void StreamChannel::send_query_response(const vector<SEAL_BYTE> &client_id, const size_t package_count)
        {
            // client_id is ignored
            write_operation_type(SOP_query);

            uint64_t pkg_count = static_cast<uint64_t>(package_count);
            ostream_.write(reinterpret_cast<const char *>(&pkg_count), sizeof(uint64_t));
            bytes_sent_ += sizeof(uint64_t);
        }

        bool StreamChannel::receive(apsi::ResultPackage &pkg)
        {
            unique_lock<mutex> rec_lock(*receive_mutex_);

            istream_.read(reinterpret_cast<char *>(&pkg.bundle_idx), sizeof(int64_t));

            read_string(pkg.data);
            read_string(pkg.label_data);

            bytes_received_ += (sizeof(int64_t) * 2);

            return true;
        }

        void StreamChannel::send(const vector<SEAL_BYTE> &client_id, const ResultPackage &pkg)
        {
            unique_lock<mutex> snd_lock(*send_mutex_);

            // client_id is ignored
            ostream_.write(reinterpret_cast<const char *>(&pkg.bundle_idx), sizeof(int64_t));

            write_string(pkg.data);
            write_string(pkg.label_data);

            bytes_sent_ += (sizeof(int64_t) * 2);
        }

        void StreamChannel::write_operation_type(const SenderOperationType type)
        {
            uint32_t sotype = static_cast<uint32_t>(type);
            ostream_.write(reinterpret_cast<const char *>(&sotype), sizeof(uint32_t));
            bytes_sent_ += sizeof(uint32_t);
        }

        SenderOperationType StreamChannel::read_operation_type()
        {
            uint32_t type;
            istream_.read(reinterpret_cast<char *>(&type), sizeof(uint32_t));
            bytes_received_ += sizeof(uint32_t);

            return static_cast<SenderOperationType>(type);
        }

        void StreamChannel::write_string(const string &str)
        {
            streamsize size = static_cast<streamsize>(str.length());
            ostream_.write(reinterpret_cast<const char *>(&size), sizeof(streamsize));
            ostream_.write(str.data(), size);

            bytes_sent_ += sizeof(streamsize);
            bytes_sent_ += static_cast<uint64_t>(size);
        }

        void StreamChannel::read_string(string &str)
        {
            streamsize size;
            istream_.read(reinterpret_cast<char *>(&size), sizeof(streamsize));

            str.resize(static_cast<size_t>(size));
            istream_.read(&str[0], size);

            bytes_received_ += sizeof(streamsize);
            bytes_received_ += static_cast<uint64_t>(size);
        }

        shared_ptr<SenderOperation> StreamChannel::decode_get_parameters()
        {
            // Nothing to decode
            return make_shared<SenderOperationGetParameters>();
        }

        shared_ptr<SenderOperation> StreamChannel::decode_preprocess()
        {
            vector<SEAL_BYTE> buffer;
            streamsize size;
            istream_.read(reinterpret_cast<char *>(&size), sizeof(streamsize));

            buffer.resize(static_cast<size_t>(size));
            istream_.read(reinterpret_cast<char *>(buffer.data()), size);

            return make_shared<SenderOperationPreprocess>(move(buffer));
        }

        shared_ptr<SenderOperation> StreamChannel::decode_query()
        {
            string relin_keys;
            read_string(relin_keys);

            uint64_t qsize;
            istream_.read(reinterpret_cast<char *>(&qsize), sizeof(uint64_t));
            bytes_received_ += sizeof(uint64_t);

            map<uint64_t, vector<string>> query;

            for (uint64_t qidx = 0; qidx < qsize; qidx++)
            {
                uint64_t power;
                uint64_t vecsize;

                istream_.read(reinterpret_cast<char *>(&power), sizeof(uint64_t));
                istream_.read(reinterpret_cast<char *>(&vecsize), sizeof(uint64_t));
                bytes_received_ += (sizeof(uint64_t) * 2);

                vector<string> power_entry;
                power_entry.reserve(static_cast<size_t>(vecsize));

                for (uint64_t vecidx = 0; vecidx < vecsize; vecidx++)
                {
                    string cipher;
                    read_string(cipher);
                    power_entry.emplace_back(move(cipher));
                }

                query[power] = power_entry;
            }

            return make_shared<SenderOperationQuery>(relin_keys, move(query));
        }
    } // namespace network
} // namespace apsi
