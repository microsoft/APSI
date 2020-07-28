// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <utility>
#include <cstddef>

// APSI
#include "apsi/network/stream_channel.h"
#include "apsi/network/network_utils.h"

// SEAL
#include <seal/util/common.h>

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    namespace network
    {
        bool StreamChannel::receive(shared_ptr<SenderOperation> &sender_op)
        {
            lock_guard<mutex> lock(receive_mutex_);

            // Get the SOP type
            SenderOperationType type = read_sop_type();

            bool ret = false;
            switch (type)
            {
            case SenderOperationType::SOP_PARMS:
                sender_op = decode_parms_request();
                ret = true;
                break;

            case SenderOperationType::SOP_OPRF:
                sender_op = decode_oprf_request();
                ret = true;
                break;

            case SenderOperationType::SOP_QUERY:
                sender_op = decode_query_request();
                ret = true;
                break;
            }

            return ret;
        }

        bool StreamChannel::receive(SenderResponseParms &response)
        {
            lock_guard<mutex> lock(receive_mutex_);

            // Get the SOP type; this should be SOP_PARMS
            SenderOperationType type = read_sop_type();

            if (type != SenderOperationType::SOP_PARMS)
            {
                // Expected SOP_PARMS; something is wrong
                return false;
            }

            // PSIConfParams
            in_.read(reinterpret_cast<char *>(&response.psiconf_params), sizeof(PSIParams::PSIConfParams));
            bytes_received_ += sizeof(PSIParams::PSIConfParams);

            // TableParams
            in_.read(reinterpret_cast<char *>(&response.table_params), sizeof(PSIParams::TableParams));
            bytes_received_ += sizeof(PSIParams::TableParams);

            // CuckooParams
            in_.read(reinterpret_cast<char *>(&response.cuckoo_params), sizeof(PSIParams::CuckooParams));
            bytes_received_ += sizeof(PSIParams::CuckooParams);

            // SEALParams
            bytes_received_ += static_cast<uint64_t>(response.seal_params.encryption_params.load(in_));

            return true;
        }

        void StreamChannel::send_parms_request()
        {
            lock_guard<mutex> lock(send_mutex_);

            // Only need to write the operation type for a parameter request
            write_sop_type(SenderOperationType::SOP_PARMS);
        }

        void StreamChannel::send_parms_response(const vector<SEAL_BYTE> &client_id, const PSIParams &params)
        {
            lock_guard<mutex> lock(send_mutex_);

            // client_id is unused for StreamChannel

            write_sop_type(SenderOperationType::SOP_PARMS);

            // PSIConfParams
            const PSIParams::PSIConfParams &psiconf_params = params.psiconf_params();
            out_.write(reinterpret_cast<const char *>(&psiconf_params), sizeof(PSIParams::PSIConfParams));
            bytes_sent_ += sizeof(PSIParams::PSIConfParams);

            // TableParams
            const PSIParams::TableParams &table_params = params.table_params();
            out_.write(reinterpret_cast<const char *>(&table_params), sizeof(PSIParams::TableParams));
            bytes_sent_ += sizeof(PSIParams::TableParams);

            // CuckooParams
            const PSIParams::CuckooParams &cuckoo_params = params.cuckoo_params();
            out_.write(reinterpret_cast<const char *>(&cuckoo_params), sizeof(PSIParams::CuckooParams));
            bytes_sent_ += sizeof(PSIParams::CuckooParams);

            // SEALParams
            bytes_sent_ += static_cast<uint64_t>(
                params.seal_params().encryption_params.save(out_, compr_mode_type::deflate));
        }

        bool StreamChannel::receive(SenderResponseOPRF &response)
        {
            lock_guard<mutex> lock(receive_mutex_);

            // Get the SOP type; this should be SOP_OPRF
            SenderOperationType type = read_sop_type();

            if (type != SenderOperationType::SOP_OPRF)
            {
                // Expected SOP_OPRF; something is wrong
                return false;
            }

            // Read size of data 
            uint64_t size;
            in_.read(reinterpret_cast<char *>(&size), sizeof(uint64_t));
            bytes_received_ += sizeof(uint64_t);

            // Read the data itself
            response.data.resize(size);
            in_.read(reinterpret_cast<char *>(response.data.data()), safe_cast<streamsize>(size));
            bytes_received_ += size;

            return true;
        }

        void StreamChannel::send_oprf_request(const vector<SEAL_BYTE> &data)
        {
            lock_guard<mutex> lock(send_mutex_);

            write_sop_type(SenderOperationType::SOP_OPRF);

            // Write size of data
            uint64_t size = data.size();
            out_.write(reinterpret_cast<const char *>(&size), sizeof(uint64_t));
            bytes_sent_ += sizeof(uint64_t);

            // Write the data itself
            out_.write(reinterpret_cast<const char *>(data.data()), safe_cast<streamsize>(size));
            bytes_sent_ += size;
        }

        void StreamChannel::send_oprf_response(
            const vector<SEAL_BYTE> &client_id, const vector<SEAL_BYTE> &data)
        {
            lock_guard<mutex> lock(send_mutex_);

            // client_id is unused for StreamChannel

            write_sop_type(SenderOperationType::SOP_OPRF);

            // Size of buffer
            uint64_t size = data.size();
            out_.write(reinterpret_cast<const char *>(&size), sizeof(uint64_t));
            bytes_sent_ += sizeof(uint64_t);

            // Actual buffer
            out_.write(reinterpret_cast<const char *>(data.data()), safe_cast<streamsize>(size));
            bytes_sent_ += static_cast<uint64_t>(size);
        }

        bool StreamChannel::receive(SenderResponseQuery &response)
        {
            lock_guard<mutex> lock(receive_mutex_);

            // Get the SOP type; this should be SOP_QUERY
            SenderOperationType type = read_sop_type();

            if (type != SenderOperationType::SOP_QUERY)
            {
                // Expected SOP_QUERY; something is wrong
                return false;
            }

            // The only data in this is the package count
            in_.read(reinterpret_cast<char *>(&response.package_count), sizeof(uint64_t));
            bytes_received_ += sizeof(uint64_t);

            return true;
        }

        void StreamChannel::send_query_request(
            const string &relin_keys, const map<uint64_t, vector<string>> &query)
        {
            lock_guard<mutex> lock(send_mutex_);

            write_sop_type(SenderOperationType::SOP_QUERY);

            // Write the relinearization keys
            write_string(relin_keys);

            // Write the size of the query: this is the number of powers of the query
            // ciphertext to be sent
            uint64_t size = query.size();
            out_.write(reinterpret_cast<const char *>(&size), sizeof(uint64_t));
            bytes_sent_ += sizeof(uint64_t);

            for (const auto &q : query)
            {
                uint64_t power = q.first;
                size = q.second.size();

                // Write the query power (exponent)
                out_.write(reinterpret_cast<const char *>(&power), sizeof(uint64_t));
                bytes_sent_ += sizeof(uint64_t);

                // Write the number of ciphertexts we have; this is the number of bin
                // bundle indices
                out_.write(reinterpret_cast<const char *>(&size), sizeof(uint64_t));
                bytes_sent_ += sizeof(uint64_t);

                for (const auto &cipher : q.second)
                {
                    // Write the ciphertexts
                    write_string(cipher);
                }
            }
        }

        void StreamChannel::send_query_response(const vector<SEAL_BYTE> &client_id, size_t package_count)
        {
            lock_guard<mutex> lock(send_mutex_);

            // client_id is unused for StreamChannel

            write_sop_type(SenderOperationType::SOP_QUERY);

            uint64_t pkg_count = static_cast<uint64_t>(package_count);
            out_.write(reinterpret_cast<const char *>(&pkg_count), sizeof(uint64_t));
            bytes_sent_ += sizeof(uint64_t);
        }

        bool StreamChannel::receive(apsi::ResultPackage &pkg)
        {
            lock_guard<mutex> lock(receive_mutex_);

            uint32_t bundle_idx = 0;
            in_.read(reinterpret_cast<char *>(&bundle_idx), sizeof(uint32_t));
            bytes_received_ += sizeof(uint32_t);
            pkg.bundle_idx = safe_cast<size_t>(bundle_idx);

            read_string(pkg.data);
            read_string(pkg.label_data);

            return true;
        }

        void StreamChannel::send_result_package(const vector<SEAL_BYTE> &client_id, const ResultPackage &pkg)
        {
            lock_guard<mutex> lock(send_mutex_);

            // client_id is unused for StreamChannel

            uint32_t bundle_idx = safe_cast<uint32_t>(pkg.bundle_idx);
            out_.write(reinterpret_cast<const char *>(&bundle_idx), sizeof(uint32_t));
            bytes_sent_ += sizeof(uint32_t);

            write_string(pkg.data);
            write_string(pkg.label_data);
        }

        void StreamChannel::write_sop_type(SenderOperationType type)
        {
            out_.write(reinterpret_cast<const char *>(&type), sizeof(uint32_t));
            bytes_sent_ += sizeof(uint32_t);
        }

        SenderOperationType StreamChannel::read_sop_type()
        {
            SenderOperationType type;
            in_.read(reinterpret_cast<char *>(&type), sizeof(SenderOperationType));
            bytes_received_ += sizeof(SenderOperationType);

            return type;
        }

        void StreamChannel::write_string(const string &str)
        {
            uint64_t size = str.length();
            out_.write(reinterpret_cast<const char *>(&size), sizeof(uint64_t));
            bytes_sent_ += sizeof(uint64_t);

            out_.write(str.data(), safe_cast<streamsize>(size));
            bytes_sent_ += size;
        }

        void StreamChannel::read_string(string &str)
        {
            uint64_t size;
            in_.read(reinterpret_cast<char *>(&size), sizeof(uint64_t));
            bytes_received_ += sizeof(uint64_t);

            str.resize(static_cast<size_t>(size));
            in_.read(str.data(), safe_cast<streamsize>(size));
            bytes_received_ += size;
        }

        shared_ptr<SenderOperation> StreamChannel::decode_parms_request()
        {
            // Nothing to decode; return a SenderOperation of the correct type.
            return make_shared<SenderOperationParms>();
        }

        shared_ptr<SenderOperation> StreamChannel::decode_oprf_request()
        {
            vector<SEAL_BYTE> data;
            uint64_t size;
            in_.read(reinterpret_cast<char *>(&size), sizeof(uint64_t));
            data.resize(size);
            in_.read(reinterpret_cast<char *>(data.data()), safe_cast<streamsize>(size));

            return make_shared<SenderOperationOPRF>(move(data));
        }

        shared_ptr<SenderOperation> StreamChannel::decode_query_request()
        {
            // First read the relinearization keys
            string relin_keys;
            read_string(relin_keys);

            // Next read the number of powers sent in the query
            uint64_t q_size;
            in_.read(reinterpret_cast<char *>(&q_size), sizeof(uint64_t));
            bytes_received_ += sizeof(uint64_t);

            map<uint64_t, vector<string>> data;

            for (uint64_t q_idx = 0; q_idx < q_size; q_idx++)
            {
                // Which power of the query is this?
                uint64_t power;
                in_.read(reinterpret_cast<char *>(&power), sizeof(uint64_t));
                bytes_received_ += sizeof(uint64_t);

                // Read the vector size for this power; these should all be there same and
                // represent the number of bundle indices.
                uint64_t vec_size;
                in_.read(reinterpret_cast<char *>(&vec_size), sizeof(uint64_t));
                bytes_received_ += sizeof(uint64_t);

                // Read all ciphertexts for this power
                vector<string> query_power;
                query_power.reserve(safe_cast<size_t>(vec_size));
                for (uint64_t vec_idx = 0; vec_idx < vec_size; vec_idx++)
                {
                    string cipher;
                    read_string(cipher);
                    query_power.emplace_back(move(cipher));
                }

                // Write the ciphertexts for this power into the map
                data[power] = move(query_power);
            }

            return make_shared<SenderOperationQuery>(move(relin_keys), move(data));
        }
    } // namespace network
} // namespace apsi
