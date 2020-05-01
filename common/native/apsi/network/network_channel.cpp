// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <sstream>
#include "apsi/result_package.h"
#include "apsi/network/network_channel.h"
#include "apsi/network/network_utils.h"

// ZeroMQ
#pragma warning(push, 0)
#include "zmqpp/zmqpp.hpp"
#pragma warning(pop)

using namespace std;
using namespace seal;
using namespace zmqpp;

namespace apsi
{
    namespace network
    {
        NetworkChannel::NetworkChannel()
            : end_point_(""),
            receive_mutex_(make_unique<mutex>()),
            send_mutex_(make_unique<mutex>()),
            context_(make_unique<context_t>())
        {
        }

        NetworkChannel::~NetworkChannel()
        {
            if (is_connected())
            {
                disconnect();
            }
        }

        void NetworkChannel::bind(const string& end_point)
        {
            throw_if_connected();

            end_point_ = end_point;
            get_socket()->bind(end_point);
        }

        void NetworkChannel::connect(const string& end_point)
        {
            throw_if_connected();

            end_point_ = end_point;
            get_socket()->connect(end_point);
        }

        void NetworkChannel::disconnect()
        {
            throw_if_not_connected();

            get_socket()->close();
            if (nullptr != context_)
            {
                context_->terminate();
            }

            end_point_ = "";
            socket_ = nullptr;
            context_ = nullptr;
        }

        void NetworkChannel::throw_if_not_connected() const
        {
            if (!is_connected())
                throw runtime_error("Socket is not connected yet.");
        }

        void NetworkChannel::throw_if_connected() const
        {
            if (is_connected())
                throw runtime_error("Socket is already connected");
        }

        bool NetworkChannel::receive(shared_ptr<SenderOperation>& sender_op, bool wait_for_message)
        {
            throw_if_not_connected();

            message_t msg;
            if (!receive_message(msg, wait_for_message))
            {
                // No message yet.
                return false;
            }

            // Should have ID and type.
            if (msg.parts() < 2)
                throw runtime_error("Not enough parts in message");

            SenderOperationType type = get_message_type(msg);

            switch (type)
            {
            case SOP_get_parameters:
                sender_op = decode_get_parameters(msg);
                break;

            case SOP_preprocess:
                sender_op = decode_preprocess(msg);
                break;

            case SOP_query:
                sender_op = decode_query(msg);
                break;

            default:
                throw runtime_error("Invalid Sender Operation type");
            }

            bytes_received_ += sizeof(SenderOperationType);

            return true;
        }

        bool NetworkChannel::receive(shared_ptr<SenderOperation>& sender_op)
        {
            return receive(sender_op, /* wait_for_message */ false);
        }

        bool NetworkChannel::receive(SenderResponseGetParameters& response)
        {
            throw_if_not_connected();

            message_t msg;
            receive_message(msg);

            // We should have at least 18 parts
            if (msg.parts() < 18)
                return false;

            // First part is message type
            SenderOperationType type = get_message_type(msg, /* part */ 0);

            if (type != SOP_get_parameters)
                return false;

            // Parameters start from second part
            size_t idx = 1;

            // PSIConfParams
            response.psiconf_params.sender_size = msg.get<u64>(idx++);
            response.psiconf_params.sender_bin_size = msg.get<u64>(idx++);
            response.psiconf_params.item_bit_count = msg.get<u32>(idx++);
            response.psiconf_params.item_bit_length_used_after_oprf = msg.get<u32>(idx++);
            response.psiconf_params.num_chunks = msg.get<u32>(idx++);
            response.psiconf_params.use_labels = msg.get<bool>(idx++);
            response.psiconf_params.use_fast_membership = msg.get<bool>(idx++);

            // TableParams
            response.table_params.log_table_size = msg.get<u32>(idx++);
            response.table_params.window_size = msg.get<u32>(idx++);
            response.table_params.split_count = msg.get<u32>(idx++);
            response.table_params.split_size = msg.get<u32>(idx++);
            response.table_params.binning_sec_level = msg.get<u32>(idx++);
            response.table_params.dynamic_split_count = msg.get<bool>(idx++);

            // CuckooParams
            response.cuckoo_params.hash_func_count = msg.get<u32>(idx++);
            response.cuckoo_params.hash_func_seed = msg.get<u32>(idx++);
            response.cuckoo_params.max_probe = msg.get<u32>(idx++);

            // SEALParams
            u64 poly_modulus_degree = msg.get<u64>(idx++);
            response.seal_params.encryption_params.set_poly_modulus_degree(static_cast<size_t>(poly_modulus_degree));

            vector<SmallModulus> coeff_modulus;
            get_sm_vector(coeff_modulus, msg, idx);
            response.seal_params.encryption_params.set_coeff_modulus(coeff_modulus);

            response.seal_params.encryption_params.set_plain_modulus(msg.get<u64>(idx++));
            response.seal_params.max_supported_degree = msg.get<u32>(idx++);

            // FFieldParams
            response.ffield_params.characteristic = msg.get<u64>(idx++);
            response.ffield_params.degree = msg.get<u32>(idx++);

            bytes_received_ += sizeof(SenderOperationType);
            bytes_received_ += sizeof(PSIParams::PSIConfParams);
            bytes_received_ += sizeof(PSIParams::TableParams);
            bytes_received_ += sizeof(PSIParams::CuckooParams);
            bytes_received_ += sizeof(u64) + sizeof(u64) + sizeof(u32);//sizeof(PSIParams::SEALParams);
            bytes_received_ += sizeof(PSIParams::FFieldParams);

            return true;
        }

        bool NetworkChannel::receive(SenderResponsePreprocess& response)
        {
            throw_if_not_connected();

            message_t msg;
            receive_message(msg);

            // We should have 3 parts
            if (msg.parts() != 3)
                return false;

            SenderOperationType type = get_message_type(msg, /* part */ 0);
            if (type != SOP_preprocess)
                return false;

            // Buffer starts at part 1
            get_buffer(response.buffer, msg, /* part_start */ 1);

            bytes_received_ += sizeof(SenderOperationType);
            bytes_received_ += response.buffer.size();

            return true;
        }


        bool NetworkChannel::receive(SenderResponseQuery& response)
        {
            throw_if_not_connected();

            message_t msg;
            receive_message(msg);

            // We should have at least 2 parts
            if (msg.parts() < 2)
                return false;

            SenderOperationType type = get_message_type(msg, /* part */ 0);
            if (type != SOP_query)
                return false;

            // Number of result packages
            response.package_count = msg.get<u64>(/* part */ 1);

            bytes_received_ += sizeof(u32); // SenderOperationType
            bytes_received_ += sizeof(u64);

            return true;
        }

        bool NetworkChannel::receive(ResultPackage& pkg)
        {
            throw_if_not_connected();

            message_t msg;
            receive_message(msg);

            if (msg.parts() != 4)
            {
                return false;;
            }

            pkg.split_idx = msg.get<i64>(/* part */ 0);
            pkg.batch_idx = msg.get<i64>(/* part */ 1);
            pkg.data = msg.get(/* part */ 2);
            pkg.label_data = msg.get(/* part */ 3);

            bytes_received_ += pkg.size();

            return true;
        }

        void NetworkChannel::send_get_parameters()
        {
            throw_if_not_connected();

            message_t msg;
            SenderOperationType type = SOP_get_parameters;
            add_message_type(type, msg);

            // that's it!
            send_message(msg);

            bytes_sent_ += sizeof(SenderOperationType);
        }

        void NetworkChannel::send_get_parameters_response(const vector<SEAL_BYTE>& client_id, const PSIParams& params)
        {
            throw_if_not_connected();

            message_t msg;

            SenderOperationType type = SOP_get_parameters;
            add_client_id(msg, client_id);
            add_message_type(type, msg);

            // PSIConfParams
            msg.add(params.sender_size());
            msg.add(params.sender_bin_size());
            msg.add(params.item_bit_count());
            msg.add(params.item_bit_length_used_after_oprf());
            msg.add(params.num_chunks());
            msg.add(params.use_labels());
            msg.add(params.use_fast_membership());

            // TableParams
            msg.add(params.log_table_size());
            msg.add(params.window_size());
            msg.add(params.split_count());
            msg.add(params.split_size());
            msg.add(params.binning_sec_level());
            msg.add(params.dynamic_split_count());

            // CuckooParams
            msg.add(params.hash_func_count());
            msg.add(params.hash_func_seed());
            msg.add(params.max_probe());

            // SEALParams
            u64 poly_modulus_degree = static_cast<u64>(params.encryption_params().poly_modulus_degree());
            msg.add(poly_modulus_degree);
            add_sm_vector(params.encryption_params().coeff_modulus(), msg);
            msg.add(params.encryption_params().plain_modulus().value());
            msg.add(params.max_supported_degree());

            // FFieldParams
            msg.add(params.ffield_characteristic());
            msg.add(params.ffield_degree());

            send_message(msg);

            bytes_sent_ += sizeof(u32); // SenderOperationType
            bytes_sent_ += sizeof(PSIParams::PSIConfParams);
            bytes_sent_ += sizeof(PSIParams::TableParams);
            bytes_sent_ += sizeof(PSIParams::CuckooParams);
            bytes_sent_ += sizeof(u64) + sizeof(u64) + sizeof(u32); //sizeof(PSIParams::SEALParams);
            bytes_sent_ += sizeof(PSIParams::FFieldParams);
        }

        void NetworkChannel::send_preprocess(const vector<SEAL_BYTE>& buffer)
        {
            throw_if_not_connected();

            message_t msg;
            SenderOperationType type = SOP_preprocess;

            add_message_type(type, msg);
            add_buffer(buffer, msg);

            send_message(msg);

            bytes_sent_ += sizeof(u32);
            bytes_sent_ += buffer.size();
        }

        void NetworkChannel::send_preprocess_response(const vector<SEAL_BYTE>& client_id, const vector<SEAL_BYTE>& buffer)
        {
            throw_if_not_connected();

            message_t msg;
            SenderOperationType type = SOP_preprocess;

            add_client_id(msg, client_id);
            add_message_type(type, msg);
            add_buffer(buffer, msg);

            send_message(msg);

            bytes_sent_ += sizeof(u32);
            bytes_sent_ += buffer.size();
        }

        void NetworkChannel::send_query(
            const string& relin_keys,
            const map<u64, vector<string>>& query)
        {
            throw_if_not_connected();

            size_t bytes_sent = 0;

            message_t msg;
            SenderOperationType type = SOP_query;
            add_message_type(type, msg);
            bytes_sent += sizeof(u32);

            msg.add(relin_keys);
            bytes_sent += relin_keys.length();

            logging::Log::debug("send_query: relin key length = %i bytes ", relin_keys.length());

            u64 query_size = static_cast<u64>(query.size());
            add_part(query_size, msg);
            bytes_sent += sizeof(u64);

            u64 sofar = bytes_sent_;

            for (const auto& q : query)
            {
                add_part(q.first, msg);
                bytes_sent += sizeof(u64);

                u64 num_elems = static_cast<u64>(q.second.size());
                add_part(num_elems, msg);
                bytes_sent += sizeof(u64);

                for (const auto& seededctxt : q.second)
                {
                    msg.add(seededctxt);
                    bytes_sent += seededctxt.length();
                }
            }

            logging::Log::debug("send_query: ciphertext lengths = %i bytes ", bytes_sent_ - sofar);

            send_message(msg);
            bytes_sent_ += bytes_sent;
        }

        void NetworkChannel::send_query_response(const vector<SEAL_BYTE>& client_id, const size_t package_count)
        {
            throw_if_not_connected();

            message_t msg;
            SenderOperationType type = SOP_query;
            add_client_id(msg, client_id);

            add_message_type(type, msg);
            u64 pkg_count = static_cast<u64>(package_count);
            msg.add(pkg_count);

            send_message(msg);

            // Message type
            bytes_sent_ += sizeof(u32);

            // Package count
            bytes_sent_ += sizeof(u64);
        }

        void NetworkChannel::send(const vector<SEAL_BYTE>& client_id, const ResultPackage& pkg)
        {
            throw_if_not_connected();

            message_t msg;

            add_client_id(msg, client_id);

            msg.add(pkg.split_idx);
            msg.add(pkg.batch_idx);
            msg.add(pkg.data);
            msg.add(pkg.label_data);

            send_message(msg);

            bytes_sent_ += pkg.size();
        }

        void NetworkChannel::get_buffer(vector<SEAL_BYTE>& buff, const message_t& msg, int part_start) const
        {
            // Need to have size
            if (msg.parts() < static_cast<size_t>(part_start) + 1)
                throw runtime_error("Should have size at least");

            u64 size;
            get_part(size, msg, /* part */ part_start);

            // If the vector is not empty, we need the part with the data
            if (size > 0 && msg.parts() < static_cast<size_t>(part_start) + 2)
                throw runtime_error("Should have size and data.");

            buff.resize(static_cast<size_t>(size));

            if (size > 0)
            {
                // Verify the actual data is the size we expect
                if (msg.size(/* part */ static_cast<size_t>(part_start) + 1) < size)
                    throw runtime_error("Second Part has less data than expected");

                memcpy(buff.data(), msg.raw_data(/* part */ static_cast<size_t>(part_start) + 1), static_cast<size_t>(size));
            }
        }

        void NetworkChannel::add_buffer(const vector<SEAL_BYTE>& buff, message_t& msg) const
        {
            // First part is size
            u64 size = static_cast<u64>(buff.size());
            add_part(size, msg);

            if (buff.size() > 0)
            {
                // Second part is raw data
                msg.add_raw(buff.data(), buff.size());
            }
        }

        void NetworkChannel::get_sm_vector(vector<SmallModulus>& smv, const message_t& msg, size_t& part_idx) const
        {
            // Need to have size
            if (msg.parts() < (part_idx + 1))
                throw runtime_error("Should have size at least");

            u64 size;
            get_part(size, msg, /* part */ part_idx++);

            if (msg.parts() < (part_idx + size))
                throw runtime_error("Insufficient parts for SmallModulus vector");

            smv.resize(static_cast<size_t>(size));
            for (size_t sm_idx = 0; sm_idx < size; sm_idx++)
            {
                string str = msg.get(part_idx++);
                get_small_modulus(smv[sm_idx], str);
            }
        }

        void NetworkChannel::add_sm_vector(const vector<SmallModulus>& smv, message_t& msg) const
        {
            // First part is size
            u64 size = static_cast<u64>(smv.size());
            add_part(size, msg);

            for (const SmallModulus& sm : smv)
            {
                // Add each element as a string
                string str;
                get_string(str, sm);
                msg.add(str);
            }
        }

        void NetworkChannel::add_message_type(const SenderOperationType type, message_t& msg) const
        {
            // Transform to int to have it have a fixed size
            add_part(static_cast<u32>(type), msg);
        }

        SenderOperationType NetworkChannel::get_message_type(const message_t& msg, const size_t part) const
        {
            // We should have at least the parts we want to get
            if (msg.parts() < (part + 1))
                throw invalid_argument("Message should have at least type");

            // Get message type
            u32 msg_type;
            get_part(msg_type, msg, /* part */ part);
            SenderOperationType type = static_cast<SenderOperationType>(msg_type);
            return type;
        }

        void NetworkChannel::extract_client_id(const message_t& msg, vector<SEAL_BYTE>& id) const
        {
            // ID should always be part 0
            size_t id_size = msg.size(/* part */ 0);
            id.resize(id_size);
            memcpy(id.data(), msg.raw_data(/* part */ 0), id_size);
        }

        void NetworkChannel::add_client_id(message_t& msg, const vector<SEAL_BYTE>& id) const
        {
            msg.add_raw(id.data(), id.size());
        }

        shared_ptr<SenderOperation> NetworkChannel::decode_get_parameters(const message_t& msg)
        {
            vector<SEAL_BYTE> client_id;
            extract_client_id(msg, client_id);

            // Nothing in the message to decode.
            return make_shared<SenderOperationGetParameters>(move(client_id));
        }

        shared_ptr<SenderOperation> NetworkChannel::decode_preprocess(const message_t& msg)
        {
            vector<SEAL_BYTE> client_id;
            extract_client_id(msg, client_id);

            vector<SEAL_BYTE> buffer;
            get_buffer(buffer, msg, /* part_start */ 2);

            bytes_received_ += buffer.size();

            return make_shared<SenderOperationPreprocess>(move(client_id), move(buffer));
        }

        shared_ptr<SenderOperation> NetworkChannel::decode_query(const message_t& msg)
        {
            vector<SEAL_BYTE> client_id;
            extract_client_id(msg, client_id);

            string relin_keys;
            map<u64, vector<string>> query;

            size_t msg_idx = 2;

            msg.get(relin_keys, /* part */  msg_idx++);
            bytes_received_ += relin_keys.length();

            u64 query_count;
            get_part(query_count, msg, /* part */  msg_idx++);
            bytes_received_ += sizeof(u64);

            for (u64 i = 0; i < query_count; i++)
            {
                u64 power;
                get_part(power, msg, msg_idx++);
                bytes_received_ += sizeof(u64);

                u64 num_elems;
                get_part(num_elems, msg, msg_idx++);
                bytes_received_ += sizeof(u64);

                vector<string> powers(static_cast<size_t>(num_elems));

                for (size_t j = 0; j < num_elems; j++)
                {
                    msg.get(powers[j], msg_idx++);
                    bytes_received_ += powers[j].length();
                }

                query.insert_or_assign(power, powers);
            }

            return make_shared<SenderOperationQuery>(move(client_id), relin_keys, move(query));
        }

        bool NetworkChannel::receive_message(message_t& msg, bool wait_for_message)
        {
            unique_lock<mutex> rec_lock(*receive_mutex_);
            bool received = get_socket()->receive(msg, !wait_for_message);

            if (!received && wait_for_message)
                throw runtime_error("Failed to receive message");

            return received;
        }

        void NetworkChannel::send_message(message_t& msg)
        {
            unique_lock<mutex> snd_lock(*send_mutex_);
            bool sent = get_socket()->send(msg);

            if (!sent)
                throw runtime_error("Failed to send message");
        }

        template<typename T>
        typename enable_if<is_pod<T>::value, void>::type
        NetworkChannel::get_part(T& data, const message_t& msg, const size_t part) const
        {
            const T* presult;
            msg.get(&presult, part);
            memcpy(&data, presult, sizeof(T));
        }

        template<typename T>
        typename enable_if<is_pod<T>::value, void>::type
        NetworkChannel::add_part(const T& data, message_t& msg) const
        {
            msg.add_raw(&data, sizeof(T));
        }

        unique_ptr<socket_t>& NetworkChannel::get_socket()
        {
            if (nullptr == socket_)
            {
                socket_ = make_unique<socket_t>(*context_.get(), get_socket_type());
                set_socket_options(socket_.get());
            }

            return socket_;
        }
    } // namespace network
} // namespace apsi