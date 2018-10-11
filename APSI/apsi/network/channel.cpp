
// STD
#include <sstream>
#include <mutex>

// APSI
#include "apsi/result_package.h"
#include "apsi/network/channel.h"
#include "apsi/network/network_utils.h"

// ZeroMQ
#pragma warning(push, 0)
#include "zmqpp/zmqpp.hpp"
#pragma warning(pop)


using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::network;
using namespace zmqpp;

namespace
{
    unique_ptr<context_t> context_;
}


Channel::Channel()
    : bytes_sent_(0),
      bytes_received_(0),
      end_point_(""),
      receive_mutex_(make_unique<mutex>()),
      send_mutex_(make_unique<mutex>())
{
}

Channel::~Channel()
{
    if (is_connected())
    {
        disconnect();
    }
}

void Channel::bind(const string& end_point)
{
    throw_if_connected();

    end_point_ = end_point;
    get_socket()->bind(end_point);
}

void Channel::connect(const string& end_point)
{
    throw_if_connected();

    end_point_ = end_point;
    get_socket()->connect(end_point);
}

void Channel::disconnect()
{
    throw_if_not_connected();

    get_socket()->close();
    end_point_ = "";
}

void Channel::throw_if_not_connected() const
{
    if (!is_connected())
        throw runtime_error("Socket is not connected yet.");
}

void Channel::throw_if_connected() const
{
    if (is_connected())
        throw runtime_error("Socket is already connected");
}

bool Channel::receive(shared_ptr<SenderOperation>& sender_op, bool wait_for_message)
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

void Channel::receive(SenderResponseGetParameters& response)
{
    throw_if_not_connected();

    message_t msg;
    receive_message(msg);

    // We should have at least 18 parts
    if (msg.parts() < 18)
        throw runtime_error("Message should have at least 18 parts");

    // First part is message type
    SenderOperationType type = get_message_type(msg, /* part */ 0);

    if (type != SOP_get_parameters)
        throw runtime_error("Message should be get parameters type");

    // Parameters start from second part
    size_t idx = 1;

    // PSIConfParams
    response.psiconf_params.item_bit_count = msg.get<unsigned int>(idx++);
    response.psiconf_params.use_oprf       = msg.get<bool>(idx++);
    response.psiconf_params.use_labels     = msg.get<bool>(idx++);
    response.psiconf_params.sender_size    = msg.get<u64>(idx++);

    // TableParams
    response.table_params.log_table_size    = msg.get<unsigned int>(idx++);
    response.table_params.window_size       = msg.get<unsigned int>(idx++);
    response.table_params.split_count       = msg.get<unsigned int>(idx++);
    response.table_params.binning_sec_level = msg.get<unsigned int>(idx++);

    // CuckooParams
    response.cuckoo_params.hash_func_count = msg.get<unsigned int>(idx++);
    response.cuckoo_params.hash_func_seed  = msg.get<unsigned int>(idx++);
    response.cuckoo_params.max_probe       = msg.get<unsigned int>(idx++);

    // SEALParams
    response.seal_params.encryption_params.set_poly_modulus_degree(msg.get<int>(idx++));

    vector<SmallModulus> coeff_modulus;
    get_sm_vector(coeff_modulus, msg, idx);
    response.seal_params.encryption_params.set_coeff_modulus(coeff_modulus);

    response.seal_params.encryption_params.set_plain_modulus(msg.get<u64>(idx++));
    response.seal_params.decomposition_bit_count = msg.get<unsigned int>(idx++);

    // ExFieldParams
    response.exfield_params.characteristic = msg.get<u64>(idx++);
    response.exfield_params.degree         = msg.get<unsigned int>(idx++);

    bytes_received_ += sizeof(SenderOperationType);
    bytes_received_ += sizeof(PSIParams::PSIConfParams);
    bytes_received_ += sizeof(PSIParams::TableParams);
    bytes_received_ += sizeof(PSIParams::CuckooParams);
    bytes_received_ += sizeof(PSIParams::SEALParams);
    bytes_received_ += sizeof(PSIParams::ExFieldParams);
}

void Channel::receive(SenderResponsePreprocess& response)
{
    throw_if_not_connected();

    message_t msg;
    receive_message(msg);

    // We should have 3 parts
    if (msg.parts() != 3)
        throw runtime_error("Message should have three parts");

    SenderOperationType type = get_message_type(msg, /* part */ 0);
    if (type != SOP_preprocess)
        throw runtime_error("Message should be preprocess type");

    // Buffer starts at part 1
    get_buffer(response.buffer, msg, /* part_start */ 1);

    bytes_received_ += sizeof(SenderOperationType);
    bytes_received_ += response.buffer.size();
}

void Channel::receive(SenderResponseQuery& response)
{
    throw_if_not_connected();

    message_t msg;
    receive_message(msg);

    // We should have at least 2 parts
    if (msg.parts() < 2)
        throw runtime_error("Message should have at least two parts");

    SenderOperationType type = get_message_type(msg, /* part */ 0);
    if (type != SOP_query)
        throw runtime_error("Message should be query type");

    // Number of result packages
    response.package_count = msg.get<size_t>(/* part */ 1);

    bytes_received_ += sizeof(SenderOperationType);
    bytes_received_ += sizeof(size_t);
}

void Channel::receive(ResultPackage& pkg)
{
    throw_if_not_connected();

    message_t msg;
    receive_message(msg);

    if (msg.parts() != 4)
    {
        stringstream ss;
        ss << "Should have 4 parts, has " << msg.parts();
        throw runtime_error(ss.str());
    }

    pkg.split_idx = msg.get<int>(/* part */ 0);
    pkg.batch_idx = msg.get<int>(/* part */ 1);
    pkg.data = msg.get(/* part */ 2);
    pkg.label_data = msg.get(/* part */ 3);

    bytes_received_ += pkg.size();
}

void Channel::send_get_parameters()
{
    throw_if_not_connected();

    message_t msg;
    SenderOperationType type = SOP_get_parameters;
    add_message_type(type, msg);

    // that's it!
    send_message(msg);

    bytes_sent_ += sizeof(SenderOperationType);
}

void Channel::send_get_parameters_response(const vector<u8>& client_id, const PSIParams& params)
{
    throw_if_not_connected();

    message_t msg;

    SenderOperationType type = SOP_get_parameters;
    add_client_id(msg, client_id);
    add_message_type(type, msg);

    // PSIConfParams
    msg.add(params.item_bit_count());
    msg.add(params.use_oprf());
    msg.add(params.use_labels());
    msg.add(params.sender_size());

    // TableParams
    msg.add(params.log_table_size());
    msg.add(params.window_size());
    msg.add(params.split_count());
    msg.add(params.binning_sec_level());

    // CuckooParams
    msg.add(params.hash_func_count());
    msg.add(params.hash_func_seed());
    msg.add(params.max_probe());

    // SEALParams
    msg.add(params.encryption_params().poly_modulus_degree());
    add_sm_vector(params.encryption_params().coeff_modulus(), msg);
    msg.add(params.encryption_params().plain_modulus().value());
    msg.add(params.decomposition_bit_count());

    // ExFieldParams
    msg.add(params.exfield_characteristic());
    msg.add(params.exfield_degree());

    send_message(msg);

    bytes_sent_ += sizeof(SenderOperationType);
    bytes_sent_ += sizeof(PSIParams::PSIConfParams);
    bytes_sent_ += sizeof(PSIParams::TableParams);
    bytes_sent_ += sizeof(PSIParams::CuckooParams);
    bytes_sent_ += sizeof(PSIParams::SEALParams);
    bytes_sent_ += sizeof(PSIParams::ExFieldParams);
}

void Channel::send_preprocess(const vector<u8>& buffer)
{
    throw_if_not_connected();

    message_t msg;
    SenderOperationType type = SOP_preprocess;

    add_message_type(type, msg);
    add_buffer(buffer, msg);

    send_message(msg);

    bytes_sent_ += sizeof(SenderOperationType);
    bytes_sent_ += buffer.size();
}

void Channel::send_preprocess_response(const vector<u8>& client_id, const std::vector<apsi::u8>& buffer)
{
    throw_if_not_connected();

    message_t msg;
    SenderOperationType type = SOP_preprocess;

    add_client_id(msg, client_id);
    add_message_type(type, msg);
    add_buffer(buffer, msg);

    send_message(msg);

    bytes_sent_ += sizeof(SenderOperationType);
    bytes_sent_ += buffer.size();
}

void Channel::send_query(
    const PublicKey& pub_key,
    const RelinKeys& relin_keys,
    const map<u64, vector<Ciphertext>>& query
)
{
    throw_if_not_connected();

    message_t msg;
    SenderOperationType type = SOP_query;
    add_message_type(type, msg);
    bytes_sent_ += sizeof(SenderOperationType);

    string str;
    get_string(str, pub_key);
    msg.add(str);
    bytes_sent_ += str.length();

    get_string(str, relin_keys);
    msg.add(str);
    bytes_sent_ += str.length();

    add_part(query.size(), msg);
    bytes_sent_ += sizeof(size_t);

    for (const auto& pair : query)
    {
        add_part(pair.first, msg);
        add_part(pair.second.size(), msg);

        for (const auto& ciphertext : pair.second)
        {
            get_string(str, ciphertext);
            msg.add(str);
            bytes_sent_ += str.length();
        }

        bytes_sent_ += sizeof(u64);
        bytes_sent_ += sizeof(size_t);
    }

    send_message(msg);
}

void Channel::send_query_response(const vector<u8>& client_id, const size_t package_count)
{
    throw_if_not_connected();

    message_t msg;
    SenderOperationType type = SOP_query;
    add_client_id(msg, client_id);
    add_message_type(type, msg);

    msg.add(package_count);

    bytes_sent_ += sizeof(SenderOperationType);
    bytes_sent_ += sizeof(size_t);

    send_message(msg);
}

void Channel::send(const vector<u8>& client_id, const ResultPackage& pkg)
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

void Channel::get_buffer(vector<u8>& buff, const message_t& msg, int part_start) const
{
    // Need to have size
    if (msg.parts() < (part_start + 1))
        throw runtime_error("Should have size at least");

    size_t size;
    get_part(size, msg, /* part */ part_start);

    // If the vector is not empty, we need the part with the data
    if (size > 0 && msg.parts() < (part_start + 2))
        throw runtime_error("Should have size and data.");

    buff.resize(size);

    if (size > 0)
    {
        // Verify the actual data is the size we expect
        if (msg.size(/* part */ part_start + 1) < size)
            throw runtime_error("Second Part has less data than expected");

        memcpy(buff.data(), msg.raw_data(/* part */ part_start + 1), size);
    }
}

void Channel::add_buffer(const vector<u8>& buff, message_t& msg) const
{
    // First part is size
    add_part(buff.size(), msg);

    if (buff.size() > 0)
    {
        // Second part is raw data
        msg.add_raw(buff.data(), buff.size());
    }
}

void Channel::get_sm_vector(vector<SmallModulus>& smv, const message_t& msg, size_t& part_idx) const
{
    // Need to have size
    if (msg.parts() < (part_idx + 1))
        throw runtime_error("Should have size at least");

    size_t size;
    get_part(size, msg, /* part */ part_idx++);

    if (msg.parts() < (part_idx + size))
        throw runtime_error("Insufficient parts for SmallModulus vector");

    smv.resize(size);
    for (u64 sm_idx = 0; sm_idx < size; sm_idx++)
    {
        string str = msg.get(part_idx++);
        get_small_modulus(smv[sm_idx], str);
    }
}

void Channel::add_sm_vector(const vector<SmallModulus>& smv, message_t& msg) const
{
    // First part is size
    add_part(smv.size(), msg);

    for (const SmallModulus& sm : smv)
    {
        // Add each element as a string
        string str;
        get_string(str, sm);
        msg.add(str);
    }
}

void Channel::add_message_type(const SenderOperationType type, message_t& msg) const
{
    // Transform to int to have it have a fixed size
    add_part(static_cast<int>(type), msg);
}

SenderOperationType Channel::get_message_type(const message_t& msg, const size_t part) const
{
    // We should have at least the parts we want to get
    if (msg.parts() < (part + 1))
        throw invalid_argument("Message should have at least type");

    // Get message type
    int msg_type;
    get_part(msg_type, msg, /* part */ part);
    SenderOperationType type = static_cast<SenderOperationType>(msg_type);
    return type;
}

void Channel::extract_client_id(const message_t& msg, vector<u8>& id) const
{
    // ID should always be part 0
    size_t id_size = msg.size(/* part */ 0);
    id.resize(id_size);
    memcpy(id.data(), msg.raw_data(/* part */ 0), id_size);
}

void Channel::add_client_id(message_t& msg, const vector<u8>& id) const
{
    msg.add_raw(id.data(), id.size());
}

shared_ptr<SenderOperation> Channel::decode_get_parameters(const message_t& msg)
{
    vector<u8> client_id;
    extract_client_id(msg, client_id);

    // Nothing in the message to decode.
    return make_shared<SenderOperationGetParameters>(std::move(client_id));
}

shared_ptr<SenderOperation> Channel::decode_preprocess(const message_t& msg)
{
    vector<u8> client_id;
    extract_client_id(msg, client_id);

    vector<u8> buffer;
    get_buffer(buffer, msg, /* part_start */ 2);

    bytes_received_ += buffer.size();

    return make_shared<SenderOperationPreprocess>(std::move(client_id), std::move(buffer));
}

shared_ptr<SenderOperation> Channel::decode_query(const message_t& msg)
{
    vector<u8> client_id;
    extract_client_id(msg, client_id);

    string pub_key;
    string relin_keys;
    map<u64, vector<string>> query;

    msg.get(pub_key, /* part */ 2);
    bytes_received_ += pub_key.length();

    msg.get(relin_keys, /* part */ 3);
    bytes_received_ += relin_keys.length();

    size_t query_count;
    get_part(query_count, msg, /* part */ 4);
    bytes_received_ += sizeof(size_t);

    size_t msg_idx = 5;

    for (u64 i = 0; i < query_count; i++)
    {
        u64 power;
        get_part(power, msg, msg_idx++);

        size_t num_elems;
        get_part(num_elems, msg, msg_idx++);

        vector<string> powers(num_elems);

        for (u64 j = 0; j < num_elems; j++)
        {
            msg.get(powers[j], msg_idx++);

            bytes_received_ += powers[j].length();
        }

        query.insert_or_assign(power, powers);

        bytes_received_ += sizeof(u64);
        bytes_received_ += sizeof(size_t);
    }

    return make_shared<SenderOperationQuery>(std::move(client_id), pub_key, relin_keys, std::move(query));
}

bool Channel::receive_message(message_t& msg, bool wait_for_message)
{
    unique_lock<mutex> rec_lock(*receive_mutex_);
    bool received = get_socket()->receive(msg, !wait_for_message);

    if (!received && wait_for_message)
        throw runtime_error("Failed to receive message");

    return received;
}

void Channel::send_message(message_t& msg)
{
    unique_lock<mutex> snd_lock(*send_mutex_);
    bool sent = get_socket()->send(msg);

    if (!sent)
        throw runtime_error("Failed to send message");
}

template<typename T>
typename enable_if<is_pod<T>::value, void>::type
Channel::get_part(T& data, const message_t& msg, const size_t part) const
{
    const T* presult;
    msg.get(&presult, part);
    memcpy(&data, presult, sizeof(T));
}

template<typename T>
typename enable_if<is_pod<T>::value, void>::type
Channel::add_part(const T& data, message_t& msg) const
{
    msg.add_raw(&data, sizeof(T));
}

unique_ptr<socket_t>& Channel::get_socket()
{
    if (nullptr == context_)
    {
        context_ = make_unique<context_t>();
    }

    if (nullptr == socket_)
    {
        socket_ = make_unique<socket_t>(*context_, get_socket_type());
    }

    return socket_;
}
