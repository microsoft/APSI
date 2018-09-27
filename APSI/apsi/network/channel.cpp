
// STD
#include <sstream>

// APSI
#include "apsi/result_package.h"
#include "apsi/network/channel.h"
#include "apsi/network/network_utils.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::network;
using namespace zmqpp;


Channel::Channel(const context_t& ctx)
    : bytes_sent_(0),
      bytes_received_(0),
      end_point_(""),
      socket_(ctx, get_socket_type()),
      thread_pool_(thread::hardware_concurrency()),
      receive_mutex_(),
      send_mutex_()
{
}

Channel::~Channel()
{
    if (is_connected())
    {
        disconnect();
    }
}

void Channel::receive(vector<u8>& buff)
{
    throw_if_not_connected();

    message_t msg;
    receive_message(msg);
    get_buffer(buff, msg, /* part_start */ 0);

    bytes_received_ += buff.size();
}

void Channel::send(const vector<u8>& buff)
{
    throw_if_not_connected();

    message_t msg;

    add_buffer(buff, msg);
    send_message(msg);

    bytes_sent_ += buff.size();
}

void Channel::receive(string& str)
{
    throw_if_not_connected();

    message_t msg;
    receive_message(msg);

    if (msg.parts() < 1)
        throw runtime_error("Message des not contain data");

    str = msg.get(/* part */ 0);
    bytes_received_ += str.length();
}

void Channel::send(const string& str)
{
    throw_if_not_connected();

    message_t msg;
    msg.add(str);

    send_message(msg);
    bytes_sent_ += str.length();
}

void Channel::receive(vector<string>& data)
{
    throw_if_not_connected();

    message_t msg;
    receive_message(msg);

    if (msg.parts() < 1)
        throw runtime_error("Should have size at least");

    // First part is size
    size_t size = msg.get<size_t>(/* part */ 0);

    if (msg.parts() != size + 1)
    {
        stringstream ss;
        ss << "Should have " << (size + 1) << " parts, has " << msg.parts() << " parts.";
        throw runtime_error(ss.str());
    }

    data.resize(size);
    for (int i = 0; i < size; i++)
    {
        data[i] = msg.get(i + 1);
        bytes_received_ += data[i].length();
    }
}

void Channel::send(const vector<string>& data)
{
    throw_if_not_connected();

    message_t msg;
    
    // First part is size
    msg.add(data.size());

    for (auto& str : data)
    {
        msg.add(str);
        bytes_sent_ += str.length();
    }

    send_message(msg);
}

void Channel::receive(ResultPackage& pkg)
{
    throw_if_not_connected();

    // Use a single message
    message_t msg;
    receive_message(msg);

    if (msg.parts() != 4)
    {
        stringstream ss;
        ss << "Should have 4 parts, has " << msg.parts();
        throw runtime_error(ss.str());
    }

    pkg.split_idx  = msg.get<int>(/* part */ 0);
    pkg.batch_idx  = msg.get<int>(/* part */ 1);
    pkg.data       = msg.get(/* part */ 2);
    pkg.label_data = msg.get(/* part */ 3);

    bytes_received_ += pkg.size();
}

void Channel::send(const ResultPackage& pkg)
{
    throw_if_not_connected();

    message_t msg;

    msg.add(pkg.split_idx);
    msg.add(pkg.batch_idx);
    msg.add(pkg.data);
    msg.add(pkg.label_data);

    send_message(msg);

    bytes_sent_ += pkg.size();
}

future<void> Channel::async_receive(vector<u8>& buff)
{
    throw_if_not_connected();

    future<void> ret = thread_pool_.enqueue([this, &buff]
    {
        receive(buff);
    });

    return ret;
}

future<void> Channel::async_receive(vector<string>& buff)
{
    throw_if_not_connected();

    future<void> ret = thread_pool_.enqueue([this, &buff]
    {
        receive(buff);
    });

    return ret;
}

future<void> Channel::async_receive(string& str)
{
    throw_if_not_connected();

    future<void> ret = thread_pool_.enqueue([this, &str]
    {
        receive(str);
    });

    return ret;
}

future<void> Channel::async_receive(ResultPackage& pkg)
{
    throw_if_not_connected();

    future<void> ret = thread_pool_.enqueue([this, &pkg]
    {
        receive(pkg);
    });

    return ret;
}

void Channel::bind(const string& end_point)
{
    throw_if_connected();

    end_point_ = end_point;
    socket_.bind(end_point);
}

void Channel::connect(const string& end_point)
{
    throw_if_connected();

    end_point_ = end_point;
    socket_.connect(end_point);
}

void Channel::disconnect()
{
    throw_if_not_connected();

    socket_.close();
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

void Channel::receive_message(message_t& msg)
{
    // Ensure we receive one message at a time.
    unique_lock<mutex> rec_lock(receive_mutex_);
    bool received = socket_.receive(msg);

    if (!received)
        throw runtime_error("Failed to receive message.");
}

void Channel::send_message(message_t& msg)
{
    // Ensure we send one message at a time.
    unique_lock<mutex> snd_lock(send_mutex_);
    bool sent = socket_.send(msg);

    if (!sent)
        throw runtime_error("Failed to send message");
}

bool Channel::receive(shared_ptr<SenderOperation>& sender_op, bool wait_for_message)
{
    throw_if_not_connected();

    message_t msg;
    if (!socket_.receive(msg, !wait_for_message))
    {
        // No message yet.
        return false;
    }

    // Should have at least type.
    if (msg.parts() < 1)
        throw runtime_error("Not enough parts in message");

    SenderOperationType type = get_message_type(msg);

    switch (type)
    {
    case SOP_get_parameters:
        // We don't need any other data.
        sender_op = make_shared<SenderOperationGetParameters>();
        break;

    case SOP_preprocess:
        {
            vector<u8> buffer;
            get_buffer(buffer, msg, /* part_start */ 1);
            sender_op = make_shared<SenderOperationPreprocess>(std::move(buffer));

            bytes_received_ += buffer.size();
        }
        break;

    case SOP_query:
        {
            string pub_key;
            string relin_keys;
            map<u64, vector<string>> query;

            msg.get(pub_key, /* part */ 1);
            bytes_received_ += pub_key.length();

            msg.get(relin_keys, /* part */ 2);
            bytes_received_ += relin_keys.length();

            auto query_count = msg.get<size_t>(/* part */ 3);
            bytes_received_ += sizeof(size_t);

            size_t msg_idx = 4;

            for (u64 i = 0; i < query_count; i++)
            {
                u64 power = msg.get<u64>(msg_idx++);
                size_t num_elems = msg.get<size_t>(msg_idx++);
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

            sender_op = make_shared<SenderOperationQuery>(pub_key, relin_keys, std::move(query));
        }
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
    socket_.receive(msg);

    // We should have two parts
    if (msg.parts() != 2)
        throw runtime_error("Message should have two parts");

    // First part is message type
    SenderOperationType type = get_message_type(msg);

    if (type != SOP_get_parameters)
        throw runtime_error("Message should be get parameters type");

    // Second part is the actual parameter: sender bin size
    response.sender_bin_size = msg.get<int>(/* part */ 1);

    bytes_received_ += sizeof(SenderOperationType);
    bytes_received_ += sizeof(int);
}

void Channel::receive(SenderResponsePreprocess& response)
{
    throw_if_not_connected();

    message_t msg;
    socket_.receive(msg);

    // We should have 3 parts
    if (msg.parts() != 3)
        throw runtime_error("Message should have three parts");

    SenderOperationType type = get_message_type(msg);
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
    socket_.receive(msg);

    // We should have at least 2 parts
    if (msg.parts() < 2)
        throw runtime_error("Message should have at least two parts");

    SenderOperationType type = get_message_type(msg);
    if (type != SOP_query)
        throw runtime_error("Message should be query type");

    // Number of result packages
    size_t pkg_count = msg.get<size_t>(/* part */ 1);

    if (msg.parts() < ((pkg_count * 4) + 2))
        throw runtime_error("Not enough results in message");

    response.result.resize(pkg_count);

    for (u64 i = 0; i < pkg_count; i++)
    {
        // Each package has 4 parts, plus the type and package count
        size_t pkg_idx = (i * 4) + 2;

        ResultPackage pkg;
        pkg.split_idx  = msg.get<int>(pkg_idx++);
        pkg.batch_idx  = msg.get<int>(pkg_idx++);
        pkg.data       = msg.get(pkg_idx++);
        pkg.label_data = msg.get(pkg_idx++);

        bytes_received_ += sizeof(int) * 2;
        bytes_received_ += pkg.data.length();
        bytes_received_ += pkg.label_data.length();

        response.result[i] = pkg;
    }

    bytes_received_ += sizeof(SenderOperationType);
    bytes_received_ += sizeof(size_t);
}

void Channel::send_get_parameters()
{
    throw_if_not_connected();

    message_t msg;
    SenderOperationType type = SOP_get_parameters;
    add_message_type(type, msg);

    // that's it!
    socket_.send(msg);

    bytes_sent_ += sizeof(SenderOperationType);
}

void Channel::send_get_parameters_response(const PSIParams& params)
{
    throw_if_not_connected();

    message_t msg;
    SenderOperationType type = SOP_get_parameters;
    add_message_type(type, msg);

    // For now only sender bin size
    msg.add(params.sender_bin_size());

    socket_.send(msg);

    bytes_sent_ += sizeof(SenderOperationType);
    bytes_sent_ += sizeof(int);
}

void Channel::send_preprocess(const vector<u8>& buffer)
{
    throw_if_not_connected();

    message_t msg;
    SenderOperationType type = SOP_preprocess;

    add_message_type(type, msg);
    add_buffer(buffer, msg);

    socket_.send(msg);

    bytes_sent_ += sizeof(SenderOperationType);
    bytes_sent_ += buffer.size();
}

void Channel::send_preprocess_response(const std::vector<apsi::u8>& buffer)
{
    throw_if_not_connected();

    message_t msg;
    SenderOperationType type = SOP_preprocess;

    add_message_type(type, msg);
    add_buffer(buffer, msg);

    socket_.send(msg);

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

    string str;
    get_string(str, pub_key);
    msg.add(str);
    bytes_sent_ += str.length();

    get_string(str, relin_keys);
    msg.add(str);
    bytes_sent_ += str.length();

    msg.add(query.size());
    bytes_sent_ += sizeof(size_t);

    for (const auto& pair : query)
    {
        msg.add(pair.first);
        msg.add(pair.second.size());

        for (const auto& ciphertext : pair.second)
        {
            get_string(str, ciphertext);
            msg.add(str);
            bytes_sent_ += str.length();
        }

        bytes_sent_ += sizeof(u64);
        bytes_sent_ += sizeof(size_t);
    }

    socket_.send(msg);
}

void Channel::send_query_response(const std::vector<apsi::ResultPackage>& result)
{
    throw_if_not_connected();

    message_t msg;
    SenderOperationType type = SOP_query;
    add_message_type(type, msg);

    msg.add(result.size());

    for (const auto& pkg : result)
    {
        msg.add(pkg.split_idx);
        msg.add(pkg.batch_idx);
        msg.add(pkg.data);
        msg.add(pkg.label_data);

        bytes_sent_ += sizeof(int) * 2;
        bytes_sent_ += pkg.data.length();
        bytes_sent_ += pkg.label_data.length();
    }

    bytes_sent_ += sizeof(SenderOperationType);
    bytes_sent_ += sizeof(size_t);

    socket_.send(msg);
}

void Channel::get_buffer(vector<u8>& buff, const message_t& msg, int part_start) const
{
    // Need to have size
    if (msg.parts() < (part_start + 1))
        throw runtime_error("Should have size at least");

    size_t size;
    get(size, msg, /* part */ part_start);

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
    msg.add(buff.size());

    if (buff.size() > 0)
    {
        // Second part is raw data
        msg.add_raw(buff.data(), buff.size());
    }
}

void Channel::add_message_type(const SenderOperationType type, message_t& msg) const
{
    // Transform to int to have it have a fixed size
    msg.add(static_cast<int>(type));
}

SenderOperationType Channel::get_message_type(const message_t& msg) const
{
    // We should have at least type
    if (msg.parts() < 1)
        throw invalid_argument("Message should have at least type");

    // First part is message type
    SenderOperationType type = static_cast<SenderOperationType>(msg.get<int>(/* part */ 0));
    return type;
}
