#include "channel.h"

// STD
#include <sstream>

// APSI
#include "apsi/result_package.h"

using namespace std;
using namespace apsi;
using namespace apsi::network;
using namespace zmqpp;


Channel::Channel(const context_t& ctx)
    : bytes_sent_(0),
      bytes_received_(0),
      end_point_(""),
      socket_(ctx, socket_type::pair),
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

    // Need to have size
    if (msg.parts() < 1)
        throw runtime_error("Should have size at least");

    size_t size = msg.get<size_t>(/* part */ 0);

    // If the vector is not empty, we need the part with the data
    if (size > 0 && msg.parts() != 2)
        throw runtime_error("Should have size and data.");

    buff.resize(size);

    if (size > 0)
    {
        // Verify the actual data is the size we expect
        if (msg.size(/* part */ 1) < size)
            throw runtime_error("Part 1 has less data than expected");

        memcpy(buff.data(), msg.raw_data(/* part */ 1), size);
    }

    bytes_received_ += size;
}

void Channel::send(const vector<u8>& buff)
{
    throw_if_not_connected();

    message_t msg;

    // First part is size
    msg.add(buff.size());

    if (buff.size() > 0)
    {
        // Second part is raw data
        msg.add_raw(buff.data(), buff.size());
    }

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
