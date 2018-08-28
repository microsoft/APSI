#include "channel.h"
//#include "zmqpp/zmqpp.hpp"

using namespace std;
using namespace apsi;
using namespace apsi::network;
using namespace zmqpp;


Channel::Channel(const context_t& ctx)
    : bytes_sent_(0),
      bytes_received_(0),
      end_point_(""),
      socket_(ctx, socket_type::pair)
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
    socket_.receive(msg);

    // Need to have at least size
    if (msg.parts() < 1)
        throw runtime_error("Should have size at least");

    // First part is vector size
    size_t size = msg.get<size_t>(/* part */ 0);

    // If the vector is not empty, we need the part with the data
    if (size > 0 && msg.parts() < 2)
        throw runtime_error("Should have data as well.");

    // Verify the actual data is the size we expect
    if (msg.size(/* part */ 1) < size)
        throw runtime_error("Part 1 has less data than expected");

    // The buffer data is in the second part.
    buff.resize(size);
    memcpy(buff.data(), msg.raw_data(/* part */ 1), size);
    bytes_received_ += size;
}

void Channel::send(const vector<u8>& buff)
{
    throw_if_not_connected();

    message_t msg;

    // First part is size
    msg.add(buff.size());

    // Second part is raw data
    msg.add_raw(buff.data(), buff.size());

    socket_.send(msg);
    bytes_sent_ += buff.size();
}

void Channel::receive(string& str)
{
    throw_if_not_connected();

    message_t msg;
    socket_.receive(msg);

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

    socket_.send(msg);
    bytes_sent_ += str.length();
}

void Channel::receive(vector<string>& data)
{
    throw_if_not_connected();

    message_t msg;
    socket_.receive(msg);

    // First part is size
    size_t size = msg.get<size_t>(/* part */ 0);

    if (size < 1)
        throw runtime_error("Should have size at least");

    if (msg.parts() < size + 1)
        throw runtime_error("Not enough parts");

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

    socket_.send(msg);
}

future<void> Channel::async_receive(vector<u8>& buff)
{
    throw_if_not_connected();

    future<void> ret = async(launch::async, [this, &buff]
    {
        receive(buff);
    });

    return ret;
}

future<void> Channel::async_receive(vector<string>& buff)
{
    throw_if_not_connected();

    future<void> ret = async(launch::async, [this, &buff]
    {
        receive(buff);
    });

    return ret;
}

future<string> Channel::async_receive()
{
    throw_if_not_connected();

    future<string> ret = async(launch::async, [this]
    {
        string result;
        receive(result);
        return result;
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
