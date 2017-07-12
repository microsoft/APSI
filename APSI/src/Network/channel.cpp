#include "Network/channel.h"
#include "Network/byte_stream.h"

void apsi::network::Channel::send(const ChannelBuffer & buf)
{
	send(buf.ChannelBufferData(), buf.ChannelBufferSize());
}

void apsi::network::Channel::asyncSendCopy(const ChannelBuffer & buf)
{
	asyncSendCopy(buf.ChannelBufferData(), buf.ChannelBufferSize());
}

void apsi::network::Channel::asyncSendCopy(const void * bufferPtr, uint64_t length)
{
	std::unique_ptr<ByteStream> bs(new ByteStream((uint8_t*)bufferPtr, length));
	asyncSend(std::move(bs));
}
