#pragma once

#include <future>
#include "channel.h"

namespace apsi
{
    namespace network
    {
        class BoostSocket;
        class BoostEndpoint;

        class BoostChannel : public Channel
        {

        public:

            BoostChannel(BoostEndpoint& endpoint, std::string localName, std::string remoteName);

            ~BoostChannel();

            /// <summary>Get the local endpoint for this channel.</summary>
            Endpoint& getEndpoint()  override;

            /// <summary>The handle for this channel. Both ends will always have the same name.</summary>
            std::string getName() const override;

            /// <summary>Returns the name of the remote endpoint.</summary>
            std::string getRemoteName() const;


            std::uint64_t getTotalDataSent() const override;

            std::uint64_t getMaxOutstandingSendData() const override;

            /// <summary>Data will be sent over the network asynchronously. WARNING: data lifetime must be handled by caller.</summary>
            void asyncSend(const void * bufferPtr, std::uint64_t length) override;

            /// <summary>Data will be sent over the network asynchronously. callback is executed at the completion of the send opertion. WARNING: data lifetime must be handled by caller.</summary>
            //void asyncSend(const void * bufferPtr, std::uint64_t length, std::function<void()>& callback) override;

            /// <summary>Buffer will be MOVED and then sent over the network asynchronously. </summary>
            void asyncSend(std::unique_ptr<ChannelBuffer> mH) override;

            /// <summary>Synchronous call to send data over the network. </summary>
            void send(const void * bufferPtr, std::uint64_t length) override;




            std::future<void> asyncRecv(void* dest, std::uint64_t length) override;
            std::future<void> asyncRecv(ChannelBuffer& mH) override;

            /// <summary>Synchronous call to receive data over the network. Assumes dest has byte size length. WARNING: will through if received message length does not match.</summary>
            void recv(void* dest, std::uint64_t length) override;

            /// <summary>Synchronous call to receive data over the network. Will resize buffer to be the appropriate size.</summary>
            void recv(ChannelBuffer& mH) override;




            /// <summary>Returns whether this channel is open in that it can send/receive data</summary>
            bool opened() override;

            /// <summary>A blocking call that waits until the channel is open in that it can send/receive data</summary>
            void waitForOpen() override;

            /// <summary>Close this channel to denote that no more data will be sent or received.</summary>
            void close() override;



            std::unique_ptr<BoostSocket> mSocket;
            BoostEndpoint& mEndpoint;
            std::string mRemoteName, mLocalName;
        };
    }
}
