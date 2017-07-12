#pragma once

#include "channel.h"
#include "concurrent_queue.h"

namespace apsi
{
    namespace network
    {
        class LocalEndpoint;
        class LocalChannel : public Channel
        {
            friend class LocalEndpoint;

        public:
            LocalChannel();
            ~LocalChannel();

            /// <summary>Get the local endpoint for this channel.</summary>
            Endpoint& getEndpoint()  override;

            /// <summary>The handle for this channel. Both ends will always have the same name.</summary>
            std::string getName() const override;


            std::uint64_t getTotalDataSent() const override;
            std::uint64_t getMaxOutstandingSendData() const override;

            /// <summary>Data will be sent over the network asynchronously. WARNING: data lifetime must be handled by caller.</summary>
            void asyncSend(const void * bufferPtr, std::uint64_t length) override;

            /// <summary>Buffer will be MOVED and then sent over the network asynchronously. </summary>
            void asyncSend(std::unique_ptr<ChannelBuffer> mH) override;

            /// <summary>Synchronous call to send data over the network. </summary>
            void send(const void * bufferPtr, std::uint64_t length) override;


            std::future<void> asyncRecv(void* dest, std::uint64_t length) override { recv(dest, length); std::promise<void> prom; prom.set_value(); return prom.get_future(); };
            std::future<void> asyncRecv(ChannelBuffer& mH) override { recv(mH); std::promise<void> prom; prom.set_value(); return prom.get_future(); };

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


            std::promise<void> mDoneProm;
            std::future<void> mDoneFuture;
        private:
            std::string mName;

            LocalChannel* mRemoteChannel;
            LocalEndpoint* mLocalEndpoint;

            struct Buffer
            {
            public:
                Buffer(const void* data, std::uint64_t length) :
                    mData(data),
                    mLength(length)
                {}

                const void* mData;
                std::uint64_t mLength;
            };

            ConcurrentQueue<Buffer> mMsgQueue;

        };


        class NullChannel : public Channel
        {

        public:
            Endpoint& getEndpoint()  override { throw std::runtime_error(""); }

            std::string getName() const override { return ""; }

            std::uint64_t getTotalDataSent() const override { return 0; }
            std::uint64_t getMaxOutstandingSendData() const override { return 0; }


            void asyncSend(const void * bufferPtr, std::uint64_t length) override {}
            void asyncSend(std::unique_ptr<ChannelBuffer> mH) override {}
            void send(const void * bufferPtr, std::uint64_t length) override {}


            std::future<void> asyncRecv(void* dest, std::uint64_t length) override { throw std::runtime_error(""); }
            std::future<void> asyncRecv(ChannelBuffer& mH) override { throw std::runtime_error(""); }

            /// <summary>Synchronous call to receive data over the network. Assumes dest has byte size length. WARNING: will through if received message length does not match.</summary>
            void recv(void* dest, std::uint64_t length) override { throw std::runtime_error(""); }

            /// <summary>Synchronous call to receive data over the network. Will resize buffer to be the appropriate size.</summary>
            void recv(ChannelBuffer& mH) override { throw std::runtime_error(""); }

            /// <summary>Returns whether this channel is open in that it can send/receive data</summary>
            bool opened() override { return true; }

            /// <summary>A blocking call that waits until the channel is open in that it can send/receive data</summary>
            void waitForOpen() override {}

            /// <summary>Close this channel to denote that no more data will be sent or received.</summary>
            void close() override {}

        };
    }
}