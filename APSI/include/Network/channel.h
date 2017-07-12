#pragma once

#include <string>
#include <memory>
#include <future>

namespace apsi
{
    namespace network
    {
        class Channel;
        class Endpoint;

        /// <summary>Represents a possibly re-sizable buffer which a channel and read and write from.</summary>
        class ChannelBuffer
        {
        public:
            virtual ~ChannelBuffer()
            {
            }

        private:
            friend class Channel;
            friend class WinNetChannel;
            friend class LocalChannel;
            friend class BoostIOService;
            friend class BoostChannel;

        protected:
            virtual std::uint8_t* ChannelBufferData() const = 0;
            virtual std::uint64_t ChannelBufferSize() const = 0;
            virtual void ChannelBufferResize(std::uint64_t length) = 0;
        };

        /// <summary>Represents a named pipe that allows data to be send between two Endpoints</summary>
        class Channel
        {
        public:
            virtual ~Channel()
            {
            }


            /// <summary>Get the local endpoint for this channel.</summary>
            virtual Endpoint& getEndpoint() = 0;

            /// <summary>The handle for this channel. Both ends will always have the same name.</summary>
            virtual std::string getName() const = 0;


            virtual std::uint64_t getTotalDataSent() const = 0;

            virtual std::uint64_t getMaxOutstandingSendData() const = 0;

            /// <summary>Data will be sent over the network asynchronously. WARNING: data lifetime must be handled by caller.</summary>
            virtual void asyncSend(const void * bufferPtr, std::uint64_t length) = 0;

            /// <summary>Data will be sent over the network asynchronously. callback is executed at the completion of the send opertion. WARNING: data lifetime must be handled by caller.</summary>
            //virtual void asyncSend(const void * bufferPtr, std::uint64_t length, std::function<void()> callback) = 0;

            /// <summary>Buffer will be MOVED and then sent over the network asynchronously. </summary>
            virtual void asyncSend(std::unique_ptr<ChannelBuffer> mH) = 0;

            /// <summary>Synchronous call to send data over the network. </summary>
            virtual void send(const void * bufferPtr, std::uint64_t length) = 0;


            virtual std::future<void> asyncRecv(void* dest, std::uint64_t length) = 0;
            virtual std::future<void> asyncRecv(ChannelBuffer& mH) = 0;

            /// <summary>Synchronous call to receive data over the network. Assumes dest has byte size length. WARNING: will through if received message length does not match.</summary>
            virtual void recv(void* dest, std::uint64_t length) = 0;

            /// <summary>Synchronous call to receive data over the network. Will resize buffer to be the appropriate size.</summary>
            virtual void recv(ChannelBuffer& mH) = 0;

            /// <summary>Returns whether this channel is open in that it can send/receive data</summary>
            virtual bool opened() = 0;

            /// <summary>A blocking call that waits until the channel is open in that it can send/receive data</summary>
            virtual void waitForOpen() = 0;

            /// <summary>Close this channel to denote that no more data will be sent or received.</summary>
            virtual void close() = 0;

            //
            // Helper functions.
            //

            /// <summary>Synchronous call to send data over the network. </summary>
            void send(const ChannelBuffer& buf);

            /// <summary>Performs a data copy and the returns. Data will be sent over the network asynconsouly. </summary>
            void asyncSendCopy(const ChannelBuffer& buf);

            /// <summary>Performs a data copy and the returns. Data will be sent over the network asynchronously.</summary> 
            void asyncSendCopy(const void * bufferPtr, std::uint64_t length);

        };
    }
}