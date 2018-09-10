#pragma once

// STD
#include <vector>
#include <future>
#include <thread>
#include <mutex>

// APSI
#include "apsi/apsidefines.h"
#include "apsi/tools/thread_pool.h"

// ZeroMQ
#pragma warning(push, 0)
#include "zmqpp/zmqpp.hpp"
#pragma warning(pop)


namespace apsi
{
    struct ResultPackage;

    namespace network
    {
        /**
        * Communication channel between Sender and Receiver.
        *
        * All receives are synchrounous, except the ones prefixed with 'async'.
        * All sends are asynchrounous.
        */
        class Channel
        {
        public:
            /**
            * A channel should always be initialized with a context.
            */
            Channel() = delete;

            /**
            * Create an instance of a Channel with the given context
            */
            Channel(const zmqpp::context_t& context);

            /**
            * Destroy an instance of a Channel
            */
            ~Channel();

            /**
            * Receive the contents of the buffer. Will resize the buffer
            * if necessary.
            */
            void receive(std::vector<apsi::u8>& buff);

            /**
            * Receive a string.
            */
            void receive(std::string& str);

            /**
            * Receive a vector of strings
            */
            void receive(std::vector<std::string>& data);

            /**
            * Receive a ResultPackage structure
            */
            void receive(apsi::ResultPackage& pkg);

            /**
            * Receive a simple POD type.
            */
            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, void>::type
                receive(T& data)
            {
                throw_if_not_connected();

                zmqpp::message_t msg;
                receive_message(msg);

                if (msg.parts() < 1)
                    throw std::runtime_error("Not enough data");

                const T* pres;
                msg.get(&pres, /* part */ 0);
                memcpy(&data, pres, sizeof(T));

                bytes_received_ += sizeof(T);
            }

            /**
            * Asynchronously receive a buffer.
            */
            std::future<void> async_receive(std::vector<apsi::u8>& buff);

            /**
            * Asynchronously receive a vector of strings.
            */
            std::future<void> async_receive(std::vector<std::string>& buff);

            /**
            * Asynchronously receive a ResultPackage structure
            */
            std::future<void> async_receive(apsi::ResultPackage& pkg);

            /**
            * Asynchrounously receive a simple POD type.
            */
            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, std::future<void>>::type
                async_receive(T& data)
            {
                throw_if_not_connected();

                std::future<void> ret = thread_pool_.enqueue([this, &data]
                {
                    receive<T>(data);
                });

                return ret;
            }

            /**
            * Asynchronously receive a string.
            */
            std::future<void> async_receive(std::string& str);

            /**
            * Send the contents of the buffer. A copy of the data is made.
            */
            void send(const std::vector<apsi::u8>& buff);

            /**
            * Send a string.
            */
            void send(const std::string& str);

            /**
            * Send a vector of strings. A copy of the data is made.
            */
            void send(const std::vector<std::string>& data);

            /**
            * Send a ResultPackage structure
            */
            void send(const apsi::ResultPackage& pkg);

            /**
            * Send a simple POD type.
            */
            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, void>::type
                send(const T& data)
            {
                throw_if_not_connected();

                zmqpp::message_t msg;
                msg.add_raw(&data, sizeof(T));
                send_message(msg);
                bytes_sent_ += sizeof(T);
            }

            /**
            * Bind the channel to the given connection point.
            */
            void bind(const std::string& connection_point);

            /**
            * Connect the channel to the given connection point
            */
            void connect(const std::string& connection_point);

            /**
            * Disconnect from the connection point
            */
            void disconnect();

            /**
            * Get the amount of data that has been sent through the channel
            */
            u64 get_total_data_sent() const { return bytes_sent_; }

            /**
            * Get the amount of data that has been received through the channel
            */
            u64 get_total_data_received() const { return bytes_received_; }

            /**
            * Indicates whether the channel is connected to the network.
            */
            bool is_connected() const { return !end_point_.empty(); }

        private:
            u64 bytes_sent_;
            u64 bytes_received_;

            zmqpp::socket_t socket_;
            std::string end_point_;

            apsi::tools::ThreadPool thread_pool_;
            std::mutex receive_mutex_;
            std::mutex send_mutex_;

            void throw_if_not_connected() const;
            void throw_if_connected() const;
            void receive_message(zmqpp::message_t& msg);
            void send_message(zmqpp::message_t& msg);
        };
    }
}
