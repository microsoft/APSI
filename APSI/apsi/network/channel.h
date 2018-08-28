#pragma once

#include <vector>
#include <future>
#include "apsi/apsidefines.h"
#include "zmqpp/zmqpp.hpp"


namespace apsi
{
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
            * Create an instance of a Channel
            */
            Channel();

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
            * Receive a simple POD type.
            */
            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, T>::type
                receive()
            {

                T result = {};
                zmqpp::message_t msg;
                socket_->receive(msg);
                if (msg.parts() < 1)
                    throw std::runtime_error("Not enough data");

                result = msg.get<T>(/* part */ 0);
                return result;
            }

            /**
            * Asynchronously receive a buffer.
            */
            std::future<void> async_receive(std::vector<apsi::u8>& buff);

            /**
            * Asynchrounously receive a simple POD type.
            */
            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, std::future<T>>::type
                async_receive()
            {
                std::future<T> future = std::async(std::launch::async, [this]
                {
                    T result = receive<T>();
                    return result;
                });

                return future;
            }

            /**
            * Asynchronously receive a string.
            */
            std::future<std::string> async_receive();

            /**
            * Send the contents of the buffer. A copy of the data is made.
            */
            void send(const std::vector<apsi::u8>& buff);

            /**
            * Send a string.
            */
            void send(const std::string& str);

            /**
            * Send a vector of strings.
            */
            void send(const std::vector<std::string>& data);

            /**
            * Send a simple POD type.
            */
            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, void>::type
                send(const T& data)
            {
                throw_if_not_connected();

                zmqpp::message_t msg;
                msg.add<T>(data);
                socket_->send(msg);
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
            * Get the amount of data that has been sent through the channel
            */
            u64 get_total_data_sent() const { return bytes_sent_; }

            /**
            * Get the amount of data that has been received through the channel
            */
            u64 get_total_data_received() const { return bytes_received_; }

        private:
            u64 bytes_sent_;
            u64 bytes_received_;

            std::unique_ptr<zmqpp::socket_t> socket_;
            std::string end_point_;

            void throw_if_not_connected() const;
            void throw_if_connected() const;
        };
    }
}
