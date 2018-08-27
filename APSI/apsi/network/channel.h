#pragma once

#include <vector>
#include <future>
#include "apsi/apsidefines.h"

namespace zmqpp
{
    class socket;
    class message;
    class context;
}

namespace apsi
{
    namespace network
    {
        /**
        * Communication channel between Sender and Receiver.
        */
        class Channel
        {
        public:
            Channel() = delete;
            Channel(const zmqpp::context& context);

            /**
            * Receive the contents of the buffer. Will resize the buffer
            * if necessary.
            */
            void receive(std::vector<apsi::u8>& buff);

            void receive(std::string& str);

            void receive(zmqpp::message& msg);

            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, T>::type
                receive()
            {
                T result = {};
                return result;
            }

            std::future<void> async_receive(std::vector<apsi::u8>& buff);

            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, std::future<T>>::type
                async_receive()
            {
                std::future<T> future = std::async(std::launch::async, [] { T result = {}; return result; });
                return future;
            }

            std::future<std::string> async_receive();

            /**
            * Send the contents of the buffer. A copy of the data is made.
            */
            void send(const std::vector<apsi::u8>& buff);
            void send(const std::string& str);
            void send(zmqpp::message& msg);

            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, void>::type
                send(const T& data)
            {
            }


            u64 get_total_data_sent() const { return bytes_sent_; }
            u64 get_total_data_received() const { return bytes_received_; }

        private:
            u64 bytes_sent_;
            u64 bytes_received_;

            std::unique_ptr<zmqpp::socket> socket_;
        };
    }
}
