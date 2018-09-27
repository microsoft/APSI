#pragma once

// STD
#include <vector>
#include <future>
#include <thread>
#include <mutex>
#include <map>
#include <memory>

// APSI
#include "apsi/apsidefines.h"
#include "apsi/psiparams.h"
#include "apsi/network/senderoperation.h"
#include "apsi/network/senderoperationresponse.h"
#include "apsi/tools/thread_pool.h"

// SEAL
#include "seal/publickey.h"
#include "seal/relinkeys.h"
#include "seal/ciphertext.h"

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
            virtual ~Channel();

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

        public:
            /**
            * Receive a Sender Operation.
            *
            * This call does not block, if there is no operation pending it will
            * immediately return false.
            */
            bool receive(std::shared_ptr<apsi::network::SenderOperation>& sender_op, bool wait_for_message = false);

            /**
            * Receive Get Parameters response from Sender
            */
            void receive(apsi::network::SenderResponseGetParameters& response);

            /**
            * Receive item preprocessing response from Sender
            */
            void receive(apsi::network::SenderResponsePreprocess& response);

            /**
            * Receive Query response from Sender
            */
            void receive(apsi::network::SenderResponseQuery& response);

            /**
            Send a request to Get Parameters from Sender
            */
            void send_get_parameters();

            /**
            Send a response to a request to Get Parameters
            */
            void send_get_parameters_response(const apsi::PSIParams& params);

            /**
            Send a request to Preprocess items on Sender
            */
            void send_preprocess(const std::vector<apsi::u8>& buffer);

            /**
            Send a response to a request to Preprocess items
            */
            void send_preprocess_response(const std::vector<apsi::u8>& buffer);

            /**
            Send a request for a Query response to Sender
            */
            void send_query(
                const seal::PublicKey& pub_key,
                const seal::RelinKeys& relin_keys,
                const std::map<apsi::u64, std::vector<seal::Ciphertext>>& query
            );

            /**
            Send a response to a Query request
            */
            void send_query_response(const std::vector<apsi::ResultPackage>& result);


        protected:
            /**
            Get socket type for this channel.
            */
            virtual zmqpp::socket_type get_socket_type()
            {
                // default is pair
                return zmqpp::socket_type::pair;
            }


        private:
            u64 bytes_sent_;
            u64 bytes_received_;

            const zmqpp::context_t& context_;
            std::unique_ptr<zmqpp::socket_t> socket_;
            std::string end_point_;

            apsi::tools::ThreadPool thread_pool_;
            std::mutex receive_mutex_;
            std::mutex send_mutex_;

            void throw_if_not_connected() const;
            void throw_if_connected() const;
            void receive_message(zmqpp::message_t& msg);
            void send_message(zmqpp::message_t& msg);

            /**
            Add message type to message
            */
            void add_message_type(const SenderOperationType type, zmqpp::message_t& msg) const;

            /**
            Get message type from message.
            Message type is always part 0.
            */
            SenderOperationType get_message_type(const zmqpp::message_t& msg) const;

            /**
            Get buffer from message, located at part_start
            */
            void get_buffer(std::vector<u8>& buff, const zmqpp::message_t& msg, int part_start) const;

            /**
            Add buffer to the given message
            */
            void add_buffer(const std::vector<u8>& buff, zmqpp::message_t& msg) const;

            /**
            Get a part from a message
            */
            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, void>::type
                get(T& data, const zmqpp::message_t& msg, const size_t part) const
            {
                const T* presult;
                msg.get(&presult, part);
                memcpy(&data, presult, sizeof(T));
            }

            /**
            Set a part on a message
            */
            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, void>::type
                set(const T& data, zmqpp::message_t& msg) const
            {
                msg.add_raw(&data, sizeof(T));
            }

            /**
            Get socket
            */
            std::unique_ptr<zmqpp::socket_t>& get_socket()
            {
                if (nullptr == socket_)
                {
                    socket_ = std::make_unique<zmqpp::socket_t>(context_, get_socket_type());
                }

                return socket_;
            }
        };
    }
}
