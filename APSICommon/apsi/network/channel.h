#pragma once

// STD
#include <vector>
#include <map>
#include <memory>

// APSI
#include "apsi/apsidefines.h"
#include "apsi/psiparams.h"
#include "apsi/network/senderoperation.h"
#include "apsi/network/senderoperationresponse.h"

// SEAL
#include "seal/publickey.h"
#include "seal/relinkeys.h"
#include "seal/ciphertext.h"


namespace std
{
    class mutex;
}

namespace zmqpp
{
    class socket;
    typedef socket socket_t;
    enum class socket_type;
    class message;
    typedef message message_t;
    class context;
    typedef context context_t;
}

namespace apsi
{
    struct ResultPackage;

    namespace network
    {
        /**
        * Communication channel between Sender and Receiver.
        *
        * All receives are synchrounous.
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
            virtual ~Channel();

            /**
            * Receive a Sender Operation.
            *
            * This call does not block if wait_for_message is false, if there
            * is no operation pending it will immediately return false.
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
            Receive a ResultPackage structure
            */
            void receive(apsi::ResultPackage& pkg);

            /**
            Send a request to Get Parameters from Sender
            */
            void send_get_parameters();

            /**
            Send a response to a request to Get Parameters
            */
            void send_get_parameters_response(const std::vector<apsi::u8>& client_id, const apsi::PSIParams& params);

            /**
            Send a request to Preprocess items on Sender
            */
            void send_preprocess(const std::vector<apsi::u8>& buffer);

            /**
            * Send a response to a request to Preprocess items
            */
            void send_preprocess_response(const std::vector<apsi::u8>& client_id, const std::vector<apsi::u8>& buffer);

            /**
            * Send a request for a Query response to Sender
            */
            void send_query(
                const seal::PublicKey& pub_key,
                const seal::RelinKeys& relin_keys,
                const std::map<apsi::u64, std::vector<seal::Ciphertext>>& query
            );

            /**
            Send a response to a Query request
            */
            void send_query_response(const std::vector<apsi::u8>& client_id, const size_t package_count);

            /**
            * Send a ResultPackage structure
            */
            void send(const std::vector<apsi::u8>& client_id, const apsi::ResultPackage& pkg);

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

        protected:
            /**
            Get socket type for this channel.
            */
            virtual zmqpp::socket_type get_socket_type() = 0;

            /**
            Add any needed options for the socket. Called just after socket creation.
            */
            virtual void set_socket_options(zmqpp::socket_t* socket) = 0;

        private:
            u64 bytes_sent_;
            u64 bytes_received_;

            std::unique_ptr<zmqpp::socket_t> socket_;
            std::string end_point_;

            std::unique_ptr<std::mutex> receive_mutex_;
            std::unique_ptr<std::mutex> send_mutex_;

            std::unique_ptr<zmqpp::context_t> context_;

            void throw_if_not_connected() const;
            void throw_if_connected() const;

            bool receive_message(zmqpp::message_t& msg, bool wait_for_message = true);
            void send_message(zmqpp::message_t& msg);

            /**
            Decode a Get Parameters message
            */
            std::shared_ptr<apsi::network::SenderOperation>
                decode_get_parameters(const zmqpp::message_t& msg);

            /**
            Decode a Preprocess message
            */
            std::shared_ptr<apsi::network::SenderOperation>
                decode_preprocess(const zmqpp::message_t& msg);

            /**
            Decode a Query message
            */
            std::shared_ptr<apsi::network::SenderOperation>
                decode_query(const zmqpp::message_t& msg);

            /**
            Add message type to message
            */
            void add_message_type(const SenderOperationType type, zmqpp::message_t& msg) const;

            /**
            Get message type from message.
            Message type is always part 0.
            */
            SenderOperationType get_message_type(const zmqpp::message_t& msg, const size_t part = 1) const;

            /**
            Extract client ID from a message
            */
            void extract_client_id(const zmqpp::message_t& msg, std::vector<apsi::u8>& id) const;

            /**
            Add client ID to message
            */
            void add_client_id(zmqpp::message_t& msg, const std::vector<apsi::u8>& id) const;

            /**
            Get buffer from message, located at part_start
            */
            void get_buffer(std::vector<u8>& buff, const zmqpp::message_t& msg, int part_start) const;

            /**
            Add buffer to the given message
            */
            void add_buffer(const std::vector<u8>& buff, zmqpp::message_t& msg) const;

            /**
            Get a vector of SmallModulus from message at the given part index.
            When method exits the part index will be pointing to the next part in the message, after the vector.
            */
            void get_sm_vector(std::vector<seal::SmallModulus>& smv, const zmqpp::message_t& msg, size_t& part_idx) const;

            /**
            Add a vector of SmallModulus to given message
            */
            void add_sm_vector(const std::vector<seal::SmallModulus>& smv, zmqpp::message_t& msg) const;

            /**
            Get a part from a message
            */
            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, void>::type
                get_part(T& data, const zmqpp::message_t& msg, const size_t part) const;

            /**
            Add a part to a message
            */
            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, void>::type
                add_part(const T& data, zmqpp::message_t& msg) const;

            /**
            Get socket
            */
            std::unique_ptr<zmqpp::socket_t>& get_socket();
        };
    }
}
