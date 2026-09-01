// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <mutex>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

// APSI
#include "apsi/network/network_channel.h"
#include "apsi/network/result_package.h"
#include "apsi/network/sender_operation.h"
#include "apsi/network/sender_operation_response.h"

namespace zmq {
    class socket_t;
    class multipart_t;
    class context_t;
    enum class socket_type;
} // namespace zmq

enum class socket_type;

namespace apsi::network {
    /**
    Encapsulates a SenderOperation and a client identifier used internally by ZeroMQ.
    */
    struct ZMQSenderOperation {
        std::unique_ptr<SenderOperation> sop;

        std::vector<unsigned char> client_id;
    };

    /**
    Encapsulates a SenderOperationResponse and a client identifier used internally by ZeroMQ.
    */
    struct ZMQSenderOperationResponse {
        std::unique_ptr<SenderOperationResponse> sop_response;

        std::vector<unsigned char> client_id;
    };

    /**
    Encapsulates a ResultPackage and a client identifier used internally by ZeroMQ.
    */
    struct ZMQResultPackage {
        std::unique_ptr<ResultPackage> rp;

        std::vector<unsigned char> client_id;
    };

    /**
    ZMQChannel is a communication channel between a sender and a receiver implemented using
    ZeroMQ. All receives are synchronous, except for receiving a SenderOperation. All sends are
    asynchronous.

    ZeroMQ uses an identifier number for internal package routing, which is why the ZMQChannel
    operates on custom ZMQSenderOperation, ZMQSenderOperationResponse, and ZMQResultPackage
    objects rather than the underlying SenderOperation, SenderOperationResponse, and
    ResultPackage.

    ZMQChannel is an interface class and is implemented by the ZMQSenderChannel and
    ZMQReceiverChannel.
    */
    class ZMQChannel : public NetworkChannel {
    public:
        /**
        Create an instance of a ZMQChannel.
        */
        ZMQChannel();

        /**
        Destroy an instance of a ZMQChannel.
        */
        ~ZMQChannel() override;

        /**
        Bind the channel to the given connection point.
        */
        void bind(const std::string &end_point);

        /**
        Connect the channel to the given connection point.
        */
        void connect(const std::string &end_point);

        /**
        Disconnect the channel from the connection point.
        */
        void disconnect();

        /**
        Returns whether the channel is in a connected state.
        */
        bool is_connected() const
        {
            return !end_point_.empty();
        }

        /**
        The endpoint the channel is bound or connected to, or an empty string if the channel is
        not connected.

        For a bound channel this is the endpoint ZeroMQ actually bound, which is not necessarily
        the one requested: binding to a port of 0 leaves the choice of port to the operating
        system, and this is how the caller learns which one it received, so that it can tell a
        peer where to connect.
        */
        const std::string &end_point() const noexcept
        {
            return end_point_;
        }

        /**
        Send a SenderOperation from a receiver to a sender. These operations represent either a
        parameter request, an OPRF request, or a query request. The function throws an exception
        on failure.
        */
        void send(std::unique_ptr<SenderOperation> sop) override;

        /**
        Receive a ZMQSenderOperation from a receiver. Operations of type sop_query and
        sop_unknown require a valid seal::SEALContext to be provided. For operations of type
        sop_parms and sop_oprf the context can be set as nullptr.

        A nullptr return has two meanings that callers must tell apart. Either nothing has
        arrived yet, in which case asking again is worthwhile, or a message arrived and was
        rejected, in which case it has been consumed and no amount of waiting will bring it
        back. Only the second records a failure, so receive_failed and receive_failure_count
        distinguish them; a loop that retries on nullptr without consulting one of those waits
        forever for data that is already gone.

        If wait_for_message is false this call does not block. If it is true the call blocks
        only until the socket's receive timeout elapses, so it always returns control to the
        caller within a bounded interval however the peer behaves.
        */
        virtual std::unique_ptr<ZMQSenderOperation> receive_network_operation(
            std::shared_ptr<seal::SEALContext> context,
            bool wait_for_message,
            SenderOperationType expected = SenderOperationType::sop_unknown);

        /**
        Receive a ZMQSenderOperation from a receiver. Operations of type sop_query and
        sop_unknown require a valid seal::SEALContext to be provided. For operations of type
        sop_parms and sop_oprf the context can be set as nullptr. This call does not block: if
        there is no operation pending, it will immediately return nullptr. See the overload
        taking wait_for_message for what a nullptr return does and does not mean.
        */
        virtual std::unique_ptr<ZMQSenderOperation> receive_network_operation(
            std::shared_ptr<seal::SEALContext> context,
            SenderOperationType expected = SenderOperationType::sop_unknown)
        {
            return receive_network_operation(std::move(context), false, expected);
        }

        /**
        Send a ZMQSenderOperationResponse from a sender to a receiver. These operations
        represent a response to either a parameter request, an OPRF request, or a query request.
        The function throws and exception on failure. The sender is expected to manually read
        the client identifier from the received ZMQSenderOperation and use the same client
        identifier in the ZMQSenderOperationResponse.
        */
        virtual void send(std::unique_ptr<ZMQSenderOperationResponse> sop_response);

        /**
        Receive a SenderOperationResponse from a sender. Returns nullptr either because nothing
        arrived within the socket's receive timeout or because a message arrived and was
        rejected; receive_failed tells the two apart, and a caller that loops on nullptr must
        consult it. The call always returns control within a bounded interval.
        */
        std::unique_ptr<SenderOperationResponse> receive_response(
            SenderOperationType expected = SenderOperationType::sop_unknown) override;

        /**
        Send a ZMQResultPackage to a receiver. The function throws and exception on failure. The
        sender is expected to manually read the client identifier from the received
        ZMQSenderOperation and use the same client identifier in the ZMQResultPackage.
        */
        virtual void send(std::unique_ptr<ZMQResultPackage> rp);

        /**
        Receive a ResultPackage from a sender. A valid seal::SEALContext must be provided.
        Returns nullptr either because nothing arrived within the socket's receive timeout or
        because a message arrived and was rejected; receive_failed tells the two apart, and a
        caller that loops on nullptr must consult it. The call always returns control within a
        bounded interval.
        */
        std::unique_ptr<ResultPackage> receive_result(
            std::shared_ptr<seal::SEALContext> context) override;

        /**
        Do not use this function. Use ZMQChannel::receive_network_operation instead.
        */
        std::unique_ptr<SenderOperation> receive_operation(
            std::shared_ptr<seal::SEALContext> context,
            SenderOperationType expected = SenderOperationType::sop_unknown) override;

        /**
        Do not use this function. Use
        ZMQChannel::send(std::unique_ptr<ZMQSenderOperationResponse>) instead.
        */
        void send(std::unique_ptr<SenderOperationResponse> sop_response) override;

        /**
        Do not use this function. Use ZMQChannel::send(std::unique_ptr<ZMQResultPackage>)
        instead.
        */
        void send(std::unique_ptr<ResultPackage> rp) override;

    protected:
        /**
        Get socket type for this channel.
        */
        virtual zmq::socket_type get_socket_type() = 0;

        /**
        Add any needed options for the socket. Called just after socket creation.
        */
        virtual void set_socket_options(zmq::socket_t *socket) = 0;

    private:
        std::unique_ptr<zmq::socket_t> socket_;

        std::string end_point_;

        std::mutex receive_mutex_;

        std::mutex send_mutex_;

        std::unique_ptr<zmq::context_t> context_;

        std::unique_ptr<zmq::socket_t> &get_socket();

        void throw_if_not_connected() const;

        void throw_if_connected() const;

        bool receive_message(zmq::multipart_t &msg, bool wait_for_message = true);

        void send_message(zmq::multipart_t &msg);
    }; // class ZMQChannel

    /**
    Implements a ZMQChannel for a sender.
    */
    class ZMQSenderChannel : public ZMQChannel {
    public:
        /**
        Create an instance of a ZMQSenderChannel.
        */
        ZMQSenderChannel() = default;

        /**
        Destroy an instance of a ZMQSenderChannel.
        */
        ~ZMQSenderChannel() override = default;

    protected:
        /**
        The only difference from a receiver is the socket type.
        */
        zmq::socket_type get_socket_type() override;

        /**
        The sender needs to set a couple of socket options to ensure messages are not dropped.
        */
        void set_socket_options(zmq::socket_t *socket) override;
    };

    /**
    Implements a ZMQChannel for a receiver.
    */
    class ZMQReceiverChannel : public ZMQChannel {
    public:
        /**
        Create an instance of a ZMQReceiverChannel.
        */
        ZMQReceiverChannel() = default;

        /**
        Destroy an instance of a ZMQReceiverChannel.
        */
        ~ZMQReceiverChannel() override = default;

    protected:
        /**
        The only difference from a sender is the socket type.
        */
        zmq::socket_type get_socket_type() override;

        /**
        The receiver needs to set a couple of socket options to ensure messages are not dropped.
        */
        void set_socket_options(zmq::socket_t *socket) override;
    };
} // namespace apsi::network
