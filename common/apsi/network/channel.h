// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

// APSI
#include "apsi/network/result_package.h"
#include "apsi/network/sender_operation.h"
#include "apsi/network/sender_operation_response.h"

// SEAL
#include "seal/util/defines.h"

namespace apsi::network {
    /**
    Channel is an interfacate to implement a communication channel between a sender and a
    receiver. It keeps track of the number of bytes sent and received.

    A receive call may block, and Channel itself makes no promise about for how long: a channel
    built on a plain stream, as network::StreamChannel is, blocks inside the stream's own read
    and returns only when that read does. The stronger obligation belongs to
    network::NetworkChannel, which is what the receiver's simple API accepts. A receive on one of
    those must return control to the caller within a bounded interval regardless of what the peer
    does, for example by setting a receive timeout on the underlying socket as
    network::ZMQChannel does. When nothing has arrived within that interval the call returns
    nullptr without recording a failure, and the caller decides whether to ask again. Callers
    enforce their own deadlines between receive calls and have no way to interrupt one already in
    progress, so an implementation that blocks indefinitely inside a receive leaves the caller
    waiting for as long as the peer stays silent.

    Implementations must tolerate concurrent calls. A receiver runs several result workers at
    once, all calling receive_result on the same channel, and a sender sends result packages from
    several tasks at once. The channels shipped with APSI serialize sends and receives
    internally; a channel written elsewhere has to do the same, and so does any send callback
    passed to sender::Sender, which is invoked from those same concurrent tasks.
    */
    class Channel {
    public:
        /**
        Create an instance of a Channel.
        */
        Channel() : bytes_sent_(0), bytes_received_(0)
        {}

        /**
        Destroy an instance of a Channel.
        */
        virtual ~Channel() = default;

        /**
        Send a SenderOperation from a receiver to a sender. These operations represent either a
        parameter request, an OPRF request, or a query request. The function throws an exception
        on failure.
        */
        virtual void send(std::unique_ptr<SenderOperation> sop) = 0;

        /**
        Receive a SenderOperation from a receiver. Operations of type sop_query and sop_unknown
        require a valid seal::SEALContext to be provided. For operations of type sop_parms and
        sop_oprf the context can be set as nullptr. The function returns nullptr on failure, and
        also returns nullptr without failing if the channel is operating in a non-blocking mode
        and no message has arrived yet. Use receive_failed to tell the two apart. See the note on
        Channel for the bounded-blocking requirement.
        */
        virtual std::unique_ptr<SenderOperation> receive_operation(
            std::shared_ptr<seal::SEALContext> context,
            SenderOperationType expected = SenderOperationType::sop_unknown) = 0;

        /**
        Send a SenderOperationResponse from a sender to a receiver. These operations represent a
        response to either a parameter request, an OPRF request, or a query request. The
        function throws and exception on failure.
        */
        virtual void send(std::unique_ptr<SenderOperationResponse> sop_response) = 0;

        /**
        Receive a SenderOperationResponse from a sender. The function returns nullptr on
        failure, and also returns nullptr without failing if no message has arrived yet. Use
        receive_failed to tell the two apart. Pass the expected operation type whenever it is
        known: a response of any other type is then rejected by the channel and recorded as a
        failure, instead of being silently discarded. See the note on Channel for the
        bounded-blocking requirement.
        */
        virtual std::unique_ptr<SenderOperationResponse> receive_response(
            SenderOperationType expected = SenderOperationType::sop_unknown) = 0;

        /**
        Send a ResultPackage to a receiver. The function throws and exception on failure.
        */
        virtual void send(std::unique_ptr<ResultPackage> rp) = 0;

        /**
        Receive a ResultPackage from a sender. A valid seal::SEALContext must be provided. The
        function returns nullptr on failure, and also returns nullptr without failing if no
        message has arrived yet. Use receive_failed to tell the two apart. See the note on Channel
        for the bounded-blocking requirement.
        */
        virtual std::unique_ptr<ResultPackage> receive_result(
            std::shared_ptr<seal::SEALContext> context) = 0;

        /**
        Returns true if a receive call has failed in a way that retrying cannot repair. There
        are two such cases: the channel took a message off the wire and could not turn it into a
        valid object, and the channel was asked for something it can never produce, such as a
        result package without a seal::SEALContext. In the first case the consumed bytes are
        gone; the peer has already sent them and will not send them again.

        This exists because a null return alone does not say whether waiting longer is
        worthwhile. A caller that loops on a null return must consult this on every iteration and
        stop looping once it is true, or a single malformed message will make it wait forever for
        data that no longer exists.

        The flag is sticky, so a channel that has failed once reports failure from then on. That
        suits a receiver, which drives one exchange from start to finish. A sender serving many
        independent peers over one channel should not consult it: it must survive a malformed
        message from any one peer and keep serving the rest. Such a sender wants
        receive_failure_count instead.
        */
        bool receive_failed() const noexcept
        {
            return receive_failure_count() > 0;
        }

        /**
        Returns how many times a receive has consumed a message and rejected it, or failed for
        good in any of the other ways described on receive_failed.

        This is the non-sticky form of the same information, for a caller that must keep serving
        after a failure and so cannot use a flag that never clears. Comparing the count across a
        receive call answers a question a null return cannot: whether the call ended in a failure
        or in an empty poll. A caller that backs off when nothing arrives needs that distinction,
        or a peer sending a stream of rubbish makes it back off once per rejected message and
        throttles everyone else it serves. A rise in the count does not by itself mean a message
        was consumed: a receive asked for something it can never produce raises it without
        reading the socket at all.
        */
        std::uint64_t receive_failure_count() const noexcept
        {
            return receive_failure_count_;
        }

        /**
        Returns the number of bytes sent on the channel.
        */
        std::uint64_t bytes_sent() const
        {
            return bytes_sent_;
        }

        /**
        Returns the number of bytes received on the channel.
        */
        std::uint64_t bytes_received() const
        {
            return bytes_received_;
        }

    protected:
        /**
        Records the failure that receive_failed and receive_failure_count report. Implementations
        call this on every path that returns nullptr other than the one meaning "nothing has
        arrived yet"; that one path is the only kind of null return a caller may retry.
        */
        void set_receive_failed() noexcept
        {
            receive_failure_count_++;
        }

        std::atomic<std::uint64_t> bytes_sent_;

        std::atomic<std::uint64_t> bytes_received_;

    private:
        std::atomic<std::uint64_t> receive_failure_count_{ 0 };
    }; // class Channel
} // namespace apsi::network
