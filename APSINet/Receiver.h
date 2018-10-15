#pragma once

// STD
#include <memory>

// APSI
#include "apsi/network/receiverchannel.h"
#include "apsi/receiver/receiver.h"

namespace apsi
{
    namespace net
    {
        /**
        Receiver implementation for .Net applications
        */
        public ref class Receiver
        {
        public:
            /**
            Constructor
            */
            Receiver();

            /**
            Destructor
            */
            ~Receiver();

            /**
            Connect to a Sender
            */
            void Connect(System::String^ address, System::Int32 port);

            /**
            Disconnect from a Sender
            */
            void Disconnect();

            /**
            Whether the Receiver is connected to a Sender
            */
            bool IsConnected();

            /**
            Execute an item query on a Sender
            */
            System::Collections::Generic::IEnumerable<System::Tuple<System::Boolean, System::UInt64>^>^
                Query(
                System::Collections::Generic::IEnumerable<System::UInt64>^ items
                    );

        private:
            apsi::network::ReceiverChannel* channel_;
            apsi::receiver::Receiver* receiver_;

            void ThrowIfConnected();
            void ThrowIfDisconnected();
        };
    }
}
