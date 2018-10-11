#pragma once

namespace apsi
{
    namespace net
    {
        /**
        Receiver implementation for .Net applications
        */
        public ref class Receiver abstract sealed
        {
        public:
            /**
            Connect to a Sender
            */
            static void Connect(System::String^ address, System::Int32 port);

            /**
            Disconnect from a Sender
            */
            static void Disconnect();

            /**
            Whether the Receiver is connected to a Sender
            */
            static bool IsConnected();

            /**
            Execute an item query on a Sender
            */
            static void Query(
                System::Collections::Generic::List<System::UInt64>^ items,
                System::Collections::Generic::List<System::Tuple<System::Boolean, System::UInt64>^>^ result
            );

        private:
            static void ThrowIfConnected();
            static void ThrowIfDisconnected();
        };
    }
}
