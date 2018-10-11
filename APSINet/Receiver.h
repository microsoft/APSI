#pragma once

namespace apsi
{
    namespace net
    {
        public ref class Receiver
        {
        public:
            static void Connect(System::String^ address, System::Int32 port);
            static void Disconnect();
            static bool IsConnected();

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
