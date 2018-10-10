#pragma once

using namespace System;

namespace apsi
{
    namespace net
    {
        public ref class Receiver
        {
        public:
            void Connect(System::String^ address, System::Int32 port);
            void Disconnect();
            bool IsConnected();

            void Query(
                System::Collections::Generic::List<System::UInt64>^ items,
                System::Collections::Generic::List<System::Tuple<System::Boolean, System::UInt64>^>^ result
            );

        private:

        };
    }
}
