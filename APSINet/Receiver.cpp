#include "stdafx.h"

// STD
#include <string>

// CLR
#include <msclr/marshal_cppstd.h>

// APSI
#include "Receiver.h"
//#include "apsi/"


using namespace std;
using namespace System;
using namespace System::Collections::Generic;
using namespace apsi;
using namespace apsi::net;


void Receiver::Connect(String^ address, Int32 port)
{
    String^ endpoint = String::Format(gcnew String("tcp://{0}:{1}"), address, port);
    string stdendpoint = msclr::interop::marshal_as<string>(endpoint);
}

void Receiver::Disconnect()
{

}

bool Receiver::IsConnected()
{
    return false;
}

void Receiver::Query(
    List<UInt64>^ items,
    List<Tuple<Boolean, UInt64>^>^ result
)
{
}
