#include "stdafx.h"

// STD
#include <string>
#include <memory>
#include <vector>

// CLR
#include <msclr/marshal_cppstd.h>

// APSI
#include "Receiver.h"
#include "apsi/item.h"


using namespace std;
using namespace System;
using namespace System::Collections::Generic;
using namespace apsi;
using namespace apsi::net;
using namespace apsi::network;


Receiver::Receiver()
    : channel_(nullptr),
      receiver_(nullptr)
{
}

Receiver::~Receiver()
{
    Disconnect();
}

void Receiver::Connect(String^ address, Int32 port)
{
    ThrowIfConnected();

    String^ endpoint = String::Format(gcnew String("tcp://{0}:{1}"), address, port);
    string stdendpoint = msclr::interop::marshal_as<string>(endpoint);

    channel_ = new ReceiverChannel();
    channel_->connect(stdendpoint);

    // Build the Receiver
    int threads = System::Environment::ProcessorCount;
    receiver_ = new receiver::Receiver(threads);

    // Perform the handshake
    receiver_->handshake(*channel_);
}

void Receiver::Disconnect()
{
    // Disconnect if connected.
    if (IsConnected())
    {
        channel_->disconnect();
    }

    delete receiver_;
    delete channel_;
    receiver_ = nullptr;
    channel_ = nullptr;
}

bool Receiver::IsConnected()
{
    if (channel_ == nullptr)
        return false;
    
    return channel_->is_connected();
}

IEnumerable<Tuple<Boolean, UInt64>^>^ Receiver::Query(
    IEnumerable<UInt64>^ items
    )
{
    ThrowIfDisconnected();

    List<Tuple<Boolean, UInt64>^>^ result = gcnew List<Tuple<Boolean, UInt64>^>();

    // Convert list to vector
    vector<Item> vitems;
    auto enumitems = items->GetEnumerator();
    unsigned idx = 0;
    while (enumitems->MoveNext())
    {
        vitems.push_back(enumitems->Current);
    }

    // Query the Sender
    auto qresult = receiver_->query(vitems, *channel_);
    result->Clear();

    for (u64 i = 0; i < qresult.first.size(); i++)
    {
        u64 value = 0;
        if (receiver_->get_params().use_labels())
        {
            auto label = qresult.second[i];
            memcpy(&value, label.data(), sizeof(u64));
        }

        Tuple<Boolean, UInt64>^ tup = gcnew Tuple<Boolean, UInt64>(qresult.first[i], value);
        result->Add(tup);
    }

    return result;
}

void Receiver::ThrowIfConnected()
{
    if (channel_ != nullptr && channel_->is_connected())
        throw gcnew InvalidOperationException("Should not be connected.");
}

void Receiver::ThrowIfDisconnected()
{
    if (channel_ == nullptr || !channel_->is_connected())
        throw gcnew InvalidOperationException("Should be connected.");
}
