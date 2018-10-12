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
#include "apsi/network/receiverchannel.h"
#include "apsi/receiver/receiver.h"


using namespace std;
using namespace System;
using namespace System::Collections::Generic;
using namespace apsi;
using namespace apsi::net;
using namespace apsi::network;

namespace
{
    unique_ptr<ReceiverChannel> channel_;
    unique_ptr<apsi::receiver::Receiver> receiver_;
}


void Receiver::Connect(String^ address, Int32 port)
{
    ThrowIfConnected();

    String^ endpoint = String::Format(gcnew String("tcp://{0}:{1}"), address, port);
    string stdendpoint = msclr::interop::marshal_as<string>(endpoint);

    channel_ = make_unique<ReceiverChannel>();
    channel_->connect(stdendpoint);

    // Build the Receiver
    int threads = System::Environment::ProcessorCount;
    receiver_ = make_unique<apsi::receiver::Receiver>(threads);
}

void Receiver::Disconnect()
{
    ThrowIfDisconnected();

    channel_->disconnect();
    channel_ = nullptr;
    receiver_ = nullptr;
}

bool Receiver::IsConnected()
{
    if (channel_ == nullptr)
        return false;
    
    return channel_->is_connected();
}

void Receiver::Query(
    List<UInt64>^ items,
    List<Tuple<Boolean, UInt64>^>^ result
)
{
    ThrowIfDisconnected();

    // Convert list to vector
    vector<Item> vitems(items->Count);
    auto enumitems = items->GetEnumerator();
    unsigned idx = 0;
    while (enumitems.MoveNext())
    {
        vitems[idx++] = enumitems.Current;
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
