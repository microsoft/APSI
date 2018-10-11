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
    unique_ptr<PSIParams> params_;
    unique_ptr<apsi::receiver::Receiver> receiver_;
}


void Receiver::Connect(String^ address, Int32 port)
{
    ThrowIfConnected();

    String^ endpoint = String::Format(gcnew String("tcp://{0}:{1}"), address, port);
    string stdendpoint = msclr::interop::marshal_as<string>(endpoint);

    channel_ = make_unique<ReceiverChannel>();
    channel_->connect(stdendpoint);

    // First thing to do is get parameters
    SenderResponseGetParameters parameters;
    channel_->send_get_parameters();
    channel_->receive(parameters);

    params_ = make_unique<PSIParams>(
        parameters.psiconf_params,
        parameters.table_params,
        parameters.cuckoo_params,
        parameters.seal_params,
        parameters.exfield_params
    );

    // We have to build the Receiver as well
    int threads = System::Environment::ProcessorCount;
    receiver_ = make_unique<apsi::receiver::Receiver>(threads, seal::MemoryPoolHandle::New());
}

void Receiver::Disconnect()
{
    ThrowIfDisconnected();

    channel_->disconnect();
    channel_ = nullptr;
    receiver_ = nullptr;
    params_ = nullptr;
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
    //for 
    auto enumitems = items->GetEnumerator();
    unsigned idx = 0;
    while (enumitems.MoveNext())
    {
        vitems[idx++] = enumitems.Current;
    }

    if (params_->use_oprf())
    {
        receiver_->preprocess(vitems, *channel_);
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
