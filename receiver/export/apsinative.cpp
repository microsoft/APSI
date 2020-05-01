// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSINative.cpp : Defines the exported functions for the library.
//

// STD
#include <memory>
#include <thread>
#include <vector>

// APSINative
#include "stdafx.h"
#include "apsinative.h"

// APSI
#include "apsi/item.h"
#include "apsi/receiver.h"
#include "apsi/network/receiverchannel.h"


using namespace std;
using namespace apsi;
using namespace apsi::receiver;
using namespace apsi::network;

namespace
{
    unique_ptr<Receiver> receiver_;
    unique_ptr<ReceiverChannel> rec_channel_;
}

APSIEXPORT bool APSICALL ReceiverConnect(char* address, int port)
{
    if (nullptr != receiver_)
        return false;

    unsigned threads = thread::hardware_concurrency();
    receiver_ = make_unique<Receiver>(threads);
    rec_channel_ = make_unique<ReceiverChannel>();

    stringstream ss;
    ss << "tcp://" << address << ":" << port;

    rec_channel_->connect(ss.str());

    // First thing to do is have Receiver configure itself
    receiver_->handshake(*rec_channel_);

    return true;
}

APSIEXPORT void APSICALL ReceiverDisconnect()
{
    rec_channel_->disconnect();

    rec_channel_ = nullptr;
    receiver_ = nullptr;
}

APSIEXPORT bool APSICALL ReceiverIsConnected()
{
    if (nullptr == rec_channel_)
        return false;

    return rec_channel_->is_connected();
}

APSIEXPORT bool APSICALL ReceiverQuery(int length, u64apsi* items, int* result, u64apsi* labels)
{
    if (nullptr == items)
        return false;
    if (nullptr == result)
        return false;
    if (nullptr == labels)
        return false;
    if (length < 0)
        return false;

    vector<Item> apsi_items(length);

    for (int i = 0; i < length; i++)
    {
        apsi_items[i] = items[i];
        result[i] = FALSE;

        if (receiver_->get_params().use_labels())
            labels[i] = 0;
    }

    auto qresult = receiver_->query(apsi_items, *rec_channel_);

    // Result
    for (int i = 0; i < length; i++)
    {
        result[i] = qresult.first[i] ? TRUE : FALSE;

        if (receiver_->get_params().use_labels())
        {
            memcpy(&labels[i], qresult.second[i].data(), sizeof(u64));
        }
    }

    return true;
}
