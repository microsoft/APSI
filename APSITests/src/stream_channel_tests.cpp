// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#include "gtest/gtest.h"
#include "apsi/network/stream_channel.h"

using namespace std;
using namespace apsi;
using namespace apsi::network;

namespace APSITests
{
    class StreamChannelTests : public ::testing::Test
    {
    protected:
        StreamChannelTests()
        {
        }

        ~StreamChannelTests()
        {
        }
    };

    TEST_F(StreamChannelTests, SendGetParametersTest)
    {
        stringstream soutput;
        stringstream sinput;

        StreamChannel choutput(soutput, soutput);
        StreamChannel chinput(sinput, sinput);

        choutput.send_get_parameters();

        shared_ptr<SenderOperation> sender_op;
        chinput.receive(sender_op);

        ASSERT_EQ(SOP_preprocess, sender_op->type);
    }
}
