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
        stringstream stream1;
        stringstream stream2;

        StreamChannel senderchannel(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel receiverchannel(/* istream */ stream2, /* ostream */ stream1);

        receiverchannel.send_get_parameters();
        stream1.seekp(0);

        shared_ptr<SenderOperation> sender_op;
        senderchannel.receive(sender_op);

        ASSERT_EQ(SOP_get_parameters, sender_op->type);
    }

    TEST_F(StreamChannelTests, SendPreprocessTest)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel senderchannel(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel receiverchannel(/* istream */ stream2, /* ostream */ stream1);

        vector<u8> items = { 10, 20, 30, 40, 50 };

        receiverchannel.send_preprocess(items);
        stream1.seekp(0);

        shared_ptr<SenderOperation> sender_op;
        senderchannel.receive(sender_op);

        ASSERT_EQ(SOP_preprocess, sender_op->type);

        shared_ptr<SenderOperationPreprocess> preprocess_op = dynamic_pointer_cast<SenderOperationPreprocess>(sender_op);
        ASSERT_TRUE(nullptr != preprocess_op);

        ASSERT_EQ((size_t)5, preprocess_op->buffer.size());
        ASSERT_EQ(10, preprocess_op->buffer[0]);
        ASSERT_EQ(20, preprocess_op->buffer[1]);
        ASSERT_EQ(30, preprocess_op->buffer[2]);
        ASSERT_EQ(40, preprocess_op->buffer[3]);
        ASSERT_EQ(50, preprocess_op->buffer[4]);
    }

    TEST_F(StreamChannelTests, SendQueryTest)
    {
        stringstream stream1;
        stringstream stream2;
        StreamChannel senderchannel(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel receiverchannel(/* istream */ stream2, /* ostream */ stream1);

        //receiverchannel.send_query()
    }
}
