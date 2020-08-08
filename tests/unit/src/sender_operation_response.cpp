// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <sstream>
#include <vector>

// APSI
#include "apsi/network/sender_operation_response.h"

#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::network;

namespace APSITests
{
    TEST(SenderOperationResponseTest, SaveLoadSenderOperationResponseParms)
    {
        SenderOperationResponseParms sopr;
        ASSERT_EQ(SenderOperationType::SOP_PARMS, sopr.type());
        ASSERT_FALSE(sopr.params);

        stringstream ss;

        // Cannot save if parameters are not set
        ASSERT_THROW(auto out_size = sopr.save(ss), logic_error);
    }
}
