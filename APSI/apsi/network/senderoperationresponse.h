#pragma once

// STD
#include <vector>

// APSI
#include "apsi/apsidefines.h"
#include "apsi/result_package.h"

namespace apsi
{
    namespace network
    {
        /**
        Response for Get Parameters request
        */
        struct SenderResponseGetParameters
        {
            int sender_bin_size;
        };

        /**
        Response for Preprocess request
        */
        struct SenderResponsePreprocess
        {
            std::vector<apsi::u8> buffer;
        };

        /**
        Response for Query request
        */
        struct SenderResponseQuery
        {
            std::vector<apsi::ResultPackage> result;
        };
    }
}
