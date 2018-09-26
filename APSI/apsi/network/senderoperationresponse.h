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
        Generic Sender Response
        */
        class SenderResponse
        {
        public:
            SenderResponse() = default;
            virtual ~SenderResponse() = default;
        };

        /**
        Response for Get Parameters request
        */
        class SenderResponseGetParameters : public SenderResponse
        {
        public:
            SenderResponseGetParameters() = default;
            virtual ~SenderResponseGetParameters() = default;

            int sender_bin_size;
        };

        /**
        Response for Preprocess request
        */
        class SenderResponsePreprocess : public SenderResponse
        {
        public:
            SenderResponsePreprocess() = default;
            virtual ~SenderResponsePreprocess() = default;

            std::vector<apsi::u8> buffer;
        };

        /**
        Response for Query request
        */
        class SenderResponseQuery : public SenderResponse
        {
        public:
            SenderResponseQuery() = default;
            virtual ~SenderResponseQuery() = default;

            std::vector<apsi::ResultPackage> result;
        };
    }
}
