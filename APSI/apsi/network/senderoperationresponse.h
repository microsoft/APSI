#pragma once

// APSI
#include "apsi/apsidefines.h"

namespace apsi
{
    namespace network
    {
        /**
        Generic Sender Response
        */
        struct SenderResponse
        {
            /**
            Get the size of the data in the structure
            */
            virtual apsi::u64 get_size() const = 0;
        };

        /**
        Response for Get Parameters request
        */
        struct SenderResponseGetParameters : SenderResponse
        {
            int sender_bin_size;

            virtual apsi::u64 get_size() const
            {
                return sizeof(int);
            }
        };

        /**
        Response for Preprocess request
        */
        struct SenderResponsePreprocess : SenderResponse
        {
            virtual apsi::u64 get_size() const
            {
                return 0;
            }
        };

        /**
        Response for Query request
        */
        struct SenderResponseQuery : SenderResponse
        {
            virtual apsi::u64 get_size() const
            {
                return 0;
            }
        };
    }
}
