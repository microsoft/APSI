#pragma once

// STD
#include <vector>

// APSI
#include "apsi/apsidefines.h"

namespace apsi
{
    namespace network
    {
        enum SenderOperationType
        {
            SOP_get_parameters = 1,
            SOP_preprocess = 2,
            SOP_query = 3
        };

        /**
        Generic Sender Operation
        */
        struct SenderOperation
        {
            /**
            Operation type
            */
            SenderOperationType type;

            /**
            Get the size of the data in the structure
            */
            virtual apsi::u64 get_size() const = 0;
        };

        /**
        Sender Operation: Get Parameters
        */
        struct SenderOperationGetParameters : SenderOperation
        {
            /**
            Get the size of the data in the structure
            */
            virtual apsi::u64 get_size() const
            {
                // The request does not contain any data.
                return 0;
            }
        };

        /**
        Sender Operation: Preprocess
        */
        struct SenderOperationPreprocess : SenderOperation
        {
        };

        /**
        Sender Operation: Query
        */
        struct SenderOperationQuery : SenderOperation
        {
        };
    }
}
