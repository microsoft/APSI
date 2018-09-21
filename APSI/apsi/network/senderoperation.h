#pragma once

// STD
#include <vector>
#include <map>

// APSI
#include "apsi/apsidefines.h"

// SEAL
#include "seal/publickey.h"
#include "seal/relinkeys.h"
#include "seal/ciphertext.h"


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
        class SenderOperation
        {
        public:
            /**
            Operation type
            */
            SenderOperationType type;
        };

        /**
        Sender Operation: Get Parameters
        */
        class SenderOperationGetParameters : public SenderOperation
        {
        };

        /**
        Sender Operation: Preprocess
        */
        class SenderOperationPreprocess : public SenderOperation
        {
        public:
            /**
            Items to preprocess
            */
            std::vector<apsi::u8> buffer;
        };

        /**
        Sender Operation: Query
        */
        class SenderOperationQuery : public SenderOperation
        {
        public:
            seal::PublicKey public_key;
            seal::RelinKeys relin_keys;
            std::map<apsi::u64, std::vector<seal::Ciphertext>> query;
        };
    }
}
