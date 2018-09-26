#pragma once

// STD
#include <vector>
#include <map>
#include <algorithm>

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
            SenderOperation() = delete;
            SenderOperation(SenderOperationType type)
                : type(type)
            {}

            virtual ~SenderOperation() = default;

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
        public:
            SenderOperationGetParameters()
                : SenderOperation(SOP_get_parameters)
            {}

            virtual ~SenderOperationGetParameters() = default;
        };

        /**
        Sender Operation: Preprocess
        */
        class SenderOperationPreprocess : public SenderOperation
        {
        public:
            SenderOperationPreprocess() = delete;
            SenderOperationPreprocess(std::vector<apsi::u8>&& buff)
                : SenderOperation(SOP_preprocess),
                  buffer(buff)
            {}

            virtual ~SenderOperationPreprocess() = default;

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
            SenderOperationQuery() = delete;
            SenderOperationQuery(seal::PublicKey& pub_key, seal::RelinKeys& relin_keys, std::map<apsi::u64, std::vector<seal::Ciphertext>>&& queryp)
                : SenderOperation(SOP_query),
                  public_key(pub_key),
                  relin_keys(relin_keys),
                  query(queryp)
            {}

            virtual ~SenderOperationQuery() = default;

            seal::PublicKey public_key;
            seal::RelinKeys relin_keys;
            std::map<apsi::u64, std::vector<seal::Ciphertext>> query;
        };
    }
}
