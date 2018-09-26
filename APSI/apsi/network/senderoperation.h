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
            SenderOperationQuery(const std::string& pub, const std::string& relin, std::map<apsi::u64, std::vector<std::string>>&& queryp)
                : SenderOperation(SOP_query),
                  public_key(pub),
                  relin_keys(relin),
                  query(queryp)
            {}

            virtual ~SenderOperationQuery() = default;

            std::string public_key;
            std::string relin_keys;
            std::map<apsi::u64, std::vector<std::string>> query;
        };
    }
}
