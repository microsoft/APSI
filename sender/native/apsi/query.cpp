// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <stdexcept>

// APSI
#include "apsi/psi_params.h"
#include "apsi/query.h"
#include "apsi/logging/log.h"

using namespace std;
using namespace seal;

namespace apsi
{
    using namespace network;

    namespace sender
    {
        Query Query::deep_copy() const
        {
            Query result;
            result.relin_keys_ = relin_keys_;
            result.data_ = data_;
            result.sender_db_ = sender_db_;

            return result;
        }

        Query::Query(QueryRequest query_request, shared_ptr<SenderDB> sender_db)
        {
            if (!sender_db)
            {
                throw invalid_argument("sender_db cannot be null");
            }
            if (!query_request)
            {
                throw invalid_argument("query_request cannot be null");
            }

            sender_db_ = move(sender_db);
            auto seal_context = sender_db_->get_seal_context();

            // Extract and validate relinearization keys 
            relin_keys_ = query_request->relin_keys.extract_local();
            if (!is_valid_for(relin_keys_, *seal_context))
            {
                APSI_LOG_ERROR("Extracted relinearization keys are invalid for SEALContext");
                return;
            }

            // Extract and validate query ciphertexts
            for (auto &q : query_request->data)
            {
                APSI_LOG_DEBUG("Extracting " << q.second.size() << " ciphertexts for exponent " << q.first);
                vector<Ciphertext> cts;
                for (auto &ct : q.second)
                {
                    cts.push_back(ct.extract_local());
                    if (!is_valid_for(cts.back(), *seal_context))
                    {
                        APSI_LOG_ERROR("Extracted ciphertext is invalid for SEALContext");
                        return;
                    }
                }
                data_[q.first] = move(cts);
            }

            // Extract the PowersDag
            pd_ = move(query_request->pd);

            // Get the PSIParams
            PSIParams params(sender_db_->get_params());

            uint32_t bundle_idx_count = params.bundle_idx_count();
            uint32_t max_items_per_bin = params.table_params().max_items_per_bin;
            uint32_t query_powers_count = params.query_params().query_powers_count;

            // Check that the PowersDag is valid and matches the PSIParams
            if (!pd_.is_configured())
            {
                APSI_LOG_ERROR("Extracted PowersDag is not configured");
                return;
            }
            if (pd_.up_to_power() != max_items_per_bin)
            {
                APSI_LOG_ERROR("Extracted PowersDag is incompatible with PSI parameters: "
                    "up_to_power (" << pd_.up_to_power() << ") does not match max_items_per_bin (" <<
                    max_items_per_bin << ")");
                return;
            }
            if (pd_.source_count() != query_powers_count)
            {
                APSI_LOG_ERROR("Extracted PowersDag is incompatible with PSI parameters: "
                    "source_count (" << pd_.source_count() << ") does not match query_power_count (" <<
                    query_powers_count << ")");
                return;
            }

            // Check that the query data size matches the PSIParams
            if (data_.size() != query_powers_count)
            {
                APSI_LOG_ERROR("Extracted query data is incompatible with PSI parameters: "
                    "query contains " << data_.size() << " ciphertext powers which does not match with "
                    "query_power_count (" << query_powers_count << ")");
                return;
            }
            auto query_powers = pd_.source_nodes();
            for (auto &q : data_)
            {
                // Check that powers in the query data match source nodes in the PowersDag
                if (q.second.size() != bundle_idx_count)
                {
                    APSI_LOG_ERROR("Extracted query data is incompatible with PSI parameters: "
                        "query power " << q.first << " contains " << q.second.size() << " ciphertexts which does not "
                        "match with bundle_idx_count (" << bundle_idx_count << ")");
                    return;
                }
                auto where = find_if(query_powers.cbegin(), query_powers.cend(), [&q](auto n) { return n.power == q.first; });
                if (where == query_powers.cend())
                {
                    APSI_LOG_ERROR("Extracted query data is incompatible with PowersDag: "
                        "query power " << q.first << " does not match with a source node in PowersDag");
                    return;
                }
            }

            // The query is valid
            valid_ = true;
        }
    }
}