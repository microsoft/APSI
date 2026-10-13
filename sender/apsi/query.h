// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

// APSI
#include "apsi/network/sender_operation.h"
#include "apsi/powers.h"
#include "apsi/psi_params.h"
#include "apsi/requests.h"
#include "apsi/sender_db.h"

// SEAL
#include "seal/ciphertext.h"
#include "seal/relinkeys.h"

namespace apsi::sender {
    class Query {
    public:
        Query() = default;

        Query(QueryRequest query_request, std::shared_ptr<sender::SenderDB> sender_db);

        [[nodiscard]] Query deep_copy() const;

        Query(const Query &source) = delete;

        // NOLINTNEXTLINE(bugprone-exception-escape): defaulted move; a member move may throw
        Query(Query &&source) = default;

        Query &operator=(const Query &source) = delete;

        Query &operator=(Query &&source) = default;

        [[nodiscard]] bool is_valid() const noexcept
        {
            return valid_;
        }

        explicit operator bool() const noexcept
        {
            return is_valid();
        }

        [[nodiscard]] const seal::RelinKeys &relin_keys() const noexcept
        {
            return relin_keys_;
        }

        [[nodiscard]] auto &data() const noexcept
        {
            return data_;
        }

        [[nodiscard]] const PowersDag &pd() const noexcept
        {
            return pd_;
        }

        [[nodiscard]] std::shared_ptr<sender::SenderDB> sender_db() const noexcept
        {
            return sender_db_;
        }

        [[nodiscard]] seal::compr_mode_type compr_mode() const noexcept
        {
            return compr_mode_;
        }

        /**
        Returns the fingerprint of the parameters the receiver created the query for (see
        PSIParams::fingerprint), or std::nullopt if the query carries none, as queries from
        receivers before APSI 2.0 do not.
        */
        [[nodiscard]] const std::optional<PSIParams::Fingerprint> &params_fingerprint()
            const noexcept
        {
            return params_fingerprint_;
        }

        /**
        Returns true if the query's parameter fingerprint allows running the query against a
        SenderDB with the given parameters, and otherwise logs why not and returns false. A query
        with a fingerprint is allowed only if it equals params.fingerprint(). A query without one
        is allowed only if receivers before APSI 2.0 can use the parameters. The constructor checks
        this against the parameters of the SenderDB; Sender::RunQuery checks it again in case the
        SenderDB has been replaced since.
        */
        [[nodiscard]] bool check_params_fingerprint(const PSIParams &params) const;

    private:
        seal::RelinKeys relin_keys_;

        std::unordered_map<std::uint32_t, std::vector<seal::Ciphertext>> data_;

        PowersDag pd_;

        std::shared_ptr<sender::SenderDB> sender_db_;

        bool valid_ = false;

        seal::compr_mode_type compr_mode_ = seal::compr_mode_type::none;

        std::optional<PSIParams::Fingerprint> params_fingerprint_;
    };
} // namespace apsi::sender
