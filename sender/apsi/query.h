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

        /**
        Creates a query to run against the given SenderDB, checking the query request against the
        SenderDB's parameters. A query that fails a check is logged and left invalid: is_valid
        returns false, and Sender::RunQuery refuses it. The checks come in this order: the
        parameter fingerprint (see check_params_fingerprint); the relinearization keys; that the
        query holds exactly the source powers the parameters call for, each with one ciphertext per
        bundle index; and then that each ciphertext is a fresh encryption valid for the SenderDB's
        SEALContext.

        A query request that SenderOperationQuery::load read holds its ciphertexts in serialized
        form. Each is loaded only in the last step, once the number of ciphertexts is known to be
        right, and checked as soon as it is loaded. The ciphertexts are loaded on the calling
        thread if ThreadPoolMgr::GetThreadCount() is one, as it is under a ScopedParallelismLimit
        of one, or if the calling thread is a task of the thread pool, and otherwise by up to that
        many tasks on the thread pool, one for each ciphertext at most, which take them in the
        order of the query data and take no other once one has failed. An invalid query can
        therefore make the sender load no more ciphertexts than a valid one holds, and at most one
        invalid one for each task. The failure logged is that of the first ciphertext to fail in
        the order of the query data, as when they are loaded one at a time. A ciphertext held in
        serialized form that takes less than 1/64 of the bytes a fresh encryption loads to, or
        whose data is not a ciphertext at all, leaves the query invalid like any other failed
        check.

        Throws std::invalid_argument if query_request or sender_db is null.
        */
        Query(QueryRequest query_request, std::shared_ptr<sender::SenderDB> sender_db);

        /**
        Returns a copy of this Query, valid exactly when this one is, with copies of its
        relinearization keys and ciphertexts. The copy shares the SenderDB of this Query.
        */
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
