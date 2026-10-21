// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

// APSI
#include "apsi/psi_params.h"
#include "apsi/seal_object.h"
#include "apsi/version.h"

// SEAL
#include "seal/ciphertext.h"
#include "seal/relinkeys.h"
#include "seal/serialization.h"
#include "seal/util/common.h"

// GSL
#include "gsl/span"

namespace apsi::network {
    enum class SenderOperationType : std::uint32_t {
        sop_unknown = 0,

        sop_parms = 1,

        sop_oprf = 2,

        sop_query = 3,
    };

    const char *sender_operation_type_str(SenderOperationType sop_type);

    /**
    Returns the name of a Microsoft SEAL compression mode: "none", "zlib", "zstd", or "bitpack". A
    value that is not a compression mode this build of Microsoft SEAL supports is reported as
    "unsupported".
    */
    const char *compr_mode_str(seal::compr_mode_type compr_mode) noexcept;

    /**
    A class describing the type of a SenderOperation object and an optional member to identify
    the client.
    */
    class SenderOperationHeader {
    public:
        std::size_t save(std::ostream &out) const;

        std::size_t load(std::istream &in);

        std::uint32_t version = apsi_serialization_version;

        SenderOperationType type = SenderOperationType::sop_unknown;
    };

    /**
    An abstract base class representing a sender operation.
    */
    class SenderOperation {
    public:
        SenderOperation() = default;

        /**
        Destroys the SenderOperation.
        */
        virtual ~SenderOperation() = default;

        /**
        Writes the SenderOperation to a stream.
        */
        virtual std::size_t save(std::ostream &out) const = 0;

        /**
        Reads the SenderOperation from a stream.
        */
        virtual std::size_t load(
            std::istream &in, std::shared_ptr<seal::SEALContext> context = nullptr) = 0;

        /**
        Returns the type of the SenderOperation.
        */
        [[nodiscard]] virtual SenderOperationType type() const noexcept = 0;
    }; // class SenderOperation

    /**
    A kind of SenderOperation for representing a parameter request from the receiver.
    */
    class SenderOperationParms final : public SenderOperation {
    public:
        std::size_t save(std::ostream &out) const override;

        std::size_t load(
            std::istream &in, std::shared_ptr<seal::SEALContext> context = nullptr) override;

        [[nodiscard]] SenderOperationType type() const noexcept override
        {
            return SenderOperationType::sop_parms;
        }
    }; // class SenderOperationParms

    /**
    A kind of SenderOperation for representing an OPRF query from the receiver.
    */
    class SenderOperationOPRF final : public SenderOperation {
    public:
        std::size_t save(std::ostream &out) const override;

        std::size_t load(
            std::istream &in, std::shared_ptr<seal::SEALContext> context = nullptr) override;

        [[nodiscard]] SenderOperationType type() const noexcept override
        {
            return SenderOperationType::sop_oprf;
        }

        /**
        Holds the OPRF query data.
        */
        std::vector<unsigned char> data;
    }; // class SenderOperationOPRF

    /**
    A kind of SenderOperation for representing a PSI or labeled PSI query from the receiver.
    */
    class SenderOperationQuery final : public SenderOperation {
    public:
        std::size_t save(std::ostream &out) const override;

        /**
        Reads a query from a stream. If the given SEALContext uses key switching, the
        relinearization keys are loaded and validated against it, and refused unless they are
        exactly one key set, as KeyGenerator::create_relin_keys makes them; their dimensions are
        read and checked before any key is loaded, so keys that declare more are refused without
        being loaded. The ciphertexts are not loaded: each is held in serialized form (see
        SEALObject::set_serialized) until sender::Query extracts it, which it does only once it has
        checked that the query holds as many as the parameters call for. A ciphertext that is not
        valid for the SEALContext is therefore not detected here but when it is extracted, and
        sender::Query then reports the query as invalid. Holding the ciphertexts copies their bytes,
        so a query whose ciphertexts share bytes, which FlatBuffers allows but no receiver writes,
        is refused as soon as the copies would add up to more than the query.

        Throws std::invalid_argument if context is null or its parameters are not set, and
        std::runtime_error if the stream does not hold a valid query.
        */
        std::size_t load(std::istream &in, std::shared_ptr<seal::SEALContext> context) override;

        [[nodiscard]] SenderOperationType type() const noexcept override
        {
            return SenderOperationType::sop_query;
        }

        /**
        Reads the parameter fingerprint from a serialized query without loading the rest of it.

        An application serving several SenderDBs can use this to find the one a query is for
        before calling SenderOperationQuery::load, which needs that SenderDB's SEALContext and
        loads and validates the relinearization keys in the query. The fingerprint identifies
        parameters, not a SenderDB, so this tells apart only SenderDBs with different parameters,
        and the receiver's OPRF request must still go to the same SenderDB as its query. The input
        is a query as SenderOperation::save writes it: a size-prefixed buffer, without the
        SenderOperationHeader that a network::Channel sends in front of it. Any bytes after the
        buffer are ignored.

        Returns std::nullopt for a query without a fingerprint, such as one from an APSI 1.x
        receiver.

        Throws std::runtime_error if in does not hold a valid serialized query, or if the
        fingerprint in it has the wrong size.
        */
        [[nodiscard]] static std::optional<PSIParams::Fingerprint> ExtractParamsFingerprint(
            gsl::span<const unsigned char> in);

        /**
        The compression mode for the relinearization keys and the ciphertexts in the query. The
        sender saves the result packages for the query in the same mode.
        */
        seal::compr_mode_type compr_mode = seal::Serialization::compr_mode_default;

        SEALObject<seal::RelinKeys> relin_keys;

        /**
        Holds the encrypted query data. In the map the key labels the exponent of the query
        ciphertext and the vector holds the ciphertext data for different bundle indices. After
        load, each ciphertext is held in serialized form, and SEALObject::extract loads it.
        */
        std::unordered_map<std::uint32_t, std::vector<SEALObject<seal::Ciphertext>>> data;

        /**
        The fingerprint of the parameters the query was created for (see PSIParams::fingerprint),
        or std::nullopt for a query without one. Receivers since APSI 2.0 always set it, and a
        sender uses it to refuse queries meant for other parameters. A query without a
        fingerprint is saved exactly as an APSI 1.x receiver saves it.
        */
        std::optional<PSIParams::Fingerprint> params_fingerprint;
    }; // class SenderOperationQuery
} // namespace apsi::network
