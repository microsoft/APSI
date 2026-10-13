// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

// SEAL
#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/util/defines.h"

// APSI
#include "apsi/crypto_context.h"
#include "apsi/psi_params.h"
#include "apsi/seal_object.h"

namespace apsi::network {
    /**
    Stores a decrypted and decoded PSI response and optionally a labeled PSI response. For
    parameters with match tags, psi_result is empty and label_result holds the tag parts followed
    by the label parts.
    */
    struct PlainResultPackage {
        std::uint32_t bundle_idx{};

        std::vector<std::uint64_t> psi_result;

        std::uint32_t label_byte_count{};

        std::uint32_t nonce_byte_count{};

        std::vector<std::vector<std::uint64_t>> label_result;
    };

    /**
    Stores a PSI response and optionally labeled PSI response ciphertexts.

    For parameters without match tags, a ResultPackage holds the result of a bin bundle's matching
    polynomial in psi_result and, if the sender's items have labels, the results of its label
    polynomials in label_result. For parameters with match tags (see PSIParams::uses_tags), it
    holds no psi_result, and label_result holds the results of the tag parts followed by the
    results of the label parts, if any.
    */
    class ResultPackage {
    public:
        /**
        Writes the ResultPackage to a stream. An empty psi_result is left out, as it is for
        parameters with match tags.
        */
        std::size_t save(std::ostream &out) const;

        /**
        Reads the ResultPackage from a stream. A package without a PSI result loads with an empty
        psi_result; whether one is expected depends on the parameters, which this overload does not
        know. Use the overload with parameters to have the structure checked.

        Before any ciphertext is loaded, a package is refused with std::runtime_error if it has more
        label parts than any parameters allow for its label and nonce byte counts, if its
        ciphertexts share bytes, which FlatBuffers allows but no sender writes, or if together they
        take less than 1/64 of what they load to, counting each as a ciphertext of size 2 at the
        last level of the modulus chain. Every ciphertext must then have the shape a sender gives
        its results: coefficient form, the last level of the modulus chain, and size 2 or 3.
        Loading throws std::runtime_error at the first that does not, before the next is loaded.
        */
        std::size_t load(std::istream &in, const std::shared_ptr<seal::SEALContext> &context);

        /**
        Reads the ResultPackage from a stream as a result of a query made with the given
        parameters. For parameters with match tags, the structure check_tag_structure describes is
        verified on the serialized package before any ciphertext in it is loaded, and a package
        without it is refused with std::runtime_error, so that one which cannot be a result for
        these parameters costs no work beyond reading it. For parameters without match tags, a
        package is refused with std::runtime_error in the same way if it has no PSI result, as the
        APSI 1.x schema refused it, if it is for a bundle index the parameters do not have, or if
        it has more label parts than its label and nonce take. Otherwise this checks and loads the
        package as the other overload does.
        */
        std::size_t load(
            std::istream &in,
            const std::shared_ptr<seal::SEALContext> &context,
            const PSIParams &params);

        /**
        For parameters with match tags, throws std::runtime_error unless this package has the
        structure every result for them has: a bundle index below params.bundle_idx_count(), no
        psi_result, a label_byte_count and nonce_byte_count within their bounds, no nonce without
        a label, and exactly params.tag_part_count() + P ciphertexts in label_result, where P is
        the number of item-sized parts the nonce and label take together, or zero without a
        label. For parameters without match tags this checks nothing. The overload of load that
        takes the parameters refuses a package for a bundle index the parameters do not have, or
        with more label parts than its label and nonce take; the receiver ignores a package loaded
        otherwise for a bundle index the parameters do not have, as in APSI 1.x.
        */
        void check_tag_structure(const PSIParams &params) const;

        /**
        Decrypts and decodes the whole result: psi_result, if present, and every ciphertext in
        label_result, which is then cleared. Noise budgets are logged at debug level.
        */
        PlainResultPackage extract(const CryptoContext &crypto_context);

        /**
        Decrypts and decodes the first tag_part_count ciphertexts in label_result, which hold the
        tag parts of a result for parameters with match tags, and returns their slot values in
        order. Their noise budgets are logged at debug level as tag results.

        The ciphertexts decrypted are moved out of label_result and cannot be decrypted again.
        Together with extract_label_result, this decrypts every ciphertext of a result with match
        tags. Throws std::invalid_argument if label_result holds fewer than tag_part_count
        ciphertexts.
        */
        std::vector<std::vector<std::uint64_t>> extract_tag_result(
            const CryptoContext &crypto_context, std::size_t tag_part_count);

        /**
        Decrypts and decodes the ciphertexts in label_result that follow the first
        tag_part_count, which hold the label parts of a result, and returns their slot values in
        order. Their noise budgets are logged at debug level as label results. With
        tag_part_count zero, as for parameters without match tags, this decrypts every ciphertext
        in label_result.

        The ciphertexts decrypted are moved out of label_result and cannot be decrypted again.
        Throws std::invalid_argument if label_result holds fewer than tag_part_count
        ciphertexts.
        */
        std::vector<std::vector<std::uint64_t>> extract_label_result(
            const CryptoContext &crypto_context, std::size_t tag_part_count);

        std::uint32_t bundle_idx{};

        seal::compr_mode_type compr_mode = seal::Serialization::compr_mode_default;

        SEALObject<seal::Ciphertext> psi_result;

        std::uint32_t label_byte_count{};

        std::uint32_t nonce_byte_count{};

        std::vector<SEALObject<seal::Ciphertext>> label_result;
    }; // struct ResultPackage
} // namespace apsi::network
