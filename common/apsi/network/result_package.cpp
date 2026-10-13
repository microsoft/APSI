// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <sstream>
#include <stdexcept>
#include <thread>

// APSI
#include "apsi/item.h"
#include "apsi/log.h"
#include "apsi/network/result_package.h"
#include "apsi/network/result_package_generated.h"
#include "apsi/network/sender_operation.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/common.h"

// GSL
#include "gsl/span"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi::network {
    namespace {
        // Upstream limit on the per-item label_byte_count field. SenderDB enforces the same
        // 1024-byte maximum at construction, so an honest sender never produces a larger value.
        // Labels longer than this are rejected on the load path.
        constexpr std::size_t max_label_byte_count = 1024;

        /**
        Decrypts and decodes a result ciphertext, logging its noise budget at debug level under
        the given description. The ciphertext is moved out of ct.
        */
        vector<uint64_t> decrypt_and_decode(
            const CryptoContext &crypto_context, SEALObject<Ciphertext> &ct, const char *what)
        {
            Ciphertext result_ct = ct.extract(crypto_context.seal_context());
            Plaintext result_pt;
            crypto_context.decryptor()->decrypt(result_ct, result_pt);
            APSI_LOG_DEBUG(
                what << ": " << crypto_context.decryptor()->invariant_noise_budget(result_ct)
                     << " bits [" << this_thread::get_id() << "]");

            vector<uint64_t> result;
            crypto_context.encoder()->decode(result_pt, result);
            return result;
        }

        /**
        Throws std::runtime_error unless a result package with the given properties has the
        structure a result for the given parameters, which use match tags, must have. Every check
        works on plain integers, so it can run on a serialized package before any of its
        ciphertexts are loaded, and on a loaded one alike.
        */
        void check_tag_result_structure(
            const PSIParams &params,
            uint64_t bundle_idx,
            bool has_psi_result,
            uint64_t label_byte_count,
            uint64_t nonce_byte_count,
            uint64_t label_part_count)
        {
            if (bundle_idx >= params.bundle_idx_count()) {
                stringstream ss;
                ss << "result package is for bundle index " << bundle_idx
                   << " but the parameters have only " << params.bundle_idx_count();
                throw runtime_error(ss.str());
            }
            if (has_psi_result) {
                throw runtime_error(
                    "result package has a PSI result, which parameters with match tags rule out");
            }
            if (label_byte_count > max_label_byte_count) {
                throw runtime_error("result package has too large a label_byte_count");
            }
            if (nonce_byte_count > max_nonce_byte_count) {
                throw runtime_error("result package has too large a nonce_byte_count");
            }
            if (!label_byte_count && nonce_byte_count) {
                throw runtime_error("result package has a nonce_byte_count but no label");
            }

            // The tag parts are followed by the parts of the encrypted label, if there is one,
            // exactly as many as SenderDB stores. The byte counts are bounded above, so none of
            // this can overflow.
            uint64_t payload_part_count = 0;
            if (label_byte_count) {
                uint64_t item_bit_count = params.item_bit_count();
                payload_part_count =
                    (((nonce_byte_count + label_byte_count) * 8) + item_bit_count - 1) /
                    item_bit_count;
            }
            uint64_t expected_part_count = params.tag_part_count() + payload_part_count;
            if (label_part_count != expected_part_count) {
                stringstream ss;
                ss << "result package has " << label_part_count << " label parts but "
                   << expected_part_count << " are expected";
                throw runtime_error(ss.str());
            }
        }

        /**
        Reads a ResultPackage from a stream into result_package. If params is not null and uses
        match tags, the structure of the package is checked against it before any ciphertext is
        loaded.
        */
        size_t load_result_package(
            ResultPackage &result_package,
            istream &in,
            const shared_ptr<SEALContext> &context,
            const PSIParams *params)
        {
            // The context must be set and valid for this operation
            if (!context) {
                throw invalid_argument("context cannot be null");
            }
            if (!context->parameters_set()) {
                throw invalid_argument("context is invalid");
            }

            // Clear the current data
            result_package.psi_result.clear();
            result_package.label_result.clear();

            vector<unsigned char> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(
                reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedResultPackageBuffer(verifier);
            if (!safe) {
                throw runtime_error("failed to load ResultPackage: invalid buffer");
            }

            const auto *rp = fbs::GetSizePrefixedResultPackage(in_data.data());

            // With match tags, the parameters determine the structure of every result package,
            // so one that does not have it is refused before any of its ciphertexts is loaded:
            // loading them is most of the work, and a package that is not what the parameters
            // call for is worth none of it. Without match tags every package carries a PSI
            // result, which the schema required until match tags made it optional; a package
            // without one is refused as the schema used to refuse it.
            if (params && params->uses_tags()) {
                try {
                    check_tag_result_structure(
                        *params,
                        rp->bundle_idx(),
                        rp->psi_result() != nullptr,
                        rp->label_byte_count(),
                        rp->nonce_byte_count(),
                        rp->label_result() ? rp->label_result()->size() : 0);
                } catch (const runtime_error &ex) {
                    stringstream ss;
                    ss << "failed to load ResultPackage: " << ex.what();
                    throw runtime_error(ss.str());
                }
            } else if (params && !rp->psi_result()) {
                throw runtime_error(
                    "failed to load ResultPackage: the PSI result is missing, but the parameters "
                    "do not use match tags");
            }

            result_package.bundle_idx = rp->bundle_idx();

            // Load psi_result, if present. A result for parameters with match tags has none, and
            // one for parameters without them always has one; which the package should be is
            // checked above when the parameters are given, and otherwise by the receiver.
            if (rp->psi_result()) {
                const auto &psi_ct = *rp->psi_result();
                gsl::span<const unsigned char> psi_ct_span(
                    reinterpret_cast<const unsigned char *>(psi_ct.data()->data()),
                    psi_ct.data()->size());
                try {
                    result_package.psi_result.load(context, psi_ct_span);
                } catch (const logic_error &ex) {
                    stringstream ss;
                    ss << "failed to load PSI ciphertext: ";
                    ss << ex.what();
                    throw runtime_error(ss.str());
                } catch (const runtime_error &ex) {
                    stringstream ss;
                    ss << "failed to load PSI ciphertext: ";
                    ss << ex.what();
                    throw runtime_error(ss.str());
                }
            }

            // Load the label_byte_count and -- if non-zero -- check that we actually have label
            // data present. This does not guarantee that we have *enough* label data present
            // though, so it is important to check that when the label data has been decrypted
            // and decoded.
            result_package.label_byte_count = rp->label_byte_count();
            if (result_package.label_byte_count > max_label_byte_count) {
                throw runtime_error("failed to load ResultPackage: label_byte_count is too large");
            }
            if (result_package.label_byte_count && !rp->label_result()) {
                throw runtime_error("failed to load ResultPackage: label data is missing");
            }

            // Load the nonce_byte_count only if we actually have a non-zero label_byte_count. We
            // still need to check (as for the actual label as well) that we received enough data.
            result_package.nonce_byte_count =
                result_package.label_byte_count ? rp->nonce_byte_count() : 0;
            if (result_package.nonce_byte_count > max_nonce_byte_count) {
                throw runtime_error("failed to load ResultPackage: nonce_byte_count is too large");
            }

            // Load the label_result data if present
            if (rp->label_result()) {
                const auto &label_cts = *rp->label_result();

                // We deliberately do not reserve() label_cts.size(): the count comes from the
                // wire, so reserving it up front would let a malformed buffer force a large
                // allocation. The vector instead grows as each ciphertext is loaded and
                // validated, bounded by the actual (verifier-checked) buffer contents.
                for (const auto *const label_ct : label_cts) {
                    gsl::span<const unsigned char> label_ct_span(
                        reinterpret_cast<const unsigned char *>(label_ct->data()->data()),
                        label_ct->data()->size());
                    SEALObject<Ciphertext> temp;
                    try {
                        temp.load(context, label_ct_span);
                    } catch (const logic_error &ex) {
                        stringstream ss;
                        ss << "failed to load label ciphertext: ";
                        ss << ex.what();
                        throw runtime_error(ss.str());
                    } catch (const runtime_error &ex) {
                        stringstream ss;
                        ss << "failed to load label ciphertext: ";
                        ss << ex.what();
                        throw runtime_error(ss.str());
                    }
                    result_package.label_result.push_back(std::move(temp));
                }
            }

            return in_data.size();
        }
    } // namespace

    size_t ResultPackage::save(ostream &out) const
    {
        flatbuffers::FlatBufferBuilder fbs_builder(1024);

        if (!Serialization::IsSupportedComprMode(compr_mode)) {
            throw runtime_error("unsupported compression mode");
        }

        // A result for parameters with match tags has no PSI result, and leaves it out
        vector<unsigned char> temp;
        size_t size = 0;
        flatbuffers::Offset<fbs::Ciphertext> psi_ct;
        if (psi_result) {
            temp.resize(psi_result.save_size(compr_mode));
            size = psi_result.save(temp, compr_mode);
            auto psi_ct_data =
                fbs_builder.CreateVector(reinterpret_cast<const uint8_t *>(temp.data()), size);
            psi_ct = fbs::CreateCiphertext(fbs_builder, psi_ct_data);
        }

        // There may or may not be label data
        auto label_cts = fbs_builder.CreateVector([&] {
            // The Ciphertext vector is populated with an immediately-invoked lambda
            vector<flatbuffers::Offset<fbs::Ciphertext>> ret;
            for (const auto &label_ct : label_result) {
                // Save each seal::Ciphertext
                temp.resize(label_ct.save_size(compr_mode));
                size = label_ct.save(temp, compr_mode);
                auto label_ct_data =
                    fbs_builder.CreateVector(reinterpret_cast<const uint8_t *>(temp.data()), size);

                // Add to the Ciphertext vector
                ret.push_back(fbs::CreateCiphertext(fbs_builder, label_ct_data));
            }
            return ret;
        }());

        fbs::ResultPackageBuilder rp_builder(fbs_builder);
        rp_builder.add_bundle_idx(bundle_idx);
        if (psi_result) {
            rp_builder.add_psi_result(psi_ct);
        }
        rp_builder.add_label_byte_count(label_byte_count);
        rp_builder.add_nonce_byte_count(nonce_byte_count);
        rp_builder.add_label_result(label_cts);
        auto rp = rp_builder.Finish();
        fbs_builder.FinishSizePrefixed(rp);

        out.write(
            reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
            safe_cast<streamsize>(fbs_builder.GetSize()));

        return fbs_builder.GetSize();
    }

    size_t ResultPackage::load(istream &in, const shared_ptr<SEALContext> &context)
    {
        return load_result_package(*this, in, context, nullptr);
    }

    size_t ResultPackage::load(
        istream &in, const shared_ptr<SEALContext> &context, const PSIParams &params)
    {
        return load_result_package(*this, in, context, &params);
    }

    void ResultPackage::check_tag_structure(const PSIParams &params) const
    {
        if (!params.uses_tags()) {
            return;
        }

        check_tag_result_structure(
            params,
            bundle_idx,
            static_cast<bool>(psi_result),
            label_byte_count,
            nonce_byte_count,
            label_result.size());
    }

    PlainResultPackage ResultPackage::extract(const CryptoContext &crypto_context)
    {
        if (!crypto_context.decryptor()) {
            throw runtime_error("decryptor is not configured in CryptoContext");
        }

        PlainResultPackage plain_rp;
        plain_rp.bundle_idx = bundle_idx;

        // A result for parameters with match tags has no PSI result to decrypt
        if (psi_result) {
            plain_rp.psi_result =
                decrypt_and_decode(crypto_context, psi_result, "Matching result noise budget");
        }

        plain_rp.label_byte_count = label_byte_count;
        plain_rp.nonce_byte_count = nonce_byte_count;
        for (auto &ct : label_result) {
            plain_rp.label_result.push_back(
                decrypt_and_decode(crypto_context, ct, "Label result noise budget"));
        }

        // Clear the label data
        label_result.clear();

        return plain_rp;
    }

    vector<vector<uint64_t>> ResultPackage::extract_tag_result(
        const CryptoContext &crypto_context, size_t tag_part_count)
    {
        if (!crypto_context.decryptor()) {
            throw runtime_error("decryptor is not configured in CryptoContext");
        }
        if (tag_part_count > label_result.size()) {
            throw invalid_argument("tag_part_count is larger than the number of label parts");
        }

        vector<vector<uint64_t>> result;
        result.reserve(tag_part_count);
        for (size_t part_idx = 0; part_idx < tag_part_count; part_idx++) {
            result.push_back(decrypt_and_decode(
                crypto_context, label_result[part_idx], "Tag result noise budget"));
        }

        return result;
    }

    vector<vector<uint64_t>> ResultPackage::extract_label_result(
        const CryptoContext &crypto_context, size_t tag_part_count)
    {
        if (!crypto_context.decryptor()) {
            throw runtime_error("decryptor is not configured in CryptoContext");
        }
        if (tag_part_count > label_result.size()) {
            throw invalid_argument("tag_part_count is larger than the number of label parts");
        }

        vector<vector<uint64_t>> result;
        result.reserve(label_result.size() - tag_part_count);
        for (size_t part_idx = tag_part_count; part_idx < label_result.size(); part_idx++) {
            result.push_back(decrypt_and_decode(
                crypto_context, label_result[part_idx], "Label result noise budget"));
        }

        return result;
    }
} // namespace apsi::network
