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

        // A result package must take at least 1/max_result_expansion of the size its ciphertexts
        // load to; see load_result_package
        constexpr std::uint64_t max_result_expansion = 64;

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
        Returns the number of label parts the encrypted label takes, nonce included, for items of
        item_bit_count bits: none without a label, whatever the nonce byte count. The byte counts
        must be within their bounds, so that this cannot overflow.
        */
        uint64_t compute_payload_part_count(
            uint64_t label_byte_count, uint64_t nonce_byte_count, uint64_t item_bit_count)
        {
            if (!label_byte_count) {
                return 0;
            }

            return (((nonce_byte_count + label_byte_count) * 8) + item_bit_count - 1) /
                   item_bit_count;
        }

        /**
        Throws std::runtime_error unless a result package for the given bundle index can be a result
        for the given parameters.
        */
        void check_result_bundle_idx(const PSIParams &params, uint64_t bundle_idx)
        {
            if (bundle_idx >= params.bundle_idx_count()) {
                stringstream ss;
                ss << "result package is for bundle index " << bundle_idx
                   << " but the parameters have only " << params.bundle_idx_count();
                throw runtime_error(ss.str());
            }
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
            check_result_bundle_idx(params, bundle_idx);
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
            // exactly as many as SenderDB stores
            uint64_t expected_part_count =
                params.tag_part_count() +
                compute_payload_part_count(
                    label_byte_count, nonce_byte_count, params.item_bit_count());
            if (label_part_count != expected_part_count) {
                stringstream ss;
                ss << "result package has " << label_part_count << " label parts but "
                   << expected_part_count << " are expected";
                throw runtime_error(ss.str());
            }
        }

        /**
        Reads a ciphertext of a result package from in and checks that it has the shape every
        sender gives a result: in coefficient form, at the last level of the modulus chain, and of
        size 2, or 3 if the sender has not relinearized it. A ciphertext of any other shape cannot
        be a result. Microsoft SEAL loads ciphertexts of size up to 16 at any level, and one of
        zeros compresses to almost nothing, so refusing each such ciphertext as soon as it is
        loaded, before the next, keeps what a package can make the receiver hold to what a result
        can take. what names the ciphertext in error messages.
        */
        Ciphertext load_result_ciphertext(
            const shared_ptr<SEALContext> &context,
            gsl::span<const unsigned char> in,
            const char *what)
        {
            Ciphertext ct;
            try {
                ct.load(*context, reinterpret_cast<const seal_byte *>(in.data()), in.size());
            } catch (const logic_error &ex) {
                stringstream ss;
                ss << "failed to load " << what << " ciphertext: " << ex.what();
                throw runtime_error(ss.str());
            } catch (const runtime_error &ex) {
                stringstream ss;
                ss << "failed to load " << what << " ciphertext: " << ex.what();
                throw runtime_error(ss.str());
            }

            if (ct.parms_id() != context->last_parms_id()) {
                stringstream ss;
                ss << "failed to load " << what
                   << " ciphertext: it is not at the last level of the modulus chain, where a "
                      "result is";
                throw runtime_error(ss.str());
            }
            if (ct.is_ntt_form()) {
                stringstream ss;
                ss << "failed to load " << what
                   << " ciphertext: it is in NTT form, and a result is in coefficient form";
                throw runtime_error(ss.str());
            }
            if ((ct.size() != 2) && (ct.size() != 3)) {
                stringstream ss;
                ss << "failed to load " << what << " ciphertext: it has size " << ct.size()
                   << ", and a result has size 2 or 3";
                throw runtime_error(ss.str());
            }

            return ct;
        }

        /**
        Reads a ResultPackage from a stream into result_package. Before any ciphertext is loaded,
        the structure of the package is checked against params, or if it is null against what any
        parameters allow, and the ciphertexts must neither share bytes nor take less than
        1/max_result_expansion of what they load to.
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
            uint64_t label_part_count = rp->label_result() ? rp->label_result()->size() : 0;

            // With match tags, the parameters determine the structure of every result package, so
            // one without it is refused before any of its ciphertexts is loaded, which is most of
            // the work. Without match tags, a package without a PSI result is refused, as the
            // APSI 1.x schema refused it, and so is one for a bundle index the parameters do not
            // have, as with match tags.
            if (params && params->uses_tags()) {
                try {
                    check_tag_result_structure(
                        *params,
                        rp->bundle_idx(),
                        rp->psi_result() != nullptr,
                        rp->label_byte_count(),
                        rp->nonce_byte_count(),
                        label_part_count);
                } catch (const runtime_error &ex) {
                    stringstream ss;
                    ss << "failed to load ResultPackage: " << ex.what();
                    throw runtime_error(ss.str());
                }
            } else if (params) {
                if (!rp->psi_result()) {
                    throw runtime_error(
                        "failed to load ResultPackage: the PSI result is missing, but the "
                        "parameters do not use match tags");
                }
                try {
                    check_result_bundle_idx(*params, rp->bundle_idx());
                } catch (const runtime_error &ex) {
                    stringstream ss;
                    ss << "failed to load ResultPackage: " << ex.what();
                    throw runtime_error(ss.str());
                }
            }

            // Read the label_byte_count and -- if non-zero -- check that we actually have label
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

            // Read the nonce_byte_count only if we actually have a non-zero label_byte_count. We
            // still need to check (as for the actual label as well) that we received enough data.
            result_package.nonce_byte_count =
                result_package.label_byte_count ? rp->nonce_byte_count() : 0;
            if (result_package.nonce_byte_count > max_nonce_byte_count) {
                throw runtime_error("failed to load ResultPackage: nonce_byte_count is too large");
            }

            // Every label part is loaded and decrypted, so without match tags no more are accepted
            // than a sender sends: as many as its label and nonce take, and none without a label.
            // Fewer are accepted, as by APSI 1.x, which reads short label data as a shorter label.
            // Without parameters, the bound is the most any parameters allow: tag_part_count_max
            // tag parts, and the label and nonce in parts of the smallest item_bit_count.
            if (!params || !params->uses_tags()) {
                uint64_t max_label_part_count = 0;
                if (params) {
                    max_label_part_count = compute_payload_part_count(
                        result_package.label_byte_count,
                        result_package.nonce_byte_count,
                        params->item_bit_count());
                } else {
                    max_label_part_count = PSIParams::ItemParams::tag_part_count_max +
                                           compute_payload_part_count(
                                               result_package.label_byte_count,
                                               result_package.nonce_byte_count,
                                               PSIParams::item_bit_count_min_with_tags);
                }
                if (label_part_count > max_label_part_count) {
                    stringstream ss;
                    ss << "failed to load ResultPackage: result package has " << label_part_count
                       << " label parts but at most " << max_label_part_count << " are expected";
                    throw runtime_error(ss.str());
                }
            }

            // A sender saves every ciphertext to bytes of its own, so those of an honest package
            // take no more than the buffer. FlatBuffers lets many offsets point at one object, and
            // the verifier allows it, so without this a short package could hold one ciphertext
            // many times over and have the receiver load each.
            size_t ct_count = 0;
            size_t ct_byte_count = 0;
            auto count_ciphertext = [&](const fbs::Ciphertext &ct) {
                size_t size = ct.data()->size();
                if (size > in_data.size() - ct_byte_count) {
                    throw runtime_error(
                        "failed to load ResultPackage: its ciphertexts share bytes");
                }
                ct_byte_count += size;
                ct_count++;
            };

            if (rp->psi_result()) {
                count_ciphertext(*rp->psi_result());
            }
            if (rp->label_result()) {
                for (const auto *const label_ct : *rp->label_result()) {
                    count_ciphertext(*label_ct);
                }
            }

            // As defense in depth, the ciphertexts must also take at least 1/max_result_expansion
            // of what they load to, counting each as size 2 at the last level of the modulus chain.
            // SEAL compresses what it saves, so a package of ciphertexts whose data is zero or
            // nearly so would otherwise load to hundreds or thousands of times its size. A result
            // keeps bit_count(plain_modulus) + log2(poly_modulus_degree) bits of each coefficient,
            // so an honest package stays far above the bound in every compression mode. The bound
            // is on the package as a whole, as one result can honestly be a ciphertext of zeros:
            // that of a label part whose polynomials are all zero, as they are when the part holds
            // only a bit or two of the label and every item in the bin bundle has zeros there. The
            // PSI result and the tag parts of the same package are not.
            const auto &last_parms = context->last_context_data()->parms();
            uint64_t loaded_byte_count = mul_safe(
                static_cast<uint64_t>(ct_count),
                static_cast<uint64_t>(2),
                static_cast<uint64_t>(last_parms.poly_modulus_degree()),
                static_cast<uint64_t>(last_parms.coeff_modulus().size()),
                static_cast<uint64_t>(sizeof(uint64_t)));
            if (static_cast<uint64_t>(ct_byte_count) < loaded_byte_count / max_result_expansion) {
                stringstream ss;
                ss << "failed to load ResultPackage: its ciphertexts take " << ct_byte_count
                   << " bytes, less than 1/" << max_result_expansion << " of the "
                   << loaded_byte_count << " bytes they would load to";
                throw runtime_error(ss.str());
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
                result_package.psi_result.set(load_result_ciphertext(context, psi_ct_span, "PSI"));
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
                    temp.set(load_result_ciphertext(context, label_ct_span, "label"));
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
