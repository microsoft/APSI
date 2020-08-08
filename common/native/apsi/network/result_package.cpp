// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstring>
#include <sstream>
#include <stdexcept>

// APSI
#include "apsi/logging/log.h"
#include "apsi/network/result_package.h"
#include "apsi/network/sender_operation.h"
#include "apsi/network/result_package_generated.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    namespace network
    {
        size_t ResultPackage::save(ostream &out) const
        {
            flatbuffers::FlatBufferBuilder fbs_builder(1024);

            vector<SEAL_BYTE> temp;
            temp.resize(psi_result.save_size(compr_mode_type::deflate));
            auto size = psi_result.save(temp.data(), temp.size(), compr_mode_type::deflate);
            auto psi_ct_data = fbs_builder.CreateVector(reinterpret_cast<uint8_t*>(temp.data()), size);
            auto psi_ct = fbs::CreateCiphertext(fbs_builder, psi_ct_data);

            // There may or may not be label data
            auto label_cts = fbs_builder.CreateVector([&]() {
                // The Ciphertext vector is populated with an immediately-invoked lambda
                vector<flatbuffers::Offset<fbs::Ciphertext>> ret;
                for (const auto &label_ct : label_result)
                {
                    // Save each seal::Ciphertext
                    temp.resize(label_ct.save_size(compr_mode_type::deflate));
                    size = label_ct.save(temp.data(), temp.size(), compr_mode_type::deflate);
                    auto label_ct_data = fbs_builder.CreateVector(reinterpret_cast<uint8_t*>(temp.data()), size);

                    // Add to the Ciphertext vector
                    ret.push_back(fbs::CreateCiphertext(fbs_builder, label_ct_data));
                }
                return ret;
            }());

            fbs::ResultPackageBuilder rp_builder(fbs_builder);
            rp_builder.add_bundle_idx(bundle_idx);
            rp_builder.add_psi_result(psi_ct);
            rp_builder.add_label_result(label_cts);
            auto rp = rp_builder.Finish();
            fbs_builder.FinishSizePrefixed(rp);

            out.write(
                reinterpret_cast<const char*>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        /**
        Reads the ResultPackage from a stream.
        */
        size_t ResultPackage::load(istream &in, shared_ptr<SEALContext> context)
        {
            // The context must be set and valid for this operation
            if (!context)
            {
                throw invalid_argument("context cannot be null");
            }
            if (!context->parameters_set())
            {
                throw invalid_argument("context is invalid");
            }

            // Clear the current data
            psi_result.release();
            label_result.clear();

            vector<SEAL_BYTE> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(reinterpret_cast<const uint8_t*>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedResultPackageBuffer(verifier);
            if (!safe)
            {
                throw runtime_error("failed to load ResultPackage: invalid buffer");
            }

            auto rp = fbs::GetSizePrefixedResultPackage(in_data.data());

            bundle_idx = rp->bundle_idx();

            // Load psi_result
            const auto &psi_ct = *rp->psi_result();
            try
            {
                psi_result.load(
                    context,
                    reinterpret_cast<const SEAL_BYTE*>(psi_ct.data()->data()), psi_ct.data()->size());
            }
            catch (const logic_error &ex)
            {
                stringstream ss;
                ss << "failed to load PSI ciphertext: ";
                ss << ex.what();
                throw runtime_error(ss.str());
            }
            catch (const runtime_error &ex)
            {
                stringstream ss;
                ss << "failed to load PSI ciphertext: ";
                ss << ex.what();
                throw runtime_error(ss.str());
            }

            // Load the label_result data if present
            if (rp->label_result())
            {
                auto &label_cts = *rp->label_result();
                label_result.reserve(label_cts.size());
                for (const auto &label_ct : label_cts)
                {
                    Ciphertext temp(context);
                    try
                    {
                        temp.load(
                            context,
                            reinterpret_cast<const SEAL_BYTE*>(label_ct->data()->data()), label_ct->data()->size());
                    }
                    catch (const logic_error &ex)
                    {
                        stringstream ss;
                        ss << "failed to load label ciphertext: ";
                        ss << ex.what();
                        throw runtime_error(ss.str());
                    }
                    catch (const runtime_error &ex)
                    {
                        stringstream ss;
                        ss << "failed to load label ciphertext: ";
                        ss << ex.what();
                        throw runtime_error(ss.str());
                    }
                    label_result.emplace_back(move(temp));
                }
            }

            return in_data.size();
        }

        PlainResultPackage ResultPackage::extract(const CryptoContext &crypto_context)
        {
            PlainResultPackage plain_rp;

            plain_rp.bundle_idx = bundle_idx;

            Plaintext temp;
            crypto_context.decryptor()->decrypt(psi_result, temp);
            APSI_LOG_DEBUG(
                "PSI result noise budget: " <<
                crypto_context.decryptor()->invariant_noise_budget(psi_result) << " bits");

            crypto_context.encoder()->decode(temp, plain_rp.psi_result);

            for (const auto &ct : label_result)
            {
                crypto_context.decryptor()->decrypt(ct, temp);
                APSI_LOG_DEBUG(
                    "Label result noise budget: " <<
                    crypto_context.decryptor()->invariant_noise_budget(ct) << " bits");

                vector<uint64_t> temp_label;
                crypto_context.encoder()->decode(temp, temp_label);
                plain_rp.label_result.push_back(move(temp_label));
            }

            return plain_rp;
        }
    }
}
