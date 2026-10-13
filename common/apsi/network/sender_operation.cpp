// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstdint>
#include <iterator>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <vector>

// APSI
#include "apsi/network/sender_operation.h"
#include "apsi/network/sop_generated.h"
#include "apsi/network/sop_header_generated.h"
#include "apsi/oprf/oprf_common.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/serialization.h"
#include "seal/util/common.h"
#include "seal/util/streambuf.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi::network {
    using namespace util;

    namespace {
        /**
        Reads the parameter fingerprint of a verified QueryRequest. Returns std::nullopt if the
        query carries none, and throws if it carries one of the wrong size, which no receiver sends.
        */
        optional<PSIParams::Fingerprint> read_params_fingerprint(const fbs::QueryRequest &req)
        {
            const auto *fingerprint_data = req.params_fingerprint();
            if (!fingerprint_data) {
                return nullopt;
            }

            PSIParams::Fingerprint fingerprint{};
            if (fingerprint_data->size() != fingerprint.size()) {
                throw runtime_error("invalid parameter fingerprint");
            }
            copy_bytes(fingerprint_data->data(), fingerprint.size(), fingerprint.data());

            return fingerprint;
        }

        /**
        The dimensions that serialized KSwitchKeys, such as relinearization keys, declare: how many
        key sets they hold, and how many keys the first key set holds, or zero if there is none.
        */
        struct KSwitchKeysDimensions {
            uint64_t key_set_count = 0;

            uint64_t first_key_count = 0;
        };

        /**
        Reads the dimensions of serialized KSwitchKeys without loading any key.

        Serialization::Load decompresses the data only as its load_members function reads it, so
        a function that stops as soon as it has read the dimensions makes Load decompress no more
        than the first block of the data, and allocate no key. The members are read as
        KSwitchKeys::load_members reads them: the parms_id, the number of key sets, and for each
        key set the number of keys in it followed by the keys. Whatever Serialization::Load throws
        for data that cannot be read that far is thrown on.
        */
        KSwitchKeysDimensions read_kswitch_keys_dimensions(const seal_byte *in, size_t size)
        {
            // Thrown to stop Serialization::Load once the dimensions have been read. Load passes
            // on an exception it does not handle itself, after restoring its stream's exception
            // mask.
            struct DimensionsRead : exception {};

            KSwitchKeysDimensions dims;
            try {
                Serialization::Load(
                    [&dims](istream &stream, SEALVersion) {
                        parms_id_type parms_id{};
                        stream.read(reinterpret_cast<char *>(&parms_id), sizeof(parms_id_type));
                        stream.read(
                            reinterpret_cast<char *>(&dims.key_set_count), sizeof(uint64_t));
                        if (dims.key_set_count) {
                            stream.read(
                                reinterpret_cast<char *>(&dims.first_key_count), sizeof(uint64_t));
                        }
                        throw DimensionsRead{};
                    },
                    in,
                    size,
                    false);
            } catch (const DimensionsRead &) {
                return dims;
            }

            // The function passed to Serialization::Load ends by throwing, so Load cannot return
            throw logic_error("the dimensions of the keys could not be read");
        }

        /**
        Throws std::runtime_error unless serialized relinearization keys declare exactly one key
        set of key_count keys, without loading any key; see read_kswitch_keys_dimensions.
        */
        void check_relin_keys_dimensions(const seal_byte *in, size_t size, size_t key_count)
        {
            KSwitchKeysDimensions dims = read_kswitch_keys_dimensions(in, size);
            if (dims.key_set_count != 1) {
                stringstream ss;
                ss << "they declare a key set count of " << dims.key_set_count << ", not 1";
                throw runtime_error(ss.str());
            }
            if (dims.first_key_count != key_count) {
                stringstream ss;
                ss << "their key set declares a key count of " << dims.first_key_count << ", not "
                   << key_count;
                throw runtime_error(ss.str());
            }
        }
    } // namespace

    const char *sender_operation_type_str(SenderOperationType sop_type)
    {
        switch (sop_type) {
        case SenderOperationType::sop_unknown:
            return "sop_unknown";

        case SenderOperationType::sop_parms:
            return "sop_parms";

        case SenderOperationType::sop_oprf:
            return "sop_oprf";

        case SenderOperationType::sop_query:
            return "sop_query";

        default:
            return "sop_invalid";
        }
    }

    const char *compr_mode_str(compr_mode_type compr_mode) noexcept
    {
        switch (compr_mode) {
        case compr_mode_type::none:
            return "none";

#ifdef SEAL_USE_ZLIB
        case compr_mode_type::zlib:
            return "zlib";
#endif

#ifdef SEAL_USE_ZSTD
        case compr_mode_type::zstd:
            return "zstd";
#endif

        case compr_mode_type::bitpack:
            return "bitpack";

        default:
            return "unsupported";
        }
    }

    size_t SenderOperationHeader::save(ostream &out) const
    {
        flatbuffers::FlatBufferBuilder fbs_builder(128);

        fbs::SenderOperationHeaderBuilder sop_header_builder(fbs_builder);
        sop_header_builder.add_version(version);
        sop_header_builder.add_type(static_cast<fbs::SenderOperationType>(type));
        auto sop_header = sop_header_builder.Finish();
        fbs_builder.FinishSizePrefixed(sop_header);

        out.write(
            reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
            safe_cast<streamsize>(fbs_builder.GetSize()));

        return fbs_builder.GetSize();
    }

    size_t SenderOperationHeader::load(istream &in)
    {
        vector<unsigned char> in_data(util::read_from_stream(in));

        auto verifier = flatbuffers::Verifier(
            reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
        bool safe = fbs::VerifySizePrefixedSenderOperationHeaderBuffer(verifier);
        if (!safe) {
            throw runtime_error("failed to load SenderOperationHeader: invalid buffer");
        }

        const auto *sop_header = fbs::GetSizePrefixedSenderOperationHeader(in_data.data());

        // Read the serialization version number
        version = sop_header->version();

        // Read the operation type
        type = static_cast<SenderOperationType>(sop_header->type());

        return in_data.size();
    }

    size_t SenderOperationParms::save(ostream &out) const
    {
        flatbuffers::FlatBufferBuilder fbs_builder(1024);

        auto parms_request = fbs::CreateParmsRequest(fbs_builder);

        fbs::SenderOperationBuilder sop_builder(fbs_builder);
        sop_builder.add_request_type(fbs::Request_ParmsRequest);
        sop_builder.add_request(parms_request.Union());
        auto sop = sop_builder.Finish();
        fbs_builder.FinishSizePrefixed(sop);

        out.write(
            reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
            safe_cast<streamsize>(fbs_builder.GetSize()));

        return fbs_builder.GetSize();
    }

    size_t SenderOperationParms::load(istream &in, shared_ptr<SEALContext> context)
    {
        // The context cannot be set for this operation
        if (context) {
            throw invalid_argument("context must be null");
        }

        vector<unsigned char> in_data(util::read_from_stream(in));

        auto verifier = flatbuffers::Verifier(
            reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
        bool safe = fbs::VerifySizePrefixedSenderOperationBuffer(verifier);
        if (!safe) {
            throw runtime_error("failed to load SenderOperation: invalid buffer");
        }

        const auto *sop = fbs::GetSizePrefixedSenderOperation(in_data.data());

        // Need to check that the operation is of the right type
        if (sop->request_type() != fbs::Request_ParmsRequest) {
            throw runtime_error("unexpected operation type");
        }

        return in_data.size();
    }

    size_t SenderOperationOPRF::save(ostream &out) const
    {
        flatbuffers::FlatBufferBuilder fbs_builder(1024);

        auto oprf_data =
            fbs_builder.CreateVector(reinterpret_cast<const uint8_t *>(data.data()), data.size());
        auto req = fbs::CreateOPRFRequest(fbs_builder, oprf_data);

        fbs::SenderOperationBuilder sop_builder(fbs_builder);
        sop_builder.add_request_type(fbs::Request_OPRFRequest);
        sop_builder.add_request(req.Union());
        auto sop = sop_builder.Finish();
        fbs_builder.FinishSizePrefixed(sop);

        out.write(
            reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
            safe_cast<streamsize>(fbs_builder.GetSize()));

        return fbs_builder.GetSize();
    }

    size_t SenderOperationOPRF::load(istream &in, shared_ptr<SEALContext> context)
    {
        // The context cannot be set for this operation
        if (context) {
            throw invalid_argument("context must be null");
        }

        // Clear the current data
        data.clear();

        vector<unsigned char> in_data(util::read_from_stream(in));

        auto verifier = flatbuffers::Verifier(
            reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
        bool safe = fbs::VerifySizePrefixedSenderOperationBuffer(verifier);
        if (!safe) {
            throw runtime_error("failed to load SenderOperation: invalid buffer");
        }

        const auto *sop = fbs::GetSizePrefixedSenderOperation(in_data.data());

        // Need to check that the operation is of the right type
        if (sop->request_type() != fbs::Request_OPRFRequest) {
            throw runtime_error("unexpected operation type");
        }

        // Load the OPRF request; this is a required field so we can always dereference. Screen the
        // item count before copying: the allocation is 1:1 with the received bytes, so there is
        // nothing to amplify, but the scalar multiplication this buys is charged to the sender's
        // dispatcher, which serves one request at a time.
        const auto &oprf_data = *sop->request_as_OPRFRequest()->data();
        if (oprf_data.size() > apsi::oprf::oprf_query_count_max * apsi::oprf::oprf_query_size) {
            throw runtime_error("oprf request is too large");
        }

        data.resize(oprf_data.size());
        copy_bytes(oprf_data.data(), oprf_data.size(), data.data());

        return in_data.size();
    }

    size_t SenderOperationQuery::save(ostream &out) const
    {
        flatbuffers::FlatBufferBuilder fbs_builder(1024);

        vector<unsigned char> temp;
        temp.resize(relin_keys.save_size(compr_mode));
        auto size = relin_keys.save(temp, compr_mode);
        auto relin_keys_data =
            fbs_builder.CreateVector(reinterpret_cast<const uint8_t *>(temp.data()), size);

        // This is a little tricky; each QueryRequestPart consists of an exponent and a vector
        // of Ciphertexts. For convenience, we create vectors in immediately-invoked lambdas and
        // pass them to the CreateVector function. In the outer lambda, we populate a vector of
        // QueryRequestParts, creating a new builder class for each of them. In the inner lambda
        // we build the QueryRequestPart data by creating multiple Ciphertexts.
        auto query_request_parts = fbs_builder.CreateVector([&] {
            // The QueryRequestPart vector is populated with an immediately-invoked lambda
            vector<flatbuffers::Offset<fbs::QueryRequestPart>> ret;
            for (const auto &q : data) {
                // Then the vector of Ciphertexts
                auto cts = fbs_builder.CreateVector([&] {
                    // The Ciphertext vector is populated with an immediately-invoked lambda
                    vector<flatbuffers::Offset<fbs::Ciphertext>> ret_inner;
                    for (const auto &ct : q.second) {
                        // Save each SEALObject<seal::Ciphertext>
                        temp.resize(ct.save_size(compr_mode));
                        size = ct.save(temp, compr_mode);
                        auto ct_data = fbs_builder.CreateVector(
                            reinterpret_cast<const uint8_t *>(temp.data()), size);

                        // Add to the Ciphertext vector
                        ret_inner.push_back(fbs::CreateCiphertext(fbs_builder, ct_data));
                    }
                    return ret_inner;
                }());

                // For each exponent, create a QueryRequestPart
                auto query_req_part = fbs::CreateQueryRequestPart(fbs_builder, q.first, cts);
                ret.push_back(query_req_part);
            }
            return ret;
        }());

        // The fingerprint is written only if it is set, so that a query without one is exactly
        // what an APSI 1.x receiver writes
        flatbuffers::Offset<flatbuffers::Vector<uint8_t>> params_fingerprint_data;
        if (params_fingerprint) {
            params_fingerprint_data = fbs_builder.CreateVector(
                reinterpret_cast<const uint8_t *>(params_fingerprint->data()),
                params_fingerprint->size());
        }

        auto req = fbs::CreateQueryRequest(
            fbs_builder,
            static_cast<uint8_t>(compr_mode),
            relin_keys_data,
            query_request_parts,
            params_fingerprint_data);

        fbs::SenderOperationBuilder sop_builder(fbs_builder);
        sop_builder.add_request_type(fbs::Request_QueryRequest);
        sop_builder.add_request(req.Union());
        auto sop = sop_builder.Finish();
        fbs_builder.FinishSizePrefixed(sop);

        out.write(
            reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
            safe_cast<streamsize>(fbs_builder.GetSize()));

        return fbs_builder.GetSize();
    }

    size_t SenderOperationQuery::load(istream &in, shared_ptr<SEALContext> context)
    {
        // The context must be set and valid for this operation
        if (!context) {
            throw invalid_argument("context cannot be null");
        }
        if (!context->parameters_set()) {
            throw invalid_argument("context is invalid");
        }

        // Clear the current data
        data.clear();
        params_fingerprint.reset();

        vector<unsigned char> in_data(util::read_from_stream(in));

        auto verifier = flatbuffers::Verifier(
            reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
        bool safe = fbs::VerifySizePrefixedSenderOperationBuffer(verifier);
        if (!safe) {
            throw runtime_error("failed to load SenderOperation: invalid buffer");
        }

        const auto *sop = fbs::GetSizePrefixedSenderOperation(in_data.data());

        // Need to check that the operation is of the right type
        if (sop->request_type() != fbs::Request_QueryRequest) {
            throw runtime_error("unexpected operation type");
        }

        const auto &req = *sop->request_as_QueryRequest();

        // Check the request's compression mode is supported
        if (!Serialization::IsSupportedComprMode(req.compression_type())) {
            throw runtime_error("unsupported compression mode");
        }

        compr_mode = static_cast<compr_mode_type>(req.compression_type());

        // Read the parameter fingerprint before the expensive parts. Whether a query without one
        // is acceptable depends on the SenderDB, so that is for sender::Query to decide.
        params_fingerprint = read_params_fingerprint(req);

        // Load relin_keys if they are needed in this case
        if (context->using_keyswitching()) {
            // This is NOT a required field; check if it is present
            if (!req.relin_keys()) {
                throw runtime_error("realinearization keys data is missing");
            }

            const auto &relin_keys_data = *req.relin_keys();
            const auto *relin_keys_bytes =
                reinterpret_cast<const seal_byte *>(relin_keys_data.data());
            size_t relin_keys_size = relin_keys_data.size();

            // A receiver creates its keys with KeyGenerator::create_relin_keys, which makes exactly
            // one key set: the one for the square of the secret key, which is all a query needs,
            // with a key for each prime of the first data level. SEAL accepts up to
            // poly_modulus_degree key sets, and keys that are almost all zero compress so well that
            // a few hundred bytes can declare gigabytes of them, so the dimensions are checked
            // before any key is loaded.
            size_t key_count = context->first_context_data()->parms().coeff_modulus().size();
            RelinKeys loaded_relin_keys;
            try {
                check_relin_keys_dimensions(relin_keys_bytes, relin_keys_size, key_count);
                loaded_relin_keys.load(*context, relin_keys_bytes, relin_keys_size);
            } catch (const logic_error &ex) {
                stringstream ss;
                ss << "failed to load relinearization keys: ";
                ss << ex.what();
                throw runtime_error(ss.str());
            } catch (const runtime_error &ex) {
                stringstream ss;
                ss << "failed to load relinearization keys: ";
                ss << ex.what();
                throw runtime_error(ss.str());
            }

            // The keys loaded have the dimensions checked above, unless a version of SEAL saves
            // keys differently from how check_relin_keys_dimensions reads them
            if (loaded_relin_keys.data().size() != 1 || loaded_relin_keys.size() != 1) {
                throw runtime_error(
                    "failed to load relinearization keys: expected exactly one key set");
            }
            relin_keys.set(std::move(loaded_relin_keys));
        }

        // Read the query data; this is a required field so we can always dereference. The
        // ciphertexts are kept in serialized form rather than loaded: SEAL compresses what it
        // saves, so a few bytes can load as a large ciphertext, and how many ciphertexts there
        // should be depends on the parameters, which sender::Query checks before loading any.
        //
        // Holding a ciphertext copies its bytes, so the bytes copied are counted. FlatBuffers lets
        // many offsets point at one object, as its builder does to share strings, and the verifier
        // allows it, so the entries of a short query could otherwise all point at one large
        // ciphertext and have it copied once each. A receiver saves every ciphertext to bytes of
        // its own, so those of an honest query never add up to more than the buffer.
        const auto &query = *req.query();
        size_t ct_byte_count = 0;
        for (const auto *query_part : query) {
            uint32_t exponent = query_part->exponent();
            if (data.count(exponent)) {
                throw runtime_error("invalid query data");
            }

            // The ciphertext data is a required field so we can always dereference. We
            // deliberately do not reserve() cts.size(): the count comes from the wire, so
            // reserving it up front would let a malformed buffer force a large allocation. The
            // vector instead grows as each ciphertext is copied, bounded by the actual
            // (verifier-checked) buffer contents.
            const auto &cts = *query_part->cts();
            vector<SEALObject<Ciphertext>> cts_vec;
            for (const auto *const ct : cts) {
                size_t ct_size = ct->data()->size();
                if (ct_size > in_data.size() - ct_byte_count) {
                    throw runtime_error("invalid query data: ciphertexts share bytes");
                }
                ct_byte_count += ct_size;

                gsl::span<const unsigned char> ct_span(
                    reinterpret_cast<const unsigned char *>(ct->data()->data()), ct_size);
                SEALObject<Ciphertext> temp;
                temp.set_serialized(ct_span);
                cts_vec.emplace_back(std::move(temp));
            }

            data.emplace(exponent, std::move(cts_vec));
        }

        return in_data.size();
    }

    optional<PSIParams::Fingerprint> SenderOperationQuery::ExtractParamsFingerprint(
        gsl::span<const unsigned char> in)
    {
        // Frame the buffer as load does when it reads the query from a stream: a size prefix and
        // exactly that many bytes after it
        flatbuffers::uoffset_t prefixed_size = 0;
        if (in.size() < sizeof(prefixed_size)) {
            throw runtime_error("failed to load SenderOperation: buffer is too small");
        }
        copy_bytes(in.data(), sizeof(prefixed_size), &prefixed_size);
        prefixed_size = flatbuffers::EndianScalar(prefixed_size);
        if (prefixed_size > in.size() - sizeof(prefixed_size)) {
            throw runtime_error("failed to load SenderOperation: buffer is truncated");
        }

        // The FlatBuffers verifier asserts that a buffer is smaller than
        // FLATBUFFERS_MAX_BUFFER_SIZE, so one that is not is refused before it is verified
        if (prefixed_size >=
            static_cast<size_t>(FLATBUFFERS_MAX_BUFFER_SIZE) - sizeof(prefixed_size)) {
            throw runtime_error("failed to load SenderOperation: buffer is too large");
        }
        size_t buffer_size = sizeof(prefixed_size) + static_cast<size_t>(prefixed_size);

        // FlatBuffers reads scalars in place, so it needs a buffer aligned for them, which the
        // caller's need not be. Copying is cheap next to loading the query.
        const auto *buffer = reinterpret_cast<const uint8_t *>(in.data());
        vector<uint8_t> aligned_copy;
        if (reinterpret_cast<uintptr_t>(buffer) % alignof(flatbuffers::largest_scalar_t)) {
            aligned_copy.assign(buffer, buffer + buffer_size);
            buffer = aligned_copy.data();
        }

        auto verifier = flatbuffers::Verifier(buffer, buffer_size);
        bool safe = fbs::VerifySizePrefixedSenderOperationBuffer(verifier);
        if (!safe) {
            throw runtime_error("failed to load SenderOperation: invalid buffer");
        }

        const auto *sop = fbs::GetSizePrefixedSenderOperation(buffer);
        if (sop->request_type() != fbs::Request_QueryRequest) {
            throw runtime_error("unexpected operation type");
        }

        return read_params_fingerprint(*sop->request_as_QueryRequest());
    }
} // namespace apsi::network
