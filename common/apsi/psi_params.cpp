// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// APSI
#include "apsi/log.h"
#include "apsi/psi_params.h"
#include "apsi/psi_params_generated.h"
#include "apsi/version.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/context.h"
#include "seal/modulus.h"
#include "seal/util/blake2.h"
#include "seal/util/common.h"
#include "seal/util/defines.h"

#ifndef APSI_DISABLE_JSON
// JSON
#include "json/json.h"
#endif

using namespace std;
using namespace seal;
using namespace seal::util;

#ifndef APSI_DISABLE_JSON
namespace {
    const Json::Value &get_non_null_json_value(const Json::Value &parent, const char *name)
    {
        const auto &value = parent[name];
        if (value.isNull()) {
            stringstream ss;
            ss << name << " is not present in " << parent;
            throw runtime_error(ss.str());
        }

        return value;
    }

    uint32_t json_value_ui32(const Json::Value &value)
    {
        if (!value.isUInt()) {
            stringstream ss;
            ss << value << " should be an unsigned int32";
            throw runtime_error(ss.str());
        }

        return value.asUInt();
    }

    uint32_t json_value_ui32(const Json::Value &parent, const char *name)
    {
        const auto &value = get_non_null_json_value(parent, name);
        return json_value_ui32(value);
    }

    uint64_t json_value_ui64(const Json::Value &parent, const char *name)
    {
        const auto &value = get_non_null_json_value(parent, name);

        if (!value.isUInt64()) {
            stringstream ss;
            ss << name << " should be an unsigned int64";
            throw runtime_error(ss.str());
        }

        return value.asUInt64();
    }

    int json_value_int(const Json::Value &value)
    {
        if (!value.isInt()) {
            stringstream ss;
            ss << value << " should be an int";
            throw runtime_error(ss.str());
        }

        return value.asInt();
    }

    int json_value_int(const Json::Value &parent, const char *name)
    {
        const auto &value = get_non_null_json_value(parent, name);
        return json_value_int(value);
    }
} // namespace
#endif

namespace apsi {
    void PSIParams::initialize()
    {
        // Checking the validity of parameters
        if (!table_params_.table_size) {
            throw invalid_argument("table_size cannot be zero");
        }
        if (table_params_.table_size > TableParams::table_size_max) {
            throw invalid_argument("table_size is too large");
        }
        if (!table_params_.max_items_per_bin) {
            throw invalid_argument("max_items_per_bin cannot be zero");
        }
        if (table_params_.max_items_per_bin > TableParams::max_items_per_bin_max) {
            throw invalid_argument("max_items_per_bin is too large");
        }
        if (table_params_.hash_func_count < TableParams::hash_func_count_min ||
            table_params_.hash_func_count > TableParams::hash_func_count_max) {
            throw invalid_argument("hash_func_count is too large or too small");
        }
        if (item_params_.tag_part_count > ItemParams::tag_part_count_max) {
            throw invalid_argument("tag_part_count is too large");
        }

        // Match tags, not the item bits, decide whether an item matches, so an item may then be a
        // single field element
        uint32_t felts_per_item_min =
            uses_tags() ? ItemParams::felts_per_item_min_with_tags : ItemParams::felts_per_item_min;
        if (item_params_.felts_per_item < felts_per_item_min ||
            item_params_.felts_per_item > ItemParams::felts_per_item_max) {
            throw invalid_argument("felts_per_item is too large or too small");
        }
        if (query_params_.ps_low_degree > table_params_.max_items_per_bin) {
            throw invalid_argument("ps_low_degree cannot be larger than max_items_per_bin");
        }
        if (query_params_.query_powers.find(0) != query_params_.query_powers.cend() ||
            query_params_.query_powers.find(1) == query_params_.query_powers.cend()) {
            throw invalid_argument("query_powers cannot contain 0 and must contain 1");
        }
        if (query_params_.query_powers.size() > table_params_.max_items_per_bin) {
            throw invalid_argument("query_powers cannot be larger than max_items_per_bin");
        }
        for (uint32_t p : query_params_.query_powers) {
            if (p > table_params_.max_items_per_bin) {
                throw invalid_argument(
                    "query_powers cannot contain values larger than max_items_per_bin");
            }
            uint32_t ps_high_degree = query_params_.ps_low_degree + 1;
            if ((p > query_params_.ps_low_degree) && (p % ps_high_degree) != 0) {
                throw invalid_argument(
                    "query_powers cannot contain values larger than ps_low_degree that are not "
                    "multiples ps_low_degree + 1");
            }
        }

        // Reject an oversized modulus chain before building anything from it; a SEALContext over
        // these parameters is what the cost would be paid on.
        if (seal_params_.coeff_modulus().size() > coeff_modulus_size_max) {
            throw invalid_argument("coeff_modulus has too many primes");
        }

        // Create a SEALContext (with expand_mod_chain == false) to check validity of parameters
        SEALContext seal_context(seal_params_, false, sec_level_type::tc128);
        if (!seal_context.parameters_set()) {
            stringstream ss;
            ss << "Microsoft SEAL parameters are invalid: "
               << seal_context.parameter_error_message();
            throw invalid_argument(ss.str());
        }
        if (!seal_context.key_context_data()->qualifiers().using_batching) {
            throw invalid_argument(
                "Microsoft SEAL parameters do not support batching; plain_modulus must be a prime "
                "congruent to 1 modulo 2*poly_modulus_degree");
        }

        // Compute the bit-length of an item
        item_bit_count_per_felt_ =
            static_cast<uint32_t>(seal_params_.plain_modulus().bit_count() - 1);
        item_bit_count_ = item_bit_count_per_felt_ * item_params_.felts_per_item;

        if (uses_tags()) {
            if (item_bit_count_ < item_bit_count_min_with_tags ||
                item_bit_count_ > item_bit_count_max) {
                throw invalid_argument(
                    "parameters result in too large or too small item_bit_count");
            }

            // Both factors are bounded above, so this cannot overflow
            tag_bit_count_ = item_params_.tag_part_count * item_bit_count_;
            if (tag_bit_count_ < tag_bit_count_min) {
                throw invalid_argument("parameters result in too small tag_bit_count");
            }

            // A bin may hold max_items_per_bin items, and its label polynomials interpolate
            // through their field elements, which must therefore be distinct; there are only
            // 2^item_bit_count_per_felt of them. The plain modulus has at most 61 bits, so the
            // shift cannot overflow.
            if (table_params_.max_items_per_bin >
                (static_cast<uint64_t>(1) << item_bit_count_per_felt_)) {
                throw invalid_argument(
                    "max_items_per_bin cannot be larger than 2^item_bit_count_per_felt with match "
                    "tags");
            }
        } else if (item_bit_count_ < item_bit_count_min || item_bit_count_ > item_bit_count_max) {
            throw invalid_argument("parameters result in too large or too small item_bit_count");
        }

        // Compute how many items fit into a bundle. If felts_per_item is not a power of two, then
        // we will simply leave a few of the batching slots unused instead of splitting items across
        // multiple SEAL batches.
        items_per_bundle_ =
            static_cast<uint32_t>(seal_params_.poly_modulus_degree()) / item_params_.felts_per_item;

        // Can we fit even one item into the SEAL ciphertext?
        if (!items_per_bundle_) {
            throw invalid_argument("poly_modulus_degree is too small");
        }

        // Compute bins_per_bundle
        bins_per_bundle_ = items_per_bundle_ * item_params_.felts_per_item;

        // table_size must be a multiple of items_per_bundle_
        if (table_params_.table_size % items_per_bundle_) {
            throw invalid_argument(
                "table_size must be a multiple of floor(poly_modulus_degree / felts_per_item)");
        }

        // Compute the number of bundle indices; this is now guaranteed to be greater than zero
        bundle_idx_count_ = table_params_.table_size / items_per_bundle_;

        // Bound the size of the encrypted query these parameters describe. table_size is already
        // bounded above, but query_powers is constrained only by max_items_per_bin, which callers
        // choose freely, so the two must be bounded together as a product rather than separately.
        uint64_t ciphertext_byte_count = static_cast<uint64_t>(2) *
                                         seal_params_.poly_modulus_degree() *
                                         seal_params_.coeff_modulus().size() * sizeof(uint64_t);
        uint64_t ciphertext_count =
            static_cast<uint64_t>(bundle_idx_count_) * query_params_.query_powers.size();

        // Compare by division so that the check itself cannot overflow
        if (ciphertext_count > query_byte_count_max / ciphertext_byte_count) {
            throw invalid_argument("parameters result in too large an encrypted query");
        }
    }

    size_t PSIParams::save(ostream &out) const
    {
        flatbuffers::FlatBufferBuilder fbs_builder(128);

        fbs::ItemParams item_params(item_params_.felts_per_item);

        fbs::TableParams table_params(
            table_params_.table_size,
            table_params_.max_items_per_bin,
            table_params_.hash_func_count);

        // There may or may not be query powers
        vector<uint32_t> query_powers_vec;
        copy(
            query_params_.query_powers.cbegin(),
            query_params_.query_powers.cend(),
            back_inserter(query_powers_vec));
        auto query_powers = fbs_builder.CreateVector(query_powers_vec);
        auto query_params =
            fbs::CreateQueryParams(fbs_builder, query_params_.ps_low_degree, query_powers);

        vector<seal_byte> temp;
        temp.resize(safe_cast<size_t>(seal_params_.save_size(compr_mode_type::none)));
        size_t size =
            static_cast<size_t>(seal_params_.save(temp.data(), temp.size(), compr_mode_type::none));
        auto seal_params_data =
            fbs_builder.CreateVector(reinterpret_cast<const uint8_t *>(temp.data()), size);
        auto seal_params = fbs::CreateSEALParams(fbs_builder, seal_params_data);

        fbs::PSIParamsBuilder psi_params_builder(fbs_builder);

        // Parameters without match tags must serialize exactly as in APSI 1.x, so they leave the
        // tag part count out. A version only APSI 2.0 and later accept marks the parameters that
        // use match tags; see tag_serialization_version.
        psi_params_builder.add_version(
            uses_tags() ? tag_serialization_version : apsi_serialization_version);
        psi_params_builder.add_item_params(&item_params);
        psi_params_builder.add_table_params(&table_params);
        psi_params_builder.add_query_params(query_params);
        psi_params_builder.add_seal_params(seal_params);
        if (uses_tags()) {
            psi_params_builder.add_tag_part_count(item_params_.tag_part_count);
        }
        auto psi_params = psi_params_builder.Finish();
        fbs_builder.FinishSizePrefixed(psi_params);

        out.write(
            reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
            safe_cast<streamsize>(fbs_builder.GetSize()));

        return fbs_builder.GetSize();
    }

    PSIParams::Fingerprint PSIParams::fingerprint() const
    {
        // Hash the canonical encoding the declaration describes. Senders and receivers of other
        // versions must compute the same fingerprint, so changing the encoding needs a new domain.
        vector<unsigned char> bytes;
        auto append_le = [&bytes](uint64_t value, size_t byte_count) {
            for (size_t i = 0; i < byte_count; i++) {
                bytes.push_back(static_cast<unsigned char>(value >> (8 * i)));
            }
        };
        auto append_u8 = [&append_le](uint8_t value) {
            append_le(value, 1);
        };
        auto append_u32 = [&append_le](uint32_t value) {
            append_le(value, 4);
        };
        auto append_u64 = [&append_le](uint64_t value) {
            append_le(value, 8);
        };

        // The domain, without a terminating null
        static constexpr string_view domain = "apsi.params.fingerprint.v1";
        bytes.insert(bytes.end(), domain.begin(), domain.end());

        // The format version and the item parameters; tag_part_count is 0 without match tags
        append_u32(uses_tags() ? tag_serialization_version : apsi_serialization_version);
        append_u32(item_params_.felts_per_item);
        append_u32(item_params_.tag_part_count);

        // The table parameters
        append_u32(table_params_.table_size);
        append_u32(table_params_.max_items_per_bin);
        append_u32(table_params_.hash_func_count);

        // The query parameters, with the powers in increasing order, as the set holds them
        append_u32(query_params_.ps_low_degree);
        append_u32(safe_cast<uint32_t>(query_params_.query_powers.size()));
        for (uint32_t power : query_params_.query_powers) {
            append_u32(power);
        }

        // The Microsoft SEAL parameters
        append_u8(static_cast<uint8_t>(seal_params_.scheme()));
        append_u64(safe_cast<uint64_t>(seal_params_.poly_modulus_degree()));
        append_u64(seal_params_.plain_modulus().value());
        append_u32(safe_cast<uint32_t>(seal_params_.coeff_modulus().size()));
        for (const auto &prime : seal_params_.coeff_modulus()) {
            append_u64(prime.value());
        }

        Fingerprint result{};
        if (APSI_blake2b(result.data(), result.size(), bytes.data(), bytes.size(), nullptr, 0)) {
            throw runtime_error("blake2b failed");
        }

        return result;
    }

    pair<PSIParams, size_t> PSIParams::Load(istream &in)
    {
        vector<unsigned char> in_data(util::read_from_stream(in));

        auto verifier = flatbuffers::Verifier(
            reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
        bool safe = fbs::VerifySizePrefixedPSIParamsBuffer(verifier);
        if (!safe) {
            throw runtime_error("failed to load parameters: invalid buffer");
        }

        const auto *psi_params = fbs::GetSizePrefixedPSIParams(in_data.data());

        // Parameters without match tags carry apsi_serialization_version and no tag part count;
        // parameters with match tags carry tag_serialization_version and a non-zero tag part
        // count. A buffer must be one or the other: in particular, version 1 with a tag part
        // count is refused rather than read as either kind, since APSI 1.x would read it as
        // parameters without them.
        uint32_t version = psi_params->version();
        uint32_t tag_part_count = psi_params->tag_part_count();
        if (!same_serialization_version(version) && (version != tag_serialization_version)) {
            // Check that the serialization version numbers match
            APSI_LOG_ERROR(
                "Loaded PSIParams data indicates a serialization version number ("
                << version << ") incompatible with the current serialization version numbers ("
                << apsi_serialization_version << " without match tags and "
                << tag_serialization_version << " with them)");
            throw runtime_error("failed to load parameters: incompatible serialization version");
        }
        if ((version == tag_serialization_version) != (tag_part_count != 0)) {
            APSI_LOG_ERROR(
                "Loaded PSIParams data indicates a serialization version number ("
                << version << ") that does not match its tag part count (" << tag_part_count
                << "); parameters with match tags must have version " << tag_serialization_version
                << " and parameters without them version " << apsi_serialization_version);
            throw runtime_error(
                "failed to load parameters: serialization version does not match tag part count");
        }

        // The schema marks each of these required, so a buffer reaching this point has already
        // been through a verifier that rejects any omission. Checking again costs a handful of
        // predictable branches and keeps the guarantee local: these accessors are dereferenced
        // unconditionally below, and the data behind them comes from the sender, whom the
        // receiver does not trust.
        if (!psi_params->item_params() || !psi_params->table_params() ||
            !psi_params->query_params() || !psi_params->query_params()->query_powers() ||
            !psi_params->seal_params() || !psi_params->seal_params()->data()) {
            APSI_LOG_ERROR("Loaded PSIParams data is missing one or more required fields");
            throw runtime_error("failed to load parameters: missing required field");
        }

        PSIParams::ItemParams item_params;
        item_params.felts_per_item = psi_params->item_params()->felts_per_item();
        item_params.tag_part_count = tag_part_count;

        PSIParams::TableParams table_params;
        table_params.table_size = psi_params->table_params()->table_size();
        table_params.max_items_per_bin = psi_params->table_params()->max_items_per_bin();
        table_params.hash_func_count = psi_params->table_params()->hash_func_count();

        PSIParams::QueryParams query_params;
        query_params.ps_low_degree = psi_params->query_params()->ps_low_degree();

        // Screen the count before materializing the set. initialize() rejects a query_powers
        // larger than max_items_per_bin, but only once a PSIParams object exists, and building
        // one means inserting every element into a node-per-element container first. Parameters
        // are the first thing a receiver accepts from a sender, so this vector is attacker-chosen
        // input arriving before anything has been agreed; the FlatBuffers verifier bounds a
        // scalar vector's extent but not its length, leaving a modest frame able to cost orders
        // of magnitude more in heap. max_items_per_bin_max is the ceiling of the bound
        // initialize() will apply, so nothing legitimate is refused here.
        if (psi_params->query_params()->query_powers()->size() >
            TableParams::max_items_per_bin_max) {
            APSI_LOG_ERROR(
                "Loaded PSIParams data indicates a query_powers count ("
                << psi_params->query_params()->query_powers()->size()
                << ") larger than the maximum supported (" << TableParams::max_items_per_bin_max
                << ")");
            throw runtime_error("failed to load parameters: query_powers is too large");
        }

        copy(
            psi_params->query_params()->query_powers()->cbegin(),
            psi_params->query_params()->query_powers()->cend(),
            inserter(query_params.query_powers, query_params.query_powers.end()));

        PSIParams::SEALParams seal_params;
        const auto &seal_params_data = *psi_params->seal_params()->data();
        try {
            seal_params.load(
                reinterpret_cast<const seal_byte *>(seal_params_data.data()),
                seal_params_data.size());
        } catch (const logic_error &ex) {
            stringstream ss;
            ss << "failed to load parameters: ";
            ss << ex.what();
            throw runtime_error(ss.str());
        } catch (const runtime_error &ex) {
            stringstream ss;
            ss << "failed to load parameters: ";
            ss << ex.what();
            throw runtime_error(ss.str());
        }

        if (seal_params.scheme() != scheme_type::bfv) {
            throw runtime_error("failed to load parameters: invalid scheme type");
        }

        return { PSIParams(item_params, table_params, query_params, seal_params), in_data.size() };
    }
#ifndef APSI_DISABLE_JSON
    PSIParams PSIParams::Load(const string &in)
    {
        // Parse JSON string
        Json::Value root;
        stringstream ss(in);
        ss >> root;

        // A parameter file may name the version of the serialized parameters it describes. The key
        // is optional for parameters without match tags, as the parameter files of APSI 1.x leave
        // it out, but a file that names a version this build does not implement is refused here
        // rather than at the first exchange with a peer, where the mismatch would otherwise first
        // appear. Whether the version agrees with the tag part count is checked once item_params
        // has been read.
        const auto &json_version = root["version"];
        bool has_version = !json_version.isNull();
        uint32_t version = 0;
        if (has_version) {
            version = json_value_ui32(json_version);
            if (!same_serialization_version(version) && (version != tag_serialization_version)) {
                stringstream err;
                err << "parameters are written for serialization version " << version
                    << ", which is incompatible with the serialization versions this build "
                    << "implements (" << apsi_serialization_version << " without match tags and "
                    << tag_serialization_version << " with them)";
                throw runtime_error(err.str());
            }
        }

        // Load TableParams
        PSIParams::TableParams table_params;
        try {
            const auto &json_table_params = get_non_null_json_value(root, "table_params");
            table_params.hash_func_count = json_value_ui32(json_table_params, "hash_func_count");
            table_params.table_size = json_value_ui32(json_table_params, "table_size");
            table_params.max_items_per_bin =
                json_value_ui32(json_table_params, "max_items_per_bin");
        } catch (const exception &ex) {
            APSI_LOG_ERROR("Failed to load table_params from JSON string: " << ex.what());
            throw;
        }

        // Load ItemParams
        PSIParams::ItemParams item_params;
        try {
            const auto &json_item_params = get_non_null_json_value(root, "item_params");
            item_params.felts_per_item = json_value_ui32(json_item_params, "felts_per_item");

            // Optional: leaving it out, or setting it to zero, selects parameters without match
            // tags
            const auto &json_tag_part_count = json_item_params["tag_part_count"];
            if (!json_tag_part_count.isNull()) {
                item_params.tag_part_count = json_value_ui32(json_tag_part_count);
            }
        } catch (const exception &ex) {
            APSI_LOG_ERROR("Failed to load item_params from JSON string: " << ex.what());
            throw;
        }

        // A file with match tags must name tag_serialization_version, and a file without them must
        // not; see the declaration for why
        bool tag_version = has_version && (version == tag_serialization_version);
        if (tag_version != (item_params.tag_part_count != 0)) {
            stringstream err;
            err << "parameters with tag_part_count " << item_params.tag_part_count;
            if (has_version) {
                err << " name serialization version " << version;
            } else {
                err << " name no serialization version";
            }
            err << "; parameters with match tags must name version " << tag_serialization_version
                << " and parameters without them version " << apsi_serialization_version
                << " or none";
            throw runtime_error(err.str());
        }

        // Load QueryParams
        PSIParams::QueryParams query_params;
        try {
            const auto &json_query_params = get_non_null_json_value(root, "query_params");
            query_params.ps_low_degree = json_value_ui32(json_query_params, "ps_low_degree");
            const auto &query_powers = get_non_null_json_value(json_query_params, "query_powers");

            // Should always contain 1
            query_params.query_powers.insert(1);
            for (const auto &power : query_powers) {
                query_params.query_powers.insert(json_value_ui32(power));
            }
        } catch (const exception &ex) {
            APSI_LOG_ERROR("Failed to load query_params from JSON string: " << ex.what());
            throw;
        }

        // Load SEALParams
        PSIParams::SEALParams seal_params;
        try {
            const auto &json_seal_params = get_non_null_json_value(root, "seal_params");
            const auto &coeff_modulus_bits =
                get_non_null_json_value(json_seal_params, "coeff_modulus_bits");

            size_t poly_modulus_degree = json_value_ui64(json_seal_params, "poly_modulus_degree");
            seal_params.set_poly_modulus_degree(poly_modulus_degree);

            if (json_seal_params.isMember("plain_modulus") &&
                json_seal_params.isMember("plain_modulus_bits")) {
                throw runtime_error(
                    "only one of plain_modulus and plain_modulus_bits must be specified");
            }
            if (json_seal_params.isMember("plain_modulus")) {
                seal_params.set_plain_modulus(json_value_ui64(json_seal_params, "plain_modulus"));
            } else if (json_seal_params.isMember("plain_modulus_bits")) {
                // Microsoft SEAL returns the largest prime of this width. A smaller one of the
                // same width would describe the same items and leave more noise budget, which is
                // why the parameter sets APSI ships name their plain modulus outright rather
                // than by width.
                seal_params.set_plain_modulus(
                    PlainModulus::Batching(
                        poly_modulus_degree,
                        json_value_int(json_seal_params, "plain_modulus_bits")));
            } else {
                throw runtime_error("neither plain_modulus nor plain_modulus_bits was specified");
            }

            vector<int> coeff_modulus_bit_sizes;
            for (const auto &coeff : coeff_modulus_bits) {
                coeff_modulus_bit_sizes.push_back(json_value_int(coeff));
            }
            seal_params.set_coeff_modulus(
                CoeffModulus::Create(poly_modulus_degree, coeff_modulus_bit_sizes));

        } catch (const exception &ex) {
            APSI_LOG_ERROR("Failed to load seal_params from JSON string: " << ex.what());
            throw;
        }

        return { item_params, table_params, query_params, seal_params };
    }
#else
    PSIParams PSIParams::Load(const string &in)
    {
        throw runtime_error("JSON parameter initialization is disabled");
    }
#endif
    string PSIParams::to_string() const
    {
        stringstream ss;
        ss << "item_params.felts_per_item: " << item_params_.felts_per_item;

        // Parameters without match tags describe themselves exactly as in APSI 1.x
        if (uses_tags()) {
            ss << "; item_params.tag_part_count: " << item_params_.tag_part_count;
        }

        ss << "; table_params.table_size: " << table_params_.table_size
           << "; table_params.max_items_per_bin: " << table_params_.max_items_per_bin
           << "; table_params.hash_func_count: " << table_params_.hash_func_count
           << "; query_params.ps_low_degree: " << query_params_.ps_low_degree
           << "; query_params.query_powers: " << util::to_string(query_params_.query_powers)
           << "; seal_params.poly_modulus_degree: " << seal_params_.poly_modulus_degree()
           << "; seal_params.coeff_modulus: "
           << util::to_string(
                  seal_params_.coeff_modulus(),
                  [](const Modulus &mod) { return std::to_string(mod.bit_count()); })
           << "; seal_params.plain_modulus: " << seal_params_.plain_modulus().value();

        return ss.str();
    }
} // namespace apsi
