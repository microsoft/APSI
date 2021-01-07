// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <string>

// APSI
#include "apsi/psi_params.h"
#include "apsi/psi_params_generated.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/defines.h"
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    void PSIParams::initialize()
    {
        // Checking the validity of parameters
        if (!table_params_.table_size || (table_params_.table_size & (table_params_.table_size - 1)))
        {
            throw invalid_argument("table_size is not a power of two");
        }
        if (!table_params_.max_items_per_bin)
        {
            throw invalid_argument("max_items_per_bin cannot be zero");
        }
        if (table_params_.hash_func_count < TableParams::hash_func_count_min ||
            table_params_.hash_func_count > TableParams::hash_func_count_max)
        {
            throw invalid_argument("hash_func_count is too large or too small");
        }
        if (item_params_.felts_per_item < ItemParams::felts_per_item_min ||
            item_params_.felts_per_item > ItemParams::felts_per_item_max)
        {
            throw invalid_argument("felts_per_item is too large or too small");
        }
        if (!item_params_.felts_per_item || (item_params_.felts_per_item & (item_params_.felts_per_item - 1)))
        {
            throw invalid_argument("felts_per_item is not a power of two");
        }
        if (query_params_.query_powers.find(0) != query_params_.query_powers.cend() ||
            query_params_.query_powers.find(1) == query_params_.query_powers.cend())
        {
            throw invalid_argument("query_powers cannot contain 0 and must contain 1");
        }
        if (query_params_.query_powers.size() > table_params_.max_items_per_bin)
        {
            throw invalid_argument("query_powers is too large");
        }
        if (!seal_params_.plain_modulus().is_prime() || seal_params_.plain_modulus().value() == 2)
        {
            throw invalid_argument("plain_modulus is not an odd prime");
        }
        if (!seal_params_.poly_modulus_degree() ||
            (seal_params_.poly_modulus_degree() & (seal_params_.poly_modulus_degree() - 1)))
        {
            throw invalid_argument("poly_modulus_degree is not a power of two");
        }

        // Compute the bit-length of an item
        item_bit_count_per_felt_ = seal_params_.plain_modulus().bit_count() - 1;
        item_bit_count_ = item_bit_count_per_felt_ * item_params_.felts_per_item;

        if (item_bit_count_ < item_bit_count_min || item_bit_count_ > item_bit_count_max)
        {
            throw invalid_argument("parameters result in too large or too small item_bit_count");
        }

        // Compute how many items fit into a bundle. The division must be exact, i.e., the number
        // of field elements per item must be a power of two and divide poly_modulus_degree.
        items_per_bundle_ =
            static_cast<uint32_t>(seal_params_.poly_modulus_degree()) / item_params_.felts_per_item;

        // Can we fit even one item into the SEAL ciphertext?
        if (!items_per_bundle_)
        {
            throw invalid_argument("poly_modulus_degree is too small");
        }

        // table_size must divide items_per_bundle; it suffices to test that table_size is not smaller
        if (table_params_.table_size < items_per_bundle_)
        {
            throw invalid_argument("table_size is too small");
        }

        // Compute the number of bundle indices; this is now guaranteed to be greater than zero
        bundle_idx_count_ = (table_params_.table_size + items_per_bundle_ - 1) / items_per_bundle_;
    }

    size_t SaveParams(const PSIParams &params, ostream &out)
    {
        flatbuffers::FlatBufferBuilder fbs_builder(1024);

        fbs::ItemParams item_params(params.item_params().felts_per_item);

        fbs::TableParams table_params(
            params.table_params().table_size,
            params.table_params().max_items_per_bin,
            params.table_params().hash_func_count);

        // There may or may not be query powers
        vector<uint32_t> query_powers_vec;
        copy(
            params.query_params().query_powers.cbegin(),
            params.query_params().query_powers.cend(),
            back_inserter(query_powers_vec));
        auto query_powers = fbs_builder.CreateVector(query_powers_vec);
        auto query_params = fbs::CreateQueryParams(fbs_builder, query_powers);

        vector<seal_byte> temp;
        temp.resize(params.seal_params().save_size(compr_mode_type::zstd));
        auto size = params.seal_params().save(temp.data(), temp.size(), compr_mode_type::zstd);
        auto seal_params_data = fbs_builder.CreateVector(reinterpret_cast<uint8_t*>(temp.data()), size);
        auto seal_params = fbs::CreateSEALParams(fbs_builder, seal_params_data);

        fbs::PSIParamsBuilder psi_params_builder(fbs_builder);
        psi_params_builder.add_item_params(&item_params);
        psi_params_builder.add_table_params(&table_params);
        psi_params_builder.add_query_params(query_params);
        psi_params_builder.add_seal_params(seal_params);
        auto psi_params = psi_params_builder.Finish();
        fbs_builder.FinishSizePrefixed(psi_params);

        out.write(
            reinterpret_cast<const char*>(fbs_builder.GetBufferPointer()),
            safe_cast<streamsize>(fbs_builder.GetSize()));

        return fbs_builder.GetSize();
    }

    pair<PSIParams, size_t> LoadParams(istream &in)
    {
        vector<seal_byte> in_data(util::read_from_stream(in));

        auto verifier = flatbuffers::Verifier(reinterpret_cast<const uint8_t*>(in_data.data()), in_data.size());
        bool safe = fbs::VerifySizePrefixedPSIParamsBuffer(verifier);
        if (!safe)
        {
            throw runtime_error("failed to load parameters: invalid buffer");
        }

        auto psi_params = fbs::GetSizePrefixedPSIParams(in_data.data());

        PSIParams::ItemParams item_params;
        item_params.felts_per_item = psi_params->item_params()->felts_per_item();

        PSIParams::TableParams table_params;
        table_params.table_size = psi_params->table_params()->table_size();
        table_params.max_items_per_bin = psi_params->table_params()->max_items_per_bin();
        table_params.hash_func_count = psi_params->table_params()->hash_func_count();

        PSIParams::QueryParams query_params;
        copy(
            psi_params->query_params()->query_powers()->cbegin(),
            psi_params->query_params()->query_powers()->cend(),
            inserter(query_params.query_powers, query_params.query_powers.end()));

        PSIParams::SEALParams seal_params;
        auto &seal_params_data = *psi_params->seal_params()->data();
        try
        {
            seal_params.load(reinterpret_cast<const seal_byte *>(seal_params_data.data()), seal_params_data.size());
        }
        catch (const logic_error &ex)
        {
            stringstream ss;
            ss << "failed to load parameters: ";
            ss << ex.what();
            throw runtime_error(ss.str());
        }
        catch (const runtime_error &ex)
        {
            stringstream ss;
            ss << "failed to load parameters: ";
            ss << ex.what();
            throw runtime_error(ss.str());
        }

        if (seal_params.scheme() != scheme_type::bfv)
        {
            throw runtime_error("failed to load parameters: invalid scheme type");
        }

        return make_pair(
            PSIParams(item_params, table_params, query_params, seal_params),
            in_data.size());
    }

    string PSIParams::to_string() const
    {
        stringstream ss;
        ss << "item_params.felts_per_item: " << item_params_.felts_per_item
            << "; table_params.table_size: " << table_params_.table_size
            << "; table_params.max_items_per_bin: " << table_params_.max_items_per_bin
            << "; table_params.hash_func_count: " << table_params_.hash_func_count
            << "; query_params.query_powers: "
            << util::to_string(query_params_.query_powers)
            << "; seal_params.poly_modulus_degree: " << seal_params_.poly_modulus_degree()
            << "; seal_params.coeff_modulus: "
            << util::to_string(
                seal_params_.coeff_modulus(),
                [](const Modulus &mod) { return std::to_string(mod.bit_count()); })
            << "; seal_params.plain_modulus: " << seal_params_.plain_modulus().value();

        return ss.str();
    }
}
