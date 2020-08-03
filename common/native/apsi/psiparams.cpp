// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <sstream>
#include <stdexcept>

// APSI
#include "apsi/psiparams.h"
#include "apsi/psiparams_generated.h"
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
        if (table_params_.table_size & (table_params_.table_size - 1))
        {
            throw invalid_argument("table_size is not a power of two");
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

        if (!items_per_bundle_)
        {
            throw invalid_argument("table_size is too small");
        }

        // Finally compute the number of bundle indices
        bundle_idx_count_ = (table_params_.table_size + items_per_bundle_ - 1) / items_per_bundle_;
    }

    size_t SaveParams(const PSIParams &params, ostream &out)
    {
        flatbuffers::FlatBufferBuilder fbs_builder(1024);
        fbs::PSIParamsBuilder psi_params_builder(fbs_builder);

        fbs::ItemParams item_params(params.item_params().felts_per_item);
        psi_params_builder.add_item_params(&item_params);

        fbs::TableParams table_params(
            params.table_params().table_size,
            params.table_params().window_size,
            params.table_params().max_items_per_bin,
            params.table_params().hash_func_count);
        psi_params_builder.add_table_params(&table_params);

        vector<SEAL_BYTE> temp;
        temp.resize(params.seal_params().save_size(compr_mode_type::deflate));
        auto size = params.seal_params().save(temp.data(), temp.size(), compr_mode_type::deflate);
        auto seal_params_data = fbs_builder.CreateVector(reinterpret_cast<uint8_t*>(temp.data()), size);
        auto seal_params = fbs::CreateSEALParams(fbs_builder, seal_params_data);
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
        vector<SEAL_BYTE> in_data(util::read_from_stream(in));

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
        table_params.window_size = psi_params->table_params()->window_size();
        table_params.max_items_per_bin = psi_params->table_params()->max_items_per_bin();
        table_params.hash_func_count = psi_params->table_params()->hash_func_count();

        EncryptionParameters seal_params;
        auto &seal_params_data = *psi_params->seal_params()->data();
        try
        {
            seal_params.load(reinterpret_cast<const SEAL_BYTE *>(seal_params_data.data()), seal_params_data.size());
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

        if (seal_params.scheme() != scheme_type::BFV)
        {
            throw runtime_error("failed to load parameters: invalid scheme type");
        }

        return make_pair(PSIParams(item_params, table_params, seal_params), in_data.size());
    }

    string PSIParams::to_string() const
    {
        stringstream ss;
        ss << "item_params.felts_per_item: " << item_params_.felts_per_item << endl;
        ss << "table_params.table_size: " << table_params_.table_size << endl;
        ss << "table_params.window_size: " << table_params_.window_size << endl;
        ss << "table_params.max_items_per_bin: " << table_params_.max_items_per_bin << endl;
        ss << "table_params.hash_func_count: " << table_params_.hash_func_count << endl;
        ss << "seal_params.poly_modulus_degree: " << seal_params_.poly_modulus_degree() << endl;
        ss << "seal_params.coeff_modulus: [ " << endl;
        for (auto &mod : seal_params_.coeff_modulus())
        {
            ss << mod.bit_count();
        }
        ss << " ]" << endl;
        ss << "seal_params.plain_modulus: " << seal_params_.plain_modulus().value() << endl;

        return ss.str();
    }
}
