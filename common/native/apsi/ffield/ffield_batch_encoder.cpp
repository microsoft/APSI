// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "apsi/ffield/ffield_batch_encoder.h"
#include <iostream>
#include <seal/util/common.h>
#include <seal/util/uintcore.h>

using namespace std;
using namespace seal;

namespace apsi
{
    FFieldBatchEncoder::FFieldBatchEncoder(shared_ptr<SEALContext> context, FField field)
        : encoder_(make_unique<BatchEncoder>(context)), field_(field),
          n_(context->first_context_data()->parms().poly_modulus_degree()), log_n_(util::get_power_of_two(n_)),
          m_(2 * n_), slot_count_(n_ / field_.degree_)
    {
        // Check that degree of extension field is a power of 2 and divides n_
        if (n_ % field_.degree_)
        {
            throw invalid_argument("field degree must divide poly_modulus_degree");
        }
    }

    void FFieldBatchEncoder::compose(const FFieldArray &values, Plaintext &destination) const
    {
        if (values.size_ != slot_count_)
        {
            throw invalid_argument("values has incorrect size");
        }
        if (values.field_ != field_)
        {
            throw invalid_argument("field mismatch");
        }
        encoder_->encode(values.array_, destination);
    }

    void FFieldBatchEncoder::decompose(const Plaintext &plain, FFieldArray &destination) const
    {
        if (destination.size_ != slot_count_)
        {
            throw invalid_argument("destination has incorrect size");
        }
        if (destination.field_ != field_)
        {
            throw invalid_argument("field mismatch");
        }
        encoder_->decode(plain, destination.array_);
    }
} // namespace apsi
