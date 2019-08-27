// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <iostream>

// APSI
#include "apsi/ffield/ffield_fast_batch_encoder.h"
#include "apsi/ffield/ffield_array.h"

// SEAL
#include <seal/util/common.h>
#include <seal/util/uintcore.h>

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace gsl;


namespace apsi
{
    FFieldFastBatchEncoder::FFieldFastBatchEncoder(
        std::shared_ptr<seal::SEALContext> context, FField field) :
        encoder_(make_unique<BatchEncoder>(context)),
        field_(field),
        n_(context->context_data()->parms().poly_modulus_degree()),
        log_n_(get_power_of_two(n_)),
        m_(2 * n_),
        slot_count_(n_ / field_.d_)
    {
        // Check that degree of extension field is a power of 2 and divides n_
        if (n_ % field_.d_)
        {
            throw invalid_argument("field degree must divide poly_modulus_degree");
        } 
    }

    void FFieldFastBatchEncoder::compose(const FFieldArray &values, Plaintext &destination) const
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

    void FFieldFastBatchEncoder::decompose(const Plaintext &plain, FFieldArray &destination) const
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
}
