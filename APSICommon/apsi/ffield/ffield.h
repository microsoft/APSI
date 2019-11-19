// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <vector>
#include <memory>
#include <seal/smallmodulus.h>
#include "apsi/apsidefines.h"

namespace apsi
{
    using _ch_t = seal::SmallModulus;
    using _ffield_elt_coeff_t = u64; 
    using _ffield_elt_t = std::vector<_ffield_elt_coeff_t>;
   
    class FFieldElt;

    class FField
    {
        friend class FFieldElt;
        friend class FFieldArray;
        friend class FFieldFastBatchEncoder;

    public:
        FField(_ch_t ch, u64 d) : ch_(ch), d_(d)
        {
        }

        inline const _ch_t &ch() const
        {
            return ch_;
        }

        inline u64 d() const
        {
            return d_;
        }

        inline bool operator ==(const FField &compare) const
        {
            return (this == &compare) || 
                ((ch_ == compare.ch_) && (d_ == compare.d_));
        }

        inline bool operator !=(const FField &compare) const
        {
            return !operator ==(compare);
        }

        FFieldElt zero();

        FFieldElt one();

    private:
        _ch_t ch_;
        u64 d_;
    }; // class FField
} // namespace apsi
