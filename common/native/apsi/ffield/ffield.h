// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <seal/modulus.h>
#include <vector>

namespace apsi
{
    class FFieldElt;

    class FField
    {
        friend class FFieldElt;
        friend class FFieldArray;
        friend class FFieldBatchEncoder;

    public:
        using CharacteristicType = seal::Modulus;

        FField(CharacteristicType ch, std::uint32_t d) : characteristic_(ch), degree_(d)
        {}

        inline const CharacteristicType &characteristic() const
        {
            return characteristic_;
        }

        inline std::uint32_t degree() const
        {
            return degree_;
        }

        inline bool operator==(const FField &compare) const
        {
            return (this == &compare) || ((characteristic_ == compare.characteristic_) && (degree_ == compare.degree_));
        }

        inline bool operator!=(const FField &compare) const
        {
            return !operator==(compare);
        }

        FFieldElt zero();

        FFieldElt one();

    private:
        CharacteristicType characteristic_;
        std::uint32_t degree_;
    }; // class FField
} // namespace apsi
