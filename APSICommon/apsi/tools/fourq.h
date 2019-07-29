// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#pragma once

// APSI
#include "apsi/apsidefines.h"
#include "apsi/tools/prng.h"

// FourQ
#include "FourQ_params.h"


namespace apsi
{
    namespace tools
    {
        /**
        Represents a coordinate for a FourQ elliptic curve
        */
        class FourQCoordinate
        {
        public:
            /**
            Constructor
            */
            FourQCoordinate();

            /**
            Constructor that initializes the coordinate from a word array
            */
            FourQCoordinate(const apsi::u64* buffer);

            /**
            Constructor that generates a random coordinate within FourQ's order
            */
            FourQCoordinate(apsi::tools::PRNG& prng);

            /**
            Get coordinate data
            */
            const apsi::u64* data() const;

            /**
            Get coordinate data
            */
            apsi::u64* data();

            /**
            Number of bytes used by a FourQ coordinate
            */
            constexpr static unsigned int byte_count()
            {
                return sizeof(f2elm_t);
            }

            /**
            Number of 64 bit words used by a FourQ coordinate
            */
            constexpr static unsigned int word_count()
            {
                return NWORDS_ORDER;
            }

            /**
            Save coordinate to a byte buffer
            */
            void to_buffer(apsi::u8* buffer) const;

            /**
            Initialize coordinate from a byte buffer
            */
            void from_buffer(const apsi::u8* buffer);

            /**
            Initialize this coordinate with a random value within FourQ's order
            */
            void random(apsi::tools::PRNG& prng);

            /**
            Multiply
            */
            void multiply_mod_order(const FourQCoordinate& other);

            /**
            Multiply
            */
            void multiply_mod_order(const u64* other);

            /**
            Inversion
            */
            void inversion_mod_order();


        private:
            digit_t coord_[NWORDS_ORDER];
        };
    }
}
