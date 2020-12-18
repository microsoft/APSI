// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <functional>

// APSI
#include "apsi/oprf/ecpoint.h"

// FourQ
#include "apsi/fourq/FourQ_internal.h"
#include "apsi/fourq/FourQ_api.h"

// SEAL
#include "seal/util/blake2.h"

using namespace std;
using namespace seal;

namespace apsi
{
    namespace oprf
    {
        namespace
        {
            void random_scalar(ECPoint::scalar_span_type value, shared_ptr<UniformRandomGenerator> rg)
            {
                if (rg)
                {
                    rg->generate(ECPoint::order_size, reinterpret_cast<seal_byte *>(value.data()));
                }
                else
                {
                    uint64_t *value_ptr = reinterpret_cast<uint64_t *>(value.data());
                    value_ptr[0] = random_uint64();
                    value_ptr[1] = random_uint64();
                    value_ptr[2] = random_uint64();
                    value_ptr[3] = random_uint64();
                }
                
                modulo_order(reinterpret_cast<digit_t *>(value.data()), reinterpret_cast<digit_t *>(value.data()));
            }

            digit_t is_nonzero_scalar(ECPoint::scalar_span_type value)
            {
                const digit_t *value_ptr = reinterpret_cast<digit_t *>(value.data());
                digit_t c = 0;

                for (size_t i = 0; i < NWORDS_ORDER; i++)
                {
                    c |= value_ptr[i];
                }

                sdigit_t first_nz = -static_cast<sdigit_t>(c & 1);
                sdigit_t rest_nz = -static_cast<sdigit_t>(c >> 1);
                return static_cast<digit_t>((first_nz | rest_nz) >> (8 * sizeof(digit_t) - 1)); 
            }
        }

        ECPoint::ECPoint(input_span_const_type value)
        {
            if (!value.empty())
            {
                f2elm_t r;

                // Compute a Blake2b hash of the value
                blake2b(
                    reinterpret_cast<unsigned char *>(r), sizeof(f2elm_t), value.data(),
                    static_cast<size_t>(value.size()), nullptr, 0);

                // Reduce r
                mod1271(r[0]);
                mod1271(r[1]);

                // Create an elliptic curve point
                HashToCurve(r, pt_);
            }
        }

        void ECPoint::make_random_nonzero_scalar(scalar_span_type out, shared_ptr<UniformRandomGenerator> rg)
        {
            // Loop until we find a non-zero element
            do
            {
                random_scalar(out, rg);
            }
            while (!is_nonzero_scalar(out));
        }

        void ECPoint::invert_scalar(scalar_span_const_type in, scalar_span_type out)
        {
            to_Montgomery(
                const_cast<digit_t *>(reinterpret_cast<const digit_t *>(in.data())),
                reinterpret_cast<digit_t *>(out.data()));
            Montgomery_inversion_mod_order(
                reinterpret_cast<digit_t *>(out.data()), reinterpret_cast<digit_t *>(out.data()));
            from_Montgomery(reinterpret_cast<digit_t *>(out.data()), reinterpret_cast<digit_t *>(out.data()));
        }

        bool ECPoint::scalar_multiply(gsl::span<const unsigned char, order_size> scalar, bool clear_cofactor)
        {
            // The ecc_mul functions returns false when the input point is not a valid curve point
            return ecc_mul(
                pt_,
                const_cast<digit_t *>(reinterpret_cast<const digit_t *>(scalar.data())),
                pt_,
                clear_cofactor);
        }

        ECPoint &ECPoint::operator=(const ECPoint &assign)
        {
            if (&assign != this)
            {
                memcpy(pt_, assign.pt_, point_size);
            }
            return *this;
        }

        void ECPoint::save(ostream &stream)
        {
            auto old_ex_mask = stream.exceptions();
            stream.exceptions(ios_base::failbit | ios_base::badbit);

            try
            {
                array<unsigned char, save_size> buf;
                encode(pt_, buf.data());
                stream.write(reinterpret_cast<const char *>(buf.data()), save_size);
            }
            catch (const ios_base::failure &)
            {
                stream.exceptions(old_ex_mask);
                throw;
            }
            stream.exceptions(old_ex_mask);
        }

        void ECPoint::load(istream &stream)
        {
            auto old_ex_mask = stream.exceptions();
            stream.exceptions(ios_base::failbit | ios_base::badbit);

            try
            {
                array<unsigned char, save_size> buf;
                stream.read(reinterpret_cast<char *>(buf.data()), save_size);
                if (decode(buf.data(), pt_) != ECCRYPTO_SUCCESS)
                {
                    stream.exceptions(old_ex_mask);
                    throw logic_error("invalid point");
                }
            }
            catch (const ios_base::failure &)
            {
                stream.exceptions(old_ex_mask);
                throw;
            }
            stream.exceptions(old_ex_mask);
        }

        void ECPoint::save(point_save_span_type out)
        {
            encode(pt_, out.data());
        }

        void ECPoint::load(point_save_span_const_type in)
        {
            if (decode(in.data(), pt_) != ECCRYPTO_SUCCESS)
            {
                throw logic_error("invalid point");
            }
        }

        void ECPoint::extract_hash(hash_span_type out)
        {
            // Compute a Blake2b hash of the value and expand to hash_size
            blake2b(out.data(), out.size(), pt_->y, sizeof(f2elm_t), nullptr, 0);
        }
    } // namespace oprf
} // namespace apsi
