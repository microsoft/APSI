// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <functional>

// APSI
#include "apsi/oprf/ecpoint.h"
#include "apsi/util/utils.h"

// FourQ
#include "apsi/fourq/FourQ.h"
#include "apsi/fourq/FourQ_api.h"
#include "apsi/fourq/FourQ_internal.h"
#include "apsi/fourq/random.h"

// SEAL
#include "seal/randomgen.h"
#include "seal/util/blake2.h"

using namespace std;
using namespace seal;

namespace apsi {
    namespace oprf {
        // Ensure our size constants are correct
        static_assert(ECPoint::save_size == sizeof(f2elm_t));
        static_assert(ECPoint::point_size == sizeof(point_t));
        static_assert(ECPoint::order_size == sizeof(digit_t) * NWORDS_ORDER);

        namespace {
            constexpr point_t neutral = { { { { 0 } }, { { 1 } } } }; // { {.x = { 0 }, .y = { 1 } }};

            void set_neutral_point(ECPoint::point_span_type pt) {
                copy_n(reinterpret_cast<const unsigned char *>(neutral), ECPoint::point_size, pt.data());
            }

            void fourq_point_to_point_type(const point_t fourq_pt, ECPoint::point_span_type pt) {
                copy_n(reinterpret_cast<const unsigned char *>(fourq_pt), ECPoint::point_size, pt.data());
            }

            void point_type_to_fourq_point(ECPoint::point_span_const_type pt, point_t fourq_pt) {
                copy_n(pt.data(), ECPoint::point_size, reinterpret_cast<unsigned char *>(fourq_pt));
            }

            void random_scalar(ECPoint::scalar_span_type value)
            {
                random_bytes(value.data(), seal::util::safe_cast<unsigned int>(value.size()));
                modulo_order(
                    reinterpret_cast<digit_t *>(value.data()),
                    reinterpret_cast<digit_t *>(value.data()));
            }

            digit_t is_nonzero_scalar(ECPoint::scalar_span_type value)
            {
                const digit_t *value_ptr = reinterpret_cast<digit_t *>(value.data());
                digit_t c = 0;

                for (size_t i = 0; i < NWORDS_ORDER; i++) {
                    c |= value_ptr[i];
                }

                sdigit_t first_nz = -static_cast<sdigit_t>(c & 1);
                sdigit_t rest_nz = -static_cast<sdigit_t>(c >> 1);
                return static_cast<digit_t>((first_nz | rest_nz) >> (8 * sizeof(digit_t) - 1));
            }
        } // namespace

        ECPoint::ECPoint()
        {
            set_neutral_point(pt_);
        }

        ECPoint::ECPoint(input_span_const_type value)
        {
            if (!value.empty()) {
                f2elm_t r;

                // Compute a Blake2b hash of the value
                APSI_blake2b(
                    reinterpret_cast<unsigned char *>(r),
                    sizeof(f2elm_t),
                    value.data(),
                    static_cast<size_t>(value.size()),
                    nullptr,
                    0);

                // Reduce r; note that this does not produce a perfectly uniform distribution modulo
                // 2^127-1, but it is good enough.
                mod1271(r[0]);
                mod1271(r[1]);

                // Create an elliptic curve point
                point_t pt;
                HashToCurve(r, pt);
                fourq_point_to_point_type(pt, pt_);
            }
        }

        void ECPoint::MakeRandomNonzeroScalar(scalar_span_type out)
        {
            // Loop until we find a non-zero element
            do {
                random_scalar(out);
            } while (!is_nonzero_scalar(out));
        }

        void ECPoint::InvertScalar(scalar_span_const_type in, scalar_span_type out)
        {
            to_Montgomery(
                const_cast<digit_t *>(reinterpret_cast<const digit_t *>(in.data())),
                reinterpret_cast<digit_t *>(out.data()));
            Montgomery_inversion_mod_order(
                reinterpret_cast<digit_t *>(out.data()), reinterpret_cast<digit_t *>(out.data()));
            from_Montgomery(
                reinterpret_cast<digit_t *>(out.data()), reinterpret_cast<digit_t *>(out.data()));
        }

        bool ECPoint::scalar_multiply(scalar_span_const_type scalar, bool clear_cofactor)
        {
            // The ecc_mul functions returns false when the input point is not a valid curve point
            point_t pt_P, pt_Q;
            point_type_to_fourq_point(pt_, pt_P);
            bool ret = ecc_mul(
                pt_P,
                const_cast<digit_t *>(reinterpret_cast<const digit_t *>(scalar.data())),
                pt_Q,
                clear_cofactor);
            fourq_point_to_point_type(pt_Q, pt_);
            return ret;
        }

        ECPoint &ECPoint::operator=(const ECPoint &assign)
        {
            if (&assign != this) {
                pt_[0] = assign.pt_[0];
            }
            return *this;
        }

        void ECPoint::save(ostream &stream) const
        {
            auto old_ex_mask = stream.exceptions();
            stream.exceptions(ios_base::failbit | ios_base::badbit);

            try {
                array<unsigned char, save_size> buf;
                point_t pt;
                point_type_to_fourq_point(pt_, pt);
                encode(pt, buf.data());
                stream.write(reinterpret_cast<const char *>(buf.data()), save_size);
            } catch (const ios_base::failure &) {
                stream.exceptions(old_ex_mask);
                throw;
            }
            stream.exceptions(old_ex_mask);
        }

        void ECPoint::load(istream &stream)
        {
            auto old_ex_mask = stream.exceptions();
            stream.exceptions(ios_base::failbit | ios_base::badbit);

            try {
                array<unsigned char, save_size> buf;
                stream.read(reinterpret_cast<char *>(buf.data()), save_size);

                point_t pt;
                if (decode(buf.data(), pt) != ECCRYPTO_SUCCESS) {
                    stream.exceptions(old_ex_mask);
                    throw logic_error("invalid point");
                }
                fourq_point_to_point_type(pt, pt_);
            } catch (const ios_base::failure &) {
                stream.exceptions(old_ex_mask);
                throw;
            }
            stream.exceptions(old_ex_mask);
        }

        void ECPoint::save(point_save_span_type out) const
        {
            point_t pt;
            point_type_to_fourq_point(pt_, pt);
            encode(pt, out.data());
        }

        void ECPoint::load(point_save_span_const_type in)
        {
            point_t pt;
            if (decode(in.data(), pt) != ECCRYPTO_SUCCESS) {
                throw logic_error("invalid point");
            }
            fourq_point_to_point_type(pt, pt_);
        }

        void ECPoint::extract_hash(hash_span_type out) const
        {
            // Compute a Blake2b hash of the value and expand to hash_size
            point_t pt;
            point_type_to_fourq_point(pt_, pt);
            APSI_blake2b(out.data(), out.size(), pt->y, sizeof(f2elm_t), nullptr, 0);
        }
    } // namespace oprf
} // namespace apsi
