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
            // Curve constants
            uint64_t c0l = 1064406672104372656ULL;
            uint64_t c0h = 4737573565184866938ULL;
            uint64_t b0l = 11442141257964318772ULL;
            uint64_t b0h = 5379339658566403666ULL;
            uint64_t b1l = 17ULL;
            uint64_t b1h = 9223372036854775796ULL;
            uint64_t A0l = 1289ULL;
            uint64_t A0h = 9223372036854774896ULL;
            uint64_t A1l = 12311914987857864728ULL;
            uint64_t A1h = 7168186187914912079ULL;
#ifndef _X86_
            felm_t c0{ c0l, c0h };
            felm_t b0{ b0l, b0h };
            felm_t b1{ b1l, b1h };
            felm_t A0{ A0l, A0h };
            felm_t A1{ A1l, A1h };
#else
#define HIGHOF64(x) static_cast<uint32_t>(x >> 32)
#define LOWOF64(x) static_cast<uint32_t>(x)
            felm_t c0{ LOWOF64(c0l), HIGHOF64(c0l), LOWOF64(c0h), HIGHOF64(c0h) };
            felm_t b0{ LOWOF64(b0l), HIGHOF64(b0l), LOWOF64(b0h), HIGHOF64(b0h) };
            felm_t b1{ LOWOF64(b1l), HIGHOF64(b1l), LOWOF64(b1h), HIGHOF64(b1h) };
            felm_t A0{ LOWOF64(A0l), HIGHOF64(A0l), LOWOF64(A0h), HIGHOF64(A0h) };
            felm_t A1{ LOWOF64(A1l), HIGHOF64(A1l), LOWOF64(A1h), HIGHOF64(A1h) };
#endif
            inline void fpsqrt1271(felm_t in, felm_t out)
            {
                fpsqr1271(in, out);
                for (size_t i = 1; i < 125; i++)
                {
                    fpsqr1271(out, out);
                }
            }

            inline bool fpeq1271(felm_t in1, felm_t in2)
            {
                return memcmp(in1, in2, sizeof(felm_t)) == 0;
            }

            inline bool pteq(const point_affine *in1, const point_affine *in2)
            {
                return memcmp(in1, in2, ECPoint::point_size) == 0;
            }

            void hash2curve(f2elm_t r, point_t out)
            {
                felm_t &r0 = r[0], &r1 = r[1];
                felm_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
                felm_t one = {};
                one[0] = 1;

                felm_t &x0 = out->x[0];
                felm_t &x1 = out->x[1];
                felm_t &y0 = out->y[0];
                felm_t &y1 = out->y[1];

                fpsqr1271(r0, t1);
                fpsqr1271(r1, t2);
                fpsub1271(t1, t2, t0);
                fpadd1271(t1, t2, t1);
                fpmul1271(r0, r1, t2);

                fpadd1271(t2, t2, t3);
                fpadd1271(t3, t3, t3);
                fpadd1271(t0, t3, t3);

                fpsub1271(t0, t2, t2);
                fpadd1271(t2, t2, t2);
                fpsqr1271(t2, t0);

                fpsqr1271(t3, t4);
                fpadd1271(t4, t0, t4);
                fpadd1271(t4, t2, t4);
                fpadd1271(t4, t2, t4);
                fpadd1271(t4, one, t4);
                fpinv1271(t4);

                fpmul1271(A1, t3, t0);
                fpadd1271(t0, A0, t0);
                fpmul1271(A0, t2, t5);
                fpadd1271(t0, t5, t0);
                fpmul1271(t4, t0, t0);
                fpneg1271(t0);

                fpmul1271(A0, t3, t5);
                fpsub1271(t5, A1, t5);
                fpmul1271(A1, t2, t6);
                fpsub1271(t5, t6, t5);
                fpmul1271(t4, t5, t5);
                fpadd1271(t0, t5, t4);

                fpsub1271(t0, t5, t6);
                fpmul1271(t4, t6, t4);
                fpadd1271(t4, one, t4);
                fpmul1271(A1, t5, t6);
                fpsub1271(t4, t6, t4);
                fpmul1271(A0, t0, t6);
                fpadd1271(t6, t4, t4);
                fpmul1271(t0, t5, t6);
                fpadd1271(t6, t6, t6);
                fpmul1271(A1, t0, t7);
                fpadd1271(t6, t7, t6);
                fpmul1271(A0, t5, t7);
                fpadd1271(t7, t6, t6);
                fpmul1271(t4, t0, t7);
                fpmul1271(t6, t5, t8);
                fpsub1271(t7, t8, t7);
                fpmul1271(t6, t0, t6);
                fpmul1271(t4, t5, t8);
                fpadd1271(t8, t6, t8);
                fpsqr1271(t7, t4);
                fpsqr1271(t8, t6);
                fpadd1271(t4, t6, t4);
                fpsqrt1271(t4, t6);
                fpsqr1271(t6, t9);

                if (!fpeq1271(t9, t4))
                {
                    fpadd1271(t0, A0, t0);
                    fpneg1271(t0);
                    fpadd1271(t5, A1, t5);
                    fpneg1271(t5);
                    fpcopy1271(t7, t9);
                    fpmul1271(t2, t7, t7);
                    fpmul1271(t8, t2, t2);
                    fpmul1271(t8, t3, t8);
                    fpsub1271(t7, t8, t7);
                    fpmul1271(t3, t9, t8);
                    fpadd1271(t8, t2, t8);
                    fpmul1271(t1, t6, t6);
                    fpmul1271(c0, t6, t6);
                }

                fpadd1271(t7, t6, t7);
                fpdiv1271(t7);
                fpsqrt1271(t7, t6);
                fpmul1271(b0, t0, t2);
                fpmul1271(b1, t5, t4);
                fpsub1271(t2, t4, t2);
                fpmul1271(t2, t6, t2);
                fpadd1271(t2, t2, t2);
                fpmul1271(b0, t5, t3);
                fpmul1271(b1, t0, t4);
                fpadd1271(t3, t4, t3);
                fpmul1271(t3, t6, t3);
                fpadd1271(t3, t3, t3);
                fpsqr1271(t6, t1);
                fpadd1271(t1, t1, t6);
                fpmul1271(t2, t6, t4);
                fpmul1271(t3, t6, t9);
                fpmul1271(t3, t8, t3);
                fpmul1271(t2, t8, t2);

                if (fpeq1271(t1, t7))
                {
                    fpadd1271(t4, t3, x0);
                    fpsub1271(t9, t2, x1);
                }
                else
                {
                    fpadd1271(t9, t2, x0);
                    fpsub1271(t3, t4, x1);
                }

                fpsqr1271(t6, t6);
                fpsqr1271(t8, t8);
                fpadd1271(t6, t8, t6);
                fpadd1271(t5, t5, y1);
                fpsqr1271(t5, t5);
                fpsqr1271(t0, t8);
                fpadd1271(t8, t5, t8);
                fpsub1271(t8, one, y0);
                fpadd1271(t0, t0, t0);
                fpadd1271(t0, t8, t0);
                fpadd1271(t0, one, t0);
                fpmul1271(t0, t6, t1);
                fpinv1271(t1);
                fpmul1271(t0, t1, t7);
                fpmul1271(t6, t1, t0);
                fpmul1271(x0, t7, x0);
                fpmul1271(x1, t7, x1);
                fpmul1271(y0, t0, y0);
                fpmul1271(y1, t0, y1);

                // Clear cofactor
                point_extproj_t P;
                point_setup(out, P);
                cofactor_clearing(P);
                eccnorm(P, out);
            }
        } // namespace

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
                hash2curve(r, pt_);
            }
        }

        void ECPoint::make_random_nonzero_scalar(scalar_span_type out, shared_ptr<UniformRandomGenerator> rg)
        {
            auto rand_scalar = [&rg](scalar_span_type value) {
                if (rg)
                {
                    rg->generate(order_size, reinterpret_cast<seal_byte *>(value.data()));
                }
                else
                {
                    value[0] = random_uint64();
                    value[1] = random_uint64();
                    value[2] = random_uint64();
                    value[3] = random_uint64();
                }
                modulo_order(reinterpret_cast<digit_t *>(value.data()), reinterpret_cast<digit_t *>(value.data()));
            };

            auto is_zero_scalar = [](scalar_span_type value) -> bool {
                return !(value[0] | value[1] | value[2] | value[3]);
            };

            // Loop until we find a non-zero element
            do
            {
                rand_scalar(out);
            }
            while (is_zero_scalar(out));
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
            return ecc_mul(
                pt_,
                const_cast<digit_t *>(reinterpret_cast<const digit_t *>(scalar.data())),
                pt_,
                clear_cofactor);
        }

        bool ECPoint::operator==(const ECPoint &compare)
        {
            return pteq(pt_, compare.pt_);
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
