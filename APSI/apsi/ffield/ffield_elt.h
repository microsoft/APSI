#pragma once

// APSI
#include "apsi/ffield/ffield.h"

// CryptoTools
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitIterator.h"

namespace apsi
{
    namespace details
    {
        // Copies bitLength bits from src starting at the bit index by bitOffset.
        // Bits are written to dest starting at the first bit. All other bits in 
        // dest are unchanged, e.g. the bit indexed by  [bitLength, bitLength + 1, ...]
        inline void copy_with_bit_offset(
            oc::span<const oc::u8> src,
            int32_t bitOffset,
            int32_t bitLength,
            oc::span<oc::u8> dest)
        {
            using namespace oc;

            // the number of bits to shift by to align with dest
            auto lowOffset = bitOffset & 7;

            // the number of full bytes that should be written to dest
            auto fullByteCount = bitLength >> 3;

            // the index of the first src word which contains our bits
            auto wordBegin = bitOffset >> 3;

            auto remBits = bitLength - fullByteCount * 8;


#ifdef _DEBUG
            if (bitOffset + bitLength > src.size() * 8)
                throw std::invalid_argument("invalid split_length, or index out of range");
            if (bitLength > dest.size() * 8)
                throw std::invalid_argument("bit length too long for dest");
#endif

            if (lowOffset)
            {
                // lowOffset mean we need to shift the bytes. 
                // Populates all of the full bytes in dest.

                int i = 0;
                while (i < fullByteCount)
                {
                    u8  low = src[wordBegin + 0] >> lowOffset;
                    u8 high = src[wordBegin + 1] << (8 - lowOffset);

                    dest[i] = low | high;

                    ++wordBegin;
                    ++i;
                }
            }
            else
            {
                // simple case, just do memcpy for all of the full bytes
                memcpy(dest.data(), &src[wordBegin], fullByteCount);
                wordBegin += fullByteCount;
            }

            // we are now done with
            // dest[0], ..., dest[fullByteCount - 1].
            // 
            // what remains is to populate dest[fullByteCount] 
            // if needed there are some remaining bits.
            if (remBits)
            {
                auto& destWord = dest[fullByteCount];

                // we now populate the last byte of dest. Branch on
                // if the src bits are contained in a single byte or
                // in two bytes.
                bool oneWordSrc = lowOffset + remBits <= 8;
                if (oneWordSrc)
                {
                    // case 1: all the remaining bits live in src[wordBegin]
                    u8 mask = (1 << remBits) - 1;

                    auto low = src[wordBegin];
                    low = low >> lowOffset;
                    low = low & mask;

                    auto high = destWord;
                    high = high & (~mask);

                    destWord = low | high;
                }
                else
                {
                    //extract the top bits out of src[wordBegin].
                    // these will become the bottom bits of destWord
                    auto lowCount = 8 - lowOffset;
                    u8 lowMask = (1 << lowCount) - 1;
                    auto low = (src[wordBegin] >> lowOffset) & lowMask;

                    //extract the bottom bits out of src[wordBegin + 1].
                    // these will become the middle bits of destWord
                    auto midCount = remBits - lowCount;
                    u8 midMask = (1 << midCount) - 1;
                    auto mid = (src[wordBegin + 1] & midMask) << lowCount;

                    // keep the high bits of destWord
                    u8 highMask = (~0) << remBits;
                    auto high = destWord & highMask;

                    // for everythign together;
                    destWord = low | mid | high;

                    //if (low & mid || mid & high || low & high)
                    //    throw std::runtime_error("");
                }
            }



        };


        // Copies bitLength bits from src starting at the bit index by srcBitOffset.
        // Bits are written to dest starting at the destBitOffset bit. All other bits in 
        // dest are unchanged, e.g. the bit indexed by [0,1,...,destBitOffset - 1], [destBitOffset + bitLength, ...]
        inline void copy_with_bit_offset(
            oc::span<const oc::u8> src,
            int32_t srcBitOffset,
            int32_t destBitOffset,
            int32_t bitLength,
            oc::span<oc::u8> dest)
        {
            using namespace oc;
            auto destNext = (destBitOffset + 7) >> 3;
            auto diff = destNext * 8 - destBitOffset;

            if (bitLength - diff > 0)
            {
                copy_with_bit_offset(src, srcBitOffset + diff, bitLength - diff, dest.subspan(destNext));
            }
            else
            {
                diff = bitLength;
            }

            if (diff)
            {
                auto srcBegin = srcBitOffset >> 3;
                auto destBegin = destBitOffset >> 3;
                auto destOffset = destBitOffset & 7;
                auto srcOffset = srcBitOffset & 7;
                auto highDiff = srcOffset + diff - 8;
                auto& destVal = dest[destBegin];

                if (highDiff <= 0)
                {
                    u8 mask = (1 << diff) - 1;
                    u8 mid = (src[srcBegin] >> srcOffset) & mask;

                    mask = ~(mask << destOffset);
                    mid = mid << destOffset;

                    destVal = destVal & mask | mid;
                }
                else
                {
                    auto lowDiff = diff - highDiff;

                    u8 lowMask = (1 << lowDiff) - 1;
                    u8 low = src[srcBegin] >> srcOffset;
                    low &= lowMask;

                    u8 highMask = (1 << highDiff) - 1;
                    u8 high = src[srcBegin + 1] & highMask;

                    low <<= destOffset;
                    high <<= (destOffset + lowDiff);

                    u8 mask = ~(((1 << diff) - 1) << destOffset);

                    destVal = destVal & mask | low | high;
                }
            }
        }

    }


    class FFieldElt
    {
        friend class FFieldArray;
        friend class FFieldPoly;
        friend class FFieldNTT;
        friend class FFieldCRTBuilder;

    public:
        FFieldElt(std::shared_ptr<FField> field) :
            field_(std::move(field))
        {
            // Allocate enough space to be an element of the field
            fq_nmod_init2(elt_, field_->ctx_);
        }

        FFieldElt(std::shared_ptr<FField> field, const seal::BigPoly &in) :
            field_(std::move(field))
        {
            // Allocate enough space to be an element of the field
            fq_nmod_init2(elt_, field_->ctx_);
            set(in);
        }

        FFieldElt(std::shared_ptr<FField> field, std::string in) :
            field_(std::move(field))
        {
            // Allocate enough space to be an element of the field
            fq_nmod_init2(elt_, field_->ctx_);
            set(in);
        }

        ~FFieldElt()
        {
            fq_nmod_clear(elt_, field_->ctx_);
        }

        FFieldElt(const FFieldElt &copy) :
            FFieldElt(copy.field_)
        {
            set(copy);
        }

        inline _ffield_elt_coeff_t get_coeff(std::size_t index) const
        {
            // This function returns 0 when index is beyond the size of the poly,
            // which is critical for correct operation.
            return nmod_poly_get_coeff_ui(elt_, index);
        }


        template<typename T>
        typename std::enable_if<std::is_pod<T>::value>::type
            encode(oc::span<T> value, int bit_length)
        {
            oc::span<const oc::u8> v2((oc::u8*)value.data(), value.size() * sizeof(T));

            // Should minus 1 to avoid wrapping around p
            int split_length = seal::util::get_significant_bit_count(field_->ch()) - 1;

            // How many coefficients do we need in the ExFieldElement
            int split_index_bound = (bit_length + split_length - 1) / split_length;

            static_assert(std::is_pod<_ffield_elt_coeff_t>::value, "must be pod type");
            _ffield_elt_coeff_t temp = 0;
            oc::span<oc::u8> temp_span((oc::u8*)&temp, sizeof(_ffield_elt_coeff_t));

            auto end = std::min<int>(field_->degree(), split_index_bound);
            for (int j = 0; j < end; j++)
            {
                // copy the j'th set of bits in value to temp
                details::copy_with_bit_offset(v2, j * split_length, split_length, temp_span);

                // the the coeff
                set_coeff(j, temp);
            }
        }

        template<typename T>
        typename std::enable_if<std::is_pod<T>::value>::type
            decode(oc::span<T> value, int bit_length)
        {
            oc::span<oc::u8> v2((oc::u8*)value.data(), value.size() * sizeof(T));

            // Should minus 1 to avoid wrapping around p
            int split_length = seal::util::get_significant_bit_count(field_->ch()) - 1;

            // How many coefficients do we need in the ExFieldElement
            int split_index_bound = (bit_length + split_length - 1) / split_length;
#ifdef _DEBUG
            if (split_index_bount > field_->degree())
                throw std::invalid_argument("too many bits required.");
#endif
            static_assert(std::is_pod<_ffield_elt_coeff_t>::value, "must be pod type");
            _ffield_elt_coeff_t temp = 0;
            oc::span<const oc::u8> temp_span((oc::u8*)&temp, sizeof(_ffield_elt_coeff_t));

            auto end = std::min<int>(field_->degree(), split_index_bound);
            for (int j = 0; j < end; j++)
            {
                temp = get_coeff(j);

                details::copy_with_bit_offset(temp_span, 0, j * split_length, split_length, v2);

                set_coeff(j, temp);
            }
        }


        inline void set_coeff(std::size_t index, _ffield_elt_coeff_t in)
        {
            if (index >= field_->d_)
            {
                throw std::out_of_range("index");
            }
            nmod_poly_set_coeff_ui(elt_, index, in);
        }

        inline void set_zero()
        {
            fq_nmod_zero(elt_, field_->ctx_);
        }

        inline void set_one()
        {
            fq_nmod_one(elt_, field_->ctx_);
        }

        inline void set_random(oc::PRNG &prng)
        {
            auto field_degree = field_->d_;
            for (unsigned i = 0; i < field_degree; i++)
            {
                nmod_poly_set_coeff_ui(elt_, i, prng.get<mp_limb_t>());
            }
        }

        inline void set_random_nonzero(oc::PRNG &prng)
        {
            do
            {
                set_random(prng);
            } while (is_zero());
        }

        inline bool is_zero() const
        {
            return fq_nmod_is_zero(elt_, field_->ctx_);
        }

        inline bool is_one() const
        {
            return fq_nmod_is_one(elt_, field_->ctx_);
        }

        inline std::shared_ptr<FField> field() const
        {
            return field_;
        }

        inline void set(const seal::BigPoly &in)
        {
            if (static_cast<unsigned>(in.coeff_count()) > field_->d_)
            {
                throw std::invalid_argument("input too large");
            }
            bigpoly_to_nmod_poly(in, elt_);
        }

        inline void set(std::string in)
        {
            set(seal::BigPoly(in));
        }

        inline seal::BigPoly to_bigpoly() const
        {
            seal::BigPoly result;
            nmod_poly_to_bigpoly(elt_, result);
            return result;
        }

        inline std::string to_string() const
        {
            seal::BigPoly result;
            nmod_poly_to_bigpoly(elt_, result);
            return result.to_string();
        }

        inline void add(FFieldElt &out, const FFieldElt &in) const
        {
            fq_nmod_add(out.elt_, elt_, in.elt_, field_->ctx_);
        }

        inline void sub(FFieldElt &out, const FFieldElt &in) const
        {
            fq_nmod_sub(out.elt_, elt_, in.elt_, field_->ctx_);
        }

        inline void mul(FFieldElt &out, const FFieldElt &in) const
        {
            fq_nmod_mul(out.elt_, elt_, in.elt_, field_->ctx_);
        }

        inline void div(FFieldElt &out, const FFieldElt &in) const
        {
            fq_nmod_div(out.elt_, elt_, in.elt_, field_->ctx_);
        }

        inline void inv(FFieldElt &out) const
        {
            fq_nmod_inv(out.elt_, elt_, field_->ctx_);
        }

        inline void inv()
        {
            inv(*this);
        }

        inline void neg(FFieldElt &out) const
        {
            fq_nmod_neg(out.elt_, elt_, field_->ctx_);
        }

        inline void neg()
        {
            neg(*this);
        }

        inline void pow(FFieldElt &out, const _bigint_t e) const
        {
            fq_nmod_pow(out.elt_, elt_, e, field_->ctx_);
        }

        inline void pow(FFieldElt &out, std::uint64_t e) const
        {
            fq_nmod_pow_ui(out.elt_, elt_, e, field_->ctx_);
        }

        inline void pow(FFieldElt &out, const seal::BigUInt &e) const
        {
            _bigint_t flint_e;
            fmpz_init(flint_e);
            biguint_to_fmpz(e, flint_e);
            pow(out, flint_e);
        }

        inline void pow(FFieldElt &out, std::string e) const
        {
            pow(out, seal::BigUInt(e));
        }

        inline FFieldElt frob(unsigned e = 1) const
        {
            // // Slow Frobenius
            // FFieldElt result(field_);
            // fq_nmod_frobenius(result.elt_, elt_, e, field_->ctx_);
            // return result;

            // Fast lookup approach
            FFieldElt result(field_);
            if (e == 0)
            {
                fq_nmod_set(result.elt_, elt_, field_->ctx_);
                return result;
            }
            FFieldElt temp(field_);
            for (unsigned i = 0; i < elt_->length; i++)
            {
                fq_nmod_mul_ui(temp.elt_, &field_->frob_table_(e, i), elt_->coeffs[i], field_->ctx_);
                result += temp;
            }
            return result;
        }

        inline void set(const FFieldElt &in)
        {
            fq_nmod_set(elt_, in.elt_, field_->ctx_);
        }

        inline bool equals(const FFieldElt &in) const
        {
            return fq_nmod_equal(elt_, in.elt_, field_->ctx_);
        }

        inline FFieldElt operator +(const FFieldElt &in) const
        {
            FFieldElt result(field_);
            add(result, in);
            return result;
        }

        inline FFieldElt operator -(const FFieldElt &in) const
        {
            FFieldElt result(field_);
            sub(result, in);
            return result;
        }

        inline FFieldElt operator *(const FFieldElt &in) const
        {
            FFieldElt result(field_);
            mul(result, in);
            return result;
        }

        inline FFieldElt operator /(const FFieldElt &in) const
        {
            FFieldElt result(field_);
            div(result, in);
            return result;
        }

        inline FFieldElt operator -() const
        {
            FFieldElt result(field_);
            neg(result);
            return result;
        }

        inline FFieldElt operator ^(const _bigint_t &e) const
        {
            FFieldElt result(field_);
            pow(result, e);
            return result;
        }

        inline FFieldElt operator ^(std::uint64_t e) const
        {
            FFieldElt result(field_);
            pow(result, e);
            return result;
        }

        inline FFieldElt operator ^(const seal::BigUInt &e) const
        {
            FFieldElt result(field_);
            pow(result, e);
            return result;
        }

        inline FFieldElt operator ^(std::string e) const
        {
            FFieldElt result(field_);
            pow(result, e);
            return result;
        }

        inline void operator +=(const FFieldElt &in)
        {
            add(*this, in);
        }

        inline void operator -=(const FFieldElt &in)
        {
            sub(*this, in);
        }

        inline void operator *=(const FFieldElt &in)
        {
            mul(*this, in);
        }

        inline void operator /=(const FFieldElt &in)
        {
            div(*this, in);
        }

        inline void operator ^=(const _bigint_t &e)
        {
            pow(*this, e);
        }

        inline void operator ^=(std::uint64_t e)
        {
            pow(*this, e);
        }

        inline void operator ^=(const seal::BigUInt &e)
        {
            pow(*this, e);
        }

        inline void operator ^=(std::string e)
        {
            pow(*this, e);
        }

        inline void operator =(const FFieldElt &in)
        {
            set(in);
        }

        inline void operator =(const seal::BigPoly &in)
        {
            set(in);
        }

        inline void operator =(std::string in)
        {
            set(in);
        }

        inline bool operator ==(const FFieldElt &compare) const
        {
            return equals(compare);
        }

        inline bool operator !=(const FFieldElt &compare) const
        {
            return !operator ==(compare);
        }

        inline _ffield_elt_ptr_t data()
        {
            return &elt_[0];
        }

        inline _ffield_elt_const_ptr_t data() const
        {
            return &elt_[0];
        }

    private:
        FFieldElt(std::shared_ptr<FField> field, const _ffield_elt_t in) :
            field_(std::move(field))
        {
            // Allocate enough space to be an element of the field
            fq_nmod_init2(elt_, field_->ctx_);
            fq_nmod_set(elt_, in, field_->ctx_);
        }

        std::shared_ptr<FField> field_;
        _ffield_elt_t elt_;
    };

    // Easy printing
    inline std::ostream &operator <<(std::ostream &os, const FFieldElt &in)
    {
        return os << in.to_string();
    }
}
