#pragma once

#include <vector>
#include <cstring>
#include <type_traits>
#include <gsl/span>

#include "aes.h"
#include "apsi/apsidefines.h"

namespace apsi
{
    class Item;

    namespace tools
    {
        /**
         * A Peudorandom number generator implemented using AES-NI.
         */
        class PRNG
        {
        public:
            /**
            * Default construct leaves the PRNG in an invalid state.
            * SetSeed(...) must be called before get(...)
            */
            PRNG() = default;

            /**
            * Explicit constructor to initialize the PRNG with the
            * given seed and buffer_size number of AES blocks
            */
            PRNG(const block& seed, u64 buffer_size = 256);

            /**
             * Explicit construction to initialize the PRNG with the
             * given seed and buffer_size number of AES blocks
             */
            PRNG(const Item& seed, u64 buffer_size = 256);

            /*
            * Standard move constructor. The moved from PRNG is invalid
            * unless SetSeed(...) is called.
            */
            PRNG(PRNG&& s);

            /**
            * Copy is not allowed.
            */
            PRNG(const PRNG&) = delete;

            /**
            * Standard move assignment. The moved from PRNG is invalid
            * unless SetSeed(...) is called.
            */
            void operator=(PRNG&&);

            /**
            * Set seed from a block and set the desired buffer size.
            */
            void set_seed(const block& b, u64 buffer_size = 256);

            /**
            * Return the seed for this PRNG.
            */
            const block get_seed() const;

            /**
            * Templated function that returns the a random element
            * of the given type T.
            * Required: T must be a POD type.
            */
            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, T>::type
            get()
            {
                T ret;
                get(reinterpret_cast<u8*>(&ret), sizeof(T));
                return ret;
            }

            /**
            * Templated function that fills the provided buffer
            * with random elements of the given type T.
            * Required: T must be a POD type.
            */
            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, void>::type
                get(T* dest, u64 length)
            {
                u64 lengthu8 = length * sizeof(T);
                u8* destu8 = reinterpret_cast<u8*>(dest);
                while (lengthu8)
                {
                    u64 step = std::min(lengthu8, buffer_byte_capacity_ - bytes_idx_);

                    memcpy(destu8, reinterpret_cast<u8*>(buffer_.data()) + bytes_idx_, step);

                    destu8 += step;
                    lengthu8 -= step;
                    bytes_idx_ += step;

                    if (bytes_idx_ == buffer_byte_capacity_)
                        refill_buffer();
                }
            }

            /**
            * Templated function that fills the provided buffer
            * with random elements of the given type T.
            * Required: T must be a POD type.
            */
            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, void>::type
                get(gsl::span<T> dest)
            {
                get(dest.data(), dest.size());
            }

            /**
            * Returns a random element from {0,1}
            */
            u8 get_bit();

        private:
            // internal buffer to store future random values.
            std::vector<block> buffer_;

            // AES that generates the randomness by computing AES_seed({0,1,2,...})
            AES aes_;

            // Indicators denoting the current state of the buffer.
            u64 bytes_idx_ = 0,
                block_idx_ = 0,
                buffer_byte_capacity_ = 0;

            // refills the internal buffer with fresh randomness
            void refill_buffer();

            // Clear all fields in instance
            static void clear(PRNG& p);
        };
    }
}
