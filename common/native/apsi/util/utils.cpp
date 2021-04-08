// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <sstream>
#include <stdexcept>

// APSI
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi {
    namespace util {
        vector<uint64_t> conversion_to_digits(const uint64_t input, const uint64_t base)
        {
            vector<uint64_t> result;
            uint64_t number = input;

            while (number > 0) {
                result.push_back(number % base);
                number /= base;
            }

            return result;
        }

        void split(const string &s, const char delim, vector<string> &elems)
        {
            stringstream ss(s);
            string item;
            while (getline(ss, item, delim)) {
                elems.push_back(item);
            }
        }

        vector<string> split(const string &s, const char delim)
        {
            vector<string> elems;
            split(s, delim, elems);
            return elems;
        }

        void read_from_stream(istream &in, uint32_t byte_count, vector<unsigned char> &destination)
        {
            // Initial number of bytes to read
            const size_t first_to_read = 1024;

            // How many bytes we read in this round
            size_t to_read = min(static_cast<size_t>(byte_count), first_to_read);

            while (byte_count) {
                size_t old_size = destination.size();

                // Save the old size and resize by adding to_read many bytes to vector
                destination.resize(add_safe(old_size, to_read));

                // Write some data into the vector
                in.read(reinterpret_cast<char *>(destination.data() + old_size), to_read);

                // Decrement byte_count and increase to_read for next round
                byte_count -= static_cast<uint32_t>(to_read);

                // Set to_read for next round exactly to right size so we don't read too much
                to_read = min(2 * to_read, static_cast<size_t>(byte_count));
            }
        }

        vector<unsigned char> read_from_stream(istream &in)
        {
            uint32_t size = 0;
            in.read(reinterpret_cast<char *>(&size), sizeof(uint32_t));

            vector<unsigned char> result(sizeof(uint32_t));
            copy_bytes(&size, sizeof(uint32_t), result.data());

            read_from_stream(in, size, result);

            return result;
        }

        uint64_t next_power_of_2(uint64_t v)
        {
            // From: graphics.stanford.edu/~seander/bithacks.html
            v--;
            v |= v >> 1;
            v |= v >> 2;
            v |= v >> 4;
            v |= v >> 8;
            v |= v >> 16;
            v |= v >> 32;
            v++;
            v += (v == 0);

            return v;
        }

        void xor_buffers(unsigned char *buf1, const unsigned char *buf2, size_t count)
        {
            for (; count >= 4; count -= 4, buf1 += 4, buf2 += 4) {
                *reinterpret_cast<uint32_t *>(buf1) ^= *reinterpret_cast<const uint32_t *>(buf2);
            }
            for (; count; count--, buf1++, buf2++) {
                *buf1 = static_cast<unsigned char>(*buf1 ^ *buf2);
            }
        }

        void copy_bytes(const void *src, std::size_t count, void *dst)
        {
            if (!count) {
                return;
            }
            if (!src) {
                throw invalid_argument("cannot copy data: source is null");
            }
            if (!dst) {
                throw invalid_argument("cannot copy data: destination is null");
            }
            copy_n(
                reinterpret_cast<const unsigned char *>(src),
                count,
                reinterpret_cast<unsigned char *>(dst));
        }
    } // namespace util
} // namespace apsi
