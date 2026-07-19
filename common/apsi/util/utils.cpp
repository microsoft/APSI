// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <sstream>
#include <stdexcept>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

// APSI
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi::util {
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
            if (!in) {
                // Stream truncated mid-read (e.g., peer closed the connection or the
                // underlying file is shorter than the declared byte_count). Fail loudly
                // here rather than handing a partially-zero-padded buffer to the caller;
                // the FlatBuffers verifier would reject it later anyway, but the actual
                // cause is more diagnostic-friendly at this layer.
                throw runtime_error("read_from_stream: truncated input");
            }

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

        // Cap the size accepted from the wire: a malicious peer could otherwise send a
        // size prefix of UINT32_MAX (~4 GiB) and force a comparable allocation. The
        // FlatBuffers verifier rejects any buffer larger than INT32_MAX bytes, so anything
        // beyond that is guaranteed to fail verification later anyway.
        constexpr uint32_t max_byte_count = static_cast<uint32_t>(numeric_limits<int32_t>::max());
        if (size > max_byte_count) {
            throw runtime_error("read_from_stream: size prefix exceeds maximum allowed");
        }

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
        // Process 8 bytes at a time.
        while (count >= sizeof(uint64_t)) {
            uint64_t a;
            uint64_t b;
            memcpy(&a, buf1, sizeof(uint64_t));
            memcpy(&b, buf2, sizeof(uint64_t));
            a ^= b;
            memcpy(buf1, &a, sizeof(uint64_t));
            buf1 += sizeof(uint64_t);
            buf2 += sizeof(uint64_t);
            count -= sizeof(uint64_t);
        }
        while (count) {
            *buf1 = static_cast<unsigned char>(*buf1 ^ *buf2);
            buf1++;
            buf2++;
            count--;
        }
    }

    void copy_bytes(const void *src, size_t count, void *dst)
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

    void secure_zero(void *ptr, size_t count) noexcept
    {
        if (!ptr || !count) {
            return;
        }
#if defined(_WIN32)
        // SecureZeroMemory is the Win32 documented zeroizer that the compiler is
        // contractually required not to optimize away.
        SecureZeroMemory(ptr, count);
#else
        using memset_t = void *(*)(void *, int, size_t);
        static volatile memset_t memset_volatile = std::memset;
        memset_volatile(ptr, 0, count);
#endif
    }

    bool compare_bytes(const void *first, const void *second, std::size_t count)
    {
        if (!first || !second) {
            throw invalid_argument("cannot compare data: input is null");
        }

        auto first_begin = reinterpret_cast<const unsigned char *>(first);
        auto first_end = first_begin + count;
        auto second_begin = reinterpret_cast<const unsigned char *>(second);

        return equal(first_begin, first_end, second_begin);
    }

    set<uint32_t> create_powers_set(uint32_t ps_low_degree, uint32_t target_degree)
    {
        if (ps_low_degree > target_degree) {
            throw invalid_argument("ps_low_degree cannot be bigger than target_degree");
        }
        if (!target_degree) {
            throw invalid_argument("target_degree cannot be zero");
        }

        set<uint32_t> result;
        if (ps_low_degree) {
            // Using Paterson-Stockmeyer; fill first with low powers up to ps_low_degree
            for (uint32_t power = 1; power <= ps_low_degree; power++) {
                result.insert(power);
            }

            // Add high powers: these are multiples of ps_low_degree + 1
            uint32_t high_powers_first = ps_low_degree + 1;
            uint32_t high_powers_last = (target_degree / high_powers_first) * high_powers_first;
            for (uint32_t power = high_powers_first; power <= high_powers_last;
                 power += high_powers_first) {
                result.insert(power);
            }
        } else {
            // Not using Paterson-Stockmeyer; fill normally up to target_degree
            for (uint32_t power = 1; power <= target_degree; power++) {
                result.insert(power);
            }
        }

        return result;
    }

    parms_id_type get_parms_id_for_chain_idx(SEALContext seal_context, size_t chain_idx)
    {
        // This function returns a parms_id matching the given chain index or -- if the chain
        // index is too large -- for the largest possible parameters (first data level).
        parms_id_type parms_id = seal_context.first_parms_id();
        while (seal_context.get_context_data(parms_id)->chain_index() > chain_idx) {
            parms_id = seal_context.get_context_data(parms_id)->next_context_data()->parms_id();
        }

        return parms_id;
    }
} // namespace apsi::util
