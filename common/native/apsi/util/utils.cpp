// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "apsi/util/utils.h"

using namespace std;

namespace apsi
{
    namespace util
    {
        Stopwatch sender_stop_watch;
        Stopwatch recv_stop_watch;

        vector<uint64_t> conversion_to_digits(const uint64_t input, const uint64_t base)
        {
            vector<uint64_t> result;
            uint64_t number = input;

            while (number > 0)
            {
                result.push_back(number % base);
                number /= base;
            }

            return result;
        }

        void split(const string &s, const char delim, vector<string> &elems)
        {
            stringstream ss(s);
            string item;
            while (getline(ss, item, delim))
            {
                elems.push_back(item);
            }
        }

        vector<string> split(const string &s, const char delim)
        {
            vector<string> elems;
            split(s, delim, elems);
            return elems;
        }

        vector<pair<size_t, size_t>> partition_evenly(size_t count, size_t partition_count)
        {
            if (count == 0 || partition_count == 0)
            {
                return {};
            }

            partition_count = min(count, partition_count);

            vector<pair<size_t, size_t>> partitions;
            partitions.reserve(min(count, partition_count) + 1);

            // May be zero
            size_t per_partition = count / partition_count;
            size_t extras_needed = count - per_partition * partition_count;

            size_t partition_start = 0;
            for (size_t i = 0; i < partition_count; i++)
            {
                size_t partition_end = partition_start + per_partition;
                if (extras_needed)
                {
                    partition_end++;
                    extras_needed--;
                }
                partitions.push_back({ partition_start, partition_end });
                partition_start = partition_end;
            }

            return partitions;
        }
    } // namespace util
} // namespace apsi
