// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <sstream>

// APSI
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
    } // namespace util
} // namespace apsi
