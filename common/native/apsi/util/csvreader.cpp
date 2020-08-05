// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cctype>
#include <fstream>
#include <sstream>
#include <utility>

#if _MSC_VER || (__GNUC__ >= 8) || __clang__
#include <filesystem>
#else
// filesystem appears to be experimental in GCC < 8
#include <experimental/filesystem>
#endif

// APSI
#include "apsi/util/csvreader.h"
#include "apsi/util/db_encoding.h"

#if !_MSC_VER && (__GNUC__ < 8) && !__clang__
using namespace experimental;
#endif

using namespace std;

namespace apsi
{
    namespace util
    {
        CSVReader::CSVReader(const PSIParams &params, const string &file_name) : file_name_(file_name)
        {
            throw_if_file_not_present();
        }

        CSVReader::CSVReader(const PSIParams &params) : file_name_("")
        {}

        void CSVReader::read(
            istream &stream, vector<Item> &items, vector<FullWidthLabel> &labels) const
        {
            string line;
            while (!stream.eof())
            {
                getline(stream, line);
                process_line(line, items, labels);
            }
        }

        void CSVReader::read(vector<Item> &items, vector<FullWidthLabel> &labels) const
        {
            throw_if_file_not_present();
            ifstream file(file_name_);
            read(file, items, labels);
        }

        void CSVReader::process_line(string line, vector<Item> &items, vector<FullWidthLabel> &labels) const
        {
            stringstream ss(line);
            string token;

            // First is the item
            getline(ss, token, ',');

            // Trim leading whitespace
            token.erase(token.begin(), find_if(token.begin(), token.end(), [](int ch) { return !isspace(ch); }));

            if (token.empty())
            {
                // Nothing found.
                return;
            }

            Item item;
            item.parse(token);
            items.push_back(move(item));

            // Second is the label, if present
            token.clear();
            getline(ss, token);

            FullWidthLabel label;
            label.parse(token);
            labels.push_back(move(label));
        }

        void CSVReader::throw_if_file_not_present() const
        {
            filesystem::path pth(file_name_);
            if (!filesystem::exists(pth))
            {
                throw invalid_argument("File name does not exist");
            }
        }
    } // namespace util
} // namespace apsi
