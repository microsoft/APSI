// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <fstream>
#include <cctype>
#include <sstream>

#if _MSC_VER || (__GNUC__ >= 8) || __clang__
#include <filesystem>
#else
// filesystem appears to be experimental in GCC < 8
#include <experimental/filesystem>
#endif
#include "csvreader.h"


#if !_MSC_VER && (__GNUC__ < 8) && !__clang__
using namespace experimental;
#endif

using namespace std;

namespace apsi
{
    namespace tools
    {
        CSVReader::CSVReader(const string& file_name)
            : file_name_(file_name)
        {
            throw_if_file_not_present();
        }

        CSVReader::CSVReader()
            : file_name_("")
        {
        }

        void CSVReader::read(istream& stream, vector<Item>& items, Matrix<u8>& labels, int label_byte_count) const
        {
            string line;
            vector<Item> temp_labels;

            while (!stream.eof())
            {
                getline(stream, line);
                process_line(line, items, temp_labels);
            }

            // Transfer temp_labels to real labels, if needed
            if (label_byte_count > 0 && temp_labels.size() > 0)
            {
                labels.resize(temp_labels.size(), label_byte_count, 1);
                for (size_t i = 0; i < temp_labels.size(); i++)
                {
                    memcpy(labels[i].data(), temp_labels[i].data(), label_byte_count);
                }
            }
        }

        void CSVReader::read(vector<Item>& items, Matrix<u8>& labels, int label_byte_count) const
        {
            throw_if_file_not_present();
            ifstream file(file_name_);
            read(file, items, labels, label_byte_count);
        }

        void CSVReader::process_line(string line, vector<Item>& items, vector<Item>& labels) const
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
            items.emplace_back(item);

            // Second is the label, if present
            token.clear();
            getline(ss, token);

            item.parse(token);
            labels.emplace_back(item);
        }

        void CSVReader::throw_if_file_not_present() const
        {
            filesystem::path pth(file_name_);
            if (!filesystem::exists(pth))
                throw invalid_argument("File name does not exist");
        }
    } // namespace tools
} // namespace apsi