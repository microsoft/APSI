// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cctype>
#include <fstream>
#include <sstream>
#include <utility>
#include <algorithm>
#include <filesystem>

// APSI
#include "common/csv_reader.h"
#include "apsi/logging/log.h"

using namespace std;
namespace fs = std::filesystem;
using namespace apsi;
using namespace apsi::util;

CSVReader::CSVReader()
{}

CSVReader::CSVReader(const string &file_name) : file_(file_name)
{
    throw_if_file_invalid();
}

auto CSVReader::read(istream &stream) const -> DBData
{
    string line;
    DBData result;

    if (!getline(stream, line))
    {
        APSI_LOG_WARNING("Nothing to read in `" << file_.string() << "`");
        return UnlabeledData{};
    }
    else
    {
        Item item;
        Label label;
        auto [has_item, has_label] = process_line(line, item, label);

        if (!has_item)
        {
            APSI_LOG_WARNING("Failed to read item from `" << file_.string() << "`");
            return UnlabeledData{};
        }
        if (has_label)
        {
            result = LabeledData{ make_pair(item, label) };
        }
        else
        {
            result = UnlabeledData{ item };
        }
    }

    while (getline(stream, line))
    {
        Item item;
        Label label;
        auto [has_item, _] = process_line(line, item, label);

        if (!has_item)
        {
            // Something went wrong; skip this item and move on to the next
            APSI_LOG_WARNING("Failed to read item from `" << file_.string() << "`");
            continue;
        }
        if (holds_alternative<UnlabeledData>(result))
        {
            get<UnlabeledData>(result).push_back(item);
        }
        else if (holds_alternative<LabeledData>(result))
        {
            get<LabeledData>(result).push_back(make_pair(item, label));
        }
        else
        {
            // Something is terribly wrong
            APSI_LOG_ERROR("Critical error reading data");
            throw runtime_error("variant is in bad state");
        }
    }

    // Pad labels with zeros to same size
    if (holds_alternative<LabeledData>(result))
    {
        // Find the longest label
        auto &labeled_data = get<LabeledData>(result);
        size_t label_byte_count = max_element(labeled_data.begin(), labeled_data.end(), [](auto &a, auto &b) {
            return a.second.size() < b.second.size();
        })->second.size();

        // Resize each label to label_byte_count
        for_each(labeled_data.begin(), labeled_data.end(), [&](auto &a) { a.second.resize(label_byte_count); });
    }

    return result;
}

auto CSVReader::read() const -> DBData
{
    throw_if_file_invalid();
    ifstream file(file_);
    if (!file.is_open())
    {
        APSI_LOG_ERROR("File `" << file_.string() << "` could not be opened for reading");
        throw runtime_error("could not open file");
    }

    return read(file);
}

pair<bool, bool> CSVReader::process_line(const string &line, Item &item, Label &label) const
{
    stringstream ss(line);
    string token;

    // First is the item
    getline(ss, token, ',');

    // Trim leading whitespace
    token.erase(token.begin(), find_if(token.begin(), token.end(), [](int ch) { return !isspace(ch); }));

    if (token.empty())
    {
        // Nothing found
        return { false, false };
    }

    // Item can be of arbitrary length; the constructor of Item will automatically hash it
    item = token;

    // Second is the label
    token.clear();
    getline(ss, token);

    // Trim leading whitespace
    token.erase(token.begin(), find_if(token.begin(), token.end(), [](int ch) { return !isspace(ch); }));

    label.clear();
    label.reserve(token.size());
    copy(token.begin(), token.end(), back_inserter(label));

    return { true, !token.empty() };
}

void CSVReader::throw_if_file_invalid() const
{
    if (!fs::exists(file_))
    {
        APSI_LOG_ERROR("File `" << file_.string() << "` does not exist");
        throw logic_error("file does not exist");
    }
    if (!fs::is_regular_file(file_))
    {
        APSI_LOG_ERROR("File `" << file_.string() << "` is not a regular file");
        throw logic_error("invalid file");
    }
}
