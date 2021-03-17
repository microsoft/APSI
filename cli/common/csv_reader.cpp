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
#include "apsi/log.h"

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

auto CSVReader::read(istream &stream) const -> pair<DBData, vector<string>>
{
    string line;
    DBData result;
    vector<string> orig_items;

    if (!getline(stream, line))
    {
        APSI_LOG_WARNING("Nothing to read in `" << file_.string() << "`");
        return { UnlabeledData{}, {} };
    }
    else
    {
        string orig_item;
        Item item;
        Label label;
        auto [has_item, has_label] = process_line(line, orig_item, item, label);

        if (!has_item)
        {
            APSI_LOG_WARNING("Failed to read item from `" << file_.string() << "`");
            return { UnlabeledData{}, {} };
        }

        orig_items.push_back(move(orig_item));
        if (has_label)
        {
            result = LabeledData{ make_pair(move(item), move(label)) };
        }
        else
        {
            result = UnlabeledData{ move(item) };
        }
    }

    while (getline(stream, line))
    {
        string orig_item;
        Item item;
        Label label;
        auto [has_item, _] = process_line(line, orig_item, item, label);

        if (!has_item)
        {
            // Something went wrong; skip this item and move on to the next
            APSI_LOG_WARNING("Failed to read item from `" << file_.string() << "`");
            continue;
        }

        orig_items.push_back(move(orig_item));
        if (holds_alternative<UnlabeledData>(result))
        {
            get<UnlabeledData>(result).push_back(move(item));
        }
        else if (holds_alternative<LabeledData>(result))
        {
            get<LabeledData>(result).push_back(make_pair(move(item), move(label)));
        }
        else
        {
            // Something is terribly wrong
            APSI_LOG_ERROR("Critical error reading data");
            throw runtime_error("variant is in bad state");
        }
    }

    return { move(result), move(orig_items) };
}

auto CSVReader::read() const -> pair<DBData, vector<string>>
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

pair<bool, bool> CSVReader::process_line(const string &line, string &orig_item, Item &item, Label &label) const
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
    orig_item = token;
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
