// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <utility>

// APSI
#include "apsi/log.h"
#include "common/common_utils.h"
#include "common/csv_reader.h"

using namespace std;
using namespace apsi;
using namespace apsi::util;

CSVReader::CSVReader()
{}

CSVReader::CSVReader(const string &file_name) : file_name_(file_name)
{
    throw_if_file_invalid(file_name_);
}

auto CSVReader::read(istream &stream) const -> pair<DBData, vector<string>>
{
    string line;
    DBData result;
    vector<string> orig_items;

    if (!getline(stream, line)) {
        APSI_LOG_WARNING("Nothing to read in `" << file_name_ << "`");
        return { UnlabeledData{}, {} };
    } else {
        string orig_item;
        Item item;
        Label label;
        auto [has_item, has_label] = process_line(line, orig_item, item, label);

        if (!has_item) {
            APSI_LOG_WARNING("Failed to read item from `" << file_name_ << "`");
            return { UnlabeledData{}, {} };
        }

        orig_items.push_back(move(orig_item));
        if (has_label) {
            result = LabeledData{ make_pair(move(item), move(label)) };
        } else {
            result = UnlabeledData{ move(item) };
        }
    }

    while (getline(stream, line)) {
        string orig_item;
        Item item;
        Label label;
        auto [has_item, _] = process_line(line, orig_item, item, label);

        if (!has_item) {
            // Something went wrong; skip this item and move on to the next
            APSI_LOG_WARNING("Failed to read item from `" << file_name_ << "`");
            continue;
        }

        orig_items.push_back(move(orig_item));
        if (holds_alternative<UnlabeledData>(result)) {
            get<UnlabeledData>(result).push_back(move(item));
        } else if (holds_alternative<LabeledData>(result)) {
            get<LabeledData>(result).push_back(make_pair(move(item), move(label)));
        } else {
            // Something is terribly wrong
            APSI_LOG_ERROR("Critical error reading data");
            throw runtime_error("variant is in bad state");
        }
    }

    return { move(result), move(orig_items) };
}

auto CSVReader::read() const -> pair<DBData, vector<string>>
{
    throw_if_file_invalid(file_name_);

    ifstream file(file_name_);
    if (!file.is_open()) {
        APSI_LOG_ERROR("File `" << file_name_ << "` could not be opened for reading");
        throw runtime_error("could not open file");
    }

    return read(file);
}

pair<bool, bool> CSVReader::process_line(
    const string &line, string &orig_item, Item &item, Label &label) const
{
    stringstream ss(line);
    string token;

    // First is the item
    getline(ss, token, ',');

    // Trim leading whitespace
    token.erase(
        token.begin(), find_if(token.begin(), token.end(), [](int ch) { return !isspace(ch); }));

    // Trim trailing whitespace
    token.erase(
        find_if(token.rbegin(), token.rend(), [](int ch) { return !isspace(ch); }).base(),
        token.end());

    if (token.empty()) {
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
    token.erase(
        token.begin(), find_if(token.begin(), token.end(), [](int ch) { return !isspace(ch); }));

    // Trim trailing whitespace
    token.erase(
        find_if(token.rbegin(), token.rend(), [](int ch) { return !isspace(ch); }).base(),
        token.end());

    label.clear();
    label.reserve(token.size());
    copy(token.begin(), token.end(), back_inserter(label));

    return { true, !token.empty() };
}
