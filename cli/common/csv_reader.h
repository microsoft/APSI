// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <string>
#include <utility>
#include <variant>
#include <vector>

// APSI
#include "apsi/item.h"

/**
Simple CSV file parser
*/
class CSVReader {
public:
    using UnlabeledData = std::vector<apsi::Item>;

    using LabeledData = std::vector<std::pair<apsi::Item, apsi::Label>>;

    using DBData = std::variant<UnlabeledData, LabeledData>;

    CSVReader() = default;

    CSVReader(std::string file_name);

    std::pair<DBData, std::vector<std::string>> read(std::istream &stream) const;

    std::pair<DBData, std::vector<std::string>> read() const;

private:
    std::string file_name_;

    std::pair<bool, bool> process_line(
        const std::string &line,
        std::string &orig_item,
        apsi::Item &item,
        apsi::Label &label) const;
}; // class CSVReader
