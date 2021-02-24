// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <string>
#include <vector>
#include <variant>
#include <utility>
#include <unordered_set>
#include <unordered_map>
#include <filesystem>

// APSI
#include "apsi/item.h"
#include "apsi/psi_params.h"
#include "apsi/util/db_encoding.h"

/**
Simple CSV file parser
*/
class CSVReader
{
public:
    using UnlabeledData = std::vector<apsi::Item>;

    using LabeledData = std::vector<std::pair<apsi::Item, apsi::util::FullWidthLabel>>;

    using DBData = std::variant<UnlabeledData, LabeledData>;

    CSVReader();

    CSVReader(const std::string &file_name);

    DBData read(std::istream &stream) const;

    DBData read() const;

private:
    std::filesystem::path file_;

    std::pair<bool, bool> process_line(
        const std::string &line,
        apsi::Item &item,
        apsi::util::FullWidthLabel &label) const;

    void throw_if_file_invalid() const;
}; // class CSVReader
