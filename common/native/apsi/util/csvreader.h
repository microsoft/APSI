// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <string>
#include <vector>

// APSI
#include "apsi/item.h"
#include "apsi/psiparams.h"
#include "apsi/util/db_encoding.h"

namespace apsi
{
    namespace util
    {
        /**
        Simple CSV file parser
        */
        class CSVReader
        {
        public:
            CSVReader();

            CSVReader(const std::string &file_name);

            void read(
                std::istream &stream, std::vector<Item> &items, std::vector<FullWidthLabel> &labels) const;

            void read(std::vector<Item> &items, std::vector<FullWidthLabel> &labels) const;

        private:
            std::string file_name_;

            void process_line(std::string line, std::vector<Item> &items, std::vector<Item> &labels) const;

            void throw_if_file_not_present() const;
        }; // class CSVReader
    }      // namespace util
} // namespace apsi
