// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <string>
#include <vector>
#include "apsi/item.h"
#include "apsi/tools/matrix.h"


namespace apsi
{
    namespace tools
    {
        /**
        Simple CSV file parser
        */
        class CSVReader
        {
        public:
            /**
            Constructor
            */
            CSVReader();

            /**
            Constructor with a given file name
            */
            CSVReader(const std::string& file_name);

            void read(std::istream& stream, std::vector<Item>& items, Matrix<Byte>& labels, int label_byte_count) const;

            /**
            Read file and put result in given vector. If file contains labels,
            the given Matrix will be updated with them.
            */
            void read(std::vector<Item>& items, Matrix<Byte>& labels, int label_byte_count) const;

        private:
            std::string file_name_;

            void process_line(std::string line, std::vector<Item>& items, std::vector<Item>& labels) const;
            void throw_if_file_not_present() const;
        }; // class CSVReader
    } // namespace tools
} // namespace apsi
