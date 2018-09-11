#pragma once

// STD
#include <string>
#include <vector>

// APSI
#include "apsi/item.h"
#include "apsi/tools/matrix.h"


namespace apsi
{
    namespace tools
    {
        /**
        Simple CSV file parser
        */
        class CsvReader
        {
        public:
            /**
            Constructor
            */
            CsvReader();

            /**
            Constructor with a given file name
            */
            CsvReader(const std::string& file_name);

            void read(std::istream& stream, std::vector<Item>& items, Matrix<u8>& labels, int label_byte_count) const;

            /**
            Read file and put result in given vector. If file contains labels,
            the given Matrix will be updated with them.
            */
            void read(std::vector<Item>& items, Matrix<u8>& labels, int label_byte_count) const;

        private:
            std::string file_name_;

            void process_line(std::string line, std::vector<Item>& items, std::vector<Item>& labels) const;
            void throw_if_file_not_present() const;
        };
    }
}
