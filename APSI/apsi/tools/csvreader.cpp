// STD
#include <fstream>
#include <filesystem>

// APSI
#include "csvreader.h"


using namespace std;
using namespace apsi;
using namespace apsi::tools;


CsvReader::CsvReader(const string& file_name)
    : file_name_(file_name)
{
    throw_if_file_not_present();
}

CsvReader::CsvReader()
    : file_name_("")
{
}

void CsvReader::read(std::istream& stream, std::vector<Item>& items, Matrix<u8>& labels, int label_byte_count) const
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
        labels.resize(temp_labels.size(), label_byte_count);
        for (u64 i = 0; i < temp_labels.size(); i++)
        {
            memcpy(labels[i].data(), &temp_labels[i].value_, label_byte_count);
        }
    }
}

void CsvReader::read(vector<Item>& items, Matrix<u8>& labels, int label_byte_count) const
{
    throw_if_file_not_present();
    ifstream file(file_name_);
    read(file, items, labels, label_byte_count);
}

void CsvReader::process_line(string line, vector<Item>& items, vector<Item>& labels) const
{
    stringstream ss(line);
    string token;

    // First is the item
    getline(ss, token, ',');

    if (token.empty())
    {
        // Nothing found.
        return;
    }

    Item item;
    item[0] = std::stoull(token);
    item[1] = 0;

    items.emplace_back(item);

    // Second is the label, if present
    getline(ss, token);

    if (!token.empty())
    {
        item[0] = std::stoull(token);
        item[1] = 0;
        labels.emplace_back(item);
    }
}

void CsvReader::throw_if_file_not_present() const
{
    filesystem::path pth(file_name_);
    if (!filesystem::exists(pth))
        throw new invalid_argument("File name does not exist");
}
