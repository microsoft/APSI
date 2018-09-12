// STD
#include <fstream>

#if _MSC_VER || (__GNUC__ >= 8)
#include <filesystem>
#else
// filesystem appears to be experimental in GCC < 8
#include <experimental/filesystem>
#endif

// APSI
#include "csvreader.h"


#if (__GNUC__ < 8)
using namespace std::experimental;
#endif

using namespace std;
using namespace apsi;
using namespace apsi::tools;


CSVReader::CSVReader(const string& file_name)
    : file_name_(file_name)
{
    throw_if_file_not_present();
}

CSVReader::CSVReader()
    : file_name_("")
{
}

void CSVReader::read(std::istream& stream, std::vector<Item>& items, Matrix<u8>& labels, int label_byte_count) const
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

void CSVReader::throw_if_file_not_present() const
{
    filesystem::path pth(file_name_);
    if (!filesystem::exists(pth))
        throw new invalid_argument("File name does not exist");
}
