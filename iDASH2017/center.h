#pragma once

#include "server.h"
#include <vector>
#include <iostream>
#include <fstream>
#include <map>
#include "item.h"
#include "Network/channel.h"
#include "Network/boost_ioservice.h"

namespace idash
{
    class Center
    {
    public:
        Center(int id);

        void load(std::istream &is);

        void load(const std::string &file_name)
        {
            std::ifstream ifs(file_name, std::ifstream::in);
            if (!ifs.is_open())
                throw std::invalid_argument("File does not exist.");
            load(ifs);
            ifs.close();
        }

        void start();

        void dispatch(const std::vector<std::pair<std::string, apsi::Item>> &batch);

        std::map<std::string, std::string>& records()
        {
            return records_;
        }

        int id() const
        {
            return id_;
        }

    private:
        int id_;

        std::map<std::string, std::string> records_;

        apsi::network::BoostIOService ios_;

        int request_count = 0;
    };
}