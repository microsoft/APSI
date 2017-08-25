#pragma once

#include <string>

namespace idash
{
#define NUM_CENTER 1000
#define NUM_SERVER 3
#define TOKEN "GO!"
#define TOKEN_ENDPOINT "TOKEN"
#define DATA_ENDPOINT "DATA"
#define APSI_ENDPOINT "APSI"
#define SHARING_ENDPOINT "SHARING"
#define DATA_BATCH 100
#define DELIM ','

    extern std::string SERVER_IPS[NUM_SERVER];
    extern std::uint32_t SERVER_TOKEN_PORTS[NUM_SERVER];
    extern std::uint32_t SERVER_DATA_PORTS[NUM_SERVER];
    extern std::uint32_t SERVER_APSI_PORTS[NUM_SERVER];
    extern std::uint32_t SERVER_SHARING_PORTS[NUM_SERVER];
}