#include "idashdefines.h"

namespace idash
{
    std::string SERVER_IPS[NUM_SERVER]{"127.0.0.1", "127.0.0.1", "127.0.0.1"};
    std::uint32_t SERVER_TOKEN_PORTS[NUM_SERVER]{4000, 4001, 4002};
    std::uint32_t SERVER_DATA_PORTS[NUM_SERVER]{ 4100, 4101, 4102 };
    std::uint32_t SERVER_APSI_PORTS[NUM_SERVER]{ 4200, 4201, 4202 };
    std::uint32_t SERVER_SHARING_PORTS[NUM_SERVER]{ 4300, 4301, 4302};
}