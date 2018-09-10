#pragma once

// STD
#include <string>

namespace apsi
{
    class BaseCLP;
    class PSIParams;

    namespace tools
    {
        /**
        Print a banner with asterisks on top and bottom
        */
        void print_example_banner(const std::string title);

        /**
        Prepare console for color output.
        */
        void prepare_console();

        /**
        Get a PSIParams object from a command line.
        */
        const PSIParams build_psi_params(const BaseCLP& cmd);
    }
}
