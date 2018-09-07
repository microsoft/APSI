#pragma once

// STD
#include <string>


namespace apsi
{
    namespace logging
    {
        /**
        Class that provides logging
        */
        class Log
        {
        public:
            /**
            This class is only to be used through its static methods.
            */
            Log() = delete;

            static void info(const std::string& msg);
            static void debug(const std::string& msg);
            static void warning(const std::string& msg);
            static void error(const std::string& msg);
        };
    }
}
