#pragma once

// STD
#include <string>
#include <cstdarg>


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

            static void info(const char* format, ...);
            static void debug(const char* format, ...);
            static void warning(const char* format, ...);
            static void error(const char* format, ...);

        private:
            static std::string format_msg(const char* format, va_list ap);
        };
    }
}
