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
            Supported log levels
            */
            enum Level
            {
                level_all,
                level_debug,
                level_info,
                level_warning,
                level_error
            };

            /**
            This class is only to be used through its static methods.
            */
            Log() = delete;

            static void info(const char* format, ...);
            static void debug(const char* format, ...);
            static void warning(const char* format, ...);
            static void error(const char* format, ...);

            static void set_log_level(Level level);
            static void set_log_level(const std::string& level);

        private:
            static void format_msg(std::string& msg, const char* format, va_list ap);
        };
    }
}