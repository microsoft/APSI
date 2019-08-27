// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

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
            static void set_log_file(const std::string& file);
            static void set_console_disabled(bool console_disabled);

        private:
            static void format_msg(std::string& msg, const char* format, va_list ap);
        };
    }
}
