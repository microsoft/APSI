// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdarg>
#include <string>
#include <sstream>

namespace apsi
{
    namespace logging
    {
        /**
        Class that provides the logging interface.
        */
        class Log
        {
        public:
            /**
            Supported log levels
            */
            enum class Level : int
            {
                all,
                debug,
                info,
                warning,
                error,
                off
            };

            /**
            This class is only to be used through its static methods.
            */
            Log() = delete;

            static void set_log_level(Level level);

            static Level get_log_level();

            static void set_log_level(const std::string &level);

            static void set_log_file(const std::string &file);

            static void set_console_disabled(bool console_disabled);

            static void configure_if_needed();

            static void terminate();

            static void do_log(std::string msg, Level msg_level);

        private:
            static void configure();

            static Level log_level_;
        }; // class Log
    }      // namespace logging
} // namespace apsi

#define APSI_INTERNAL_CHECK_LOG_LEVEL(log_level)   \
    logging::Log::configure_if_needed();           \
    if (logging::Log::get_log_level() > log_level) \
    {                                              \
        break;                                     \
    }                                              \

#define APSI_INTERNAL_DO_LOG(msg, msg_level)  \
    std::stringstream ss;                     \
    ss << msg;                                \
    std::string msg_str = ss.str();           \
    logging::Log::do_log(msg_str, msg_level); \

#define APSI_LOG_INFO(msg)                                              \
    do {                                                                \
        APSI_INTERNAL_CHECK_LOG_LEVEL(logging::Log::Level::info); \
        APSI_INTERNAL_DO_LOG(msg, logging::Log::Level::info);     \
    } while (0);

#define APSI_LOG_DEBUG(msg)                                              \
    do {                                                                 \
        APSI_INTERNAL_CHECK_LOG_LEVEL(logging::Log::Level::debug); \
        APSI_INTERNAL_DO_LOG(msg, logging::Log::Level::debug);     \
    } while (0);

#define APSI_LOG_WARNING(msg)                                              \
    do {                                                                   \
        APSI_INTERNAL_CHECK_LOG_LEVEL(logging::Log::Level::warning); \
        APSI_INTERNAL_DO_LOG(msg, logging::Log::Level::warning);     \
    } while (0);

#define APSI_LOG_ERROR(msg)                                              \
    do {                                                                 \
        APSI_INTERNAL_CHECK_LOG_LEVEL(logging::Log::Level::error); \
        APSI_INTERNAL_DO_LOG(msg, logging::Log::Level::error);     \
    } while (0);

