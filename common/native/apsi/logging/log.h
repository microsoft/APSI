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

            static void SetLogLevel(Level level);

            static Level GetLogLevel();

            static void SetLogLevel(const std::string &level);

            static void SetLogFile(const std::string &file);

            static void SetConsoleDisabled(bool console_disabled);

            static void ConfigureIfNeeded();

            static void Terminate();

            static void DoLog(std::string msg, Level msg_level);

        private:
            static void Configure();

            static Level log_level_;
        }; // class Log
    }      // namespace logging
} // namespace apsi

#define APSI_INTERNAL_CHECK_LOG_LEVEL(log_level)   \
    logging::Log::ConfigureIfNeeded();           \
    if (logging::Log::GetLogLevel() > log_level) \
    {                                              \
        break;                                     \
    }                                              \

#define APSI_INTERNAL_DO_LOG(msg, msg_level)  \
    std::stringstream ss;                     \
    ss << msg;                                \
    std::string msg_str = ss.str();           \
    logging::Log::DoLog(msg_str, msg_level); \

#define APSI_LOG_DEBUG(msg)                                        \
    do {                                                           \
        APSI_INTERNAL_CHECK_LOG_LEVEL(logging::Log::Level::debug); \
        APSI_INTERNAL_DO_LOG(msg, logging::Log::Level::debug);     \
    } while (0);

#define APSI_LOG_INFO(msg)                                        \
    do {                                                          \
        APSI_INTERNAL_CHECK_LOG_LEVEL(logging::Log::Level::info); \
        APSI_INTERNAL_DO_LOG(msg, logging::Log::Level::info);     \
    } while (0);

#define APSI_LOG_WARNING(msg)                                        \
    do {                                                             \
        APSI_INTERNAL_CHECK_LOG_LEVEL(logging::Log::Level::warning); \
        APSI_INTERNAL_DO_LOG(msg, logging::Log::Level::warning);     \
    } while (0);

#define APSI_LOG_ERROR(msg)                                        \
    do {                                                           \
        APSI_INTERNAL_CHECK_LOG_LEVEL(logging::Log::Level::error); \
        APSI_INTERNAL_DO_LOG(msg, logging::Log::Level::error);     \
    } while (0);
