// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdarg>
#include <sstream>
#include <string>

namespace apsi {
    /**
    Class that provides the logging interface.
    */
    class Log {
    public:
        /**
        Supported log levels
        */
        enum class Level : int { all, debug, info, warning, error, off };

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
} // namespace apsi

#define APSI_INTERNAL_CHECK_LOG_LEVEL(log_level) \
    apsi::Log::ConfigureIfNeeded();              \
    if (apsi::Log::GetLogLevel() > log_level) {  \
        break;                                   \
    }

#define APSI_INTERNAL_DO_LOG(msg, msg_level) \
    std::stringstream log_ss;                \
    log_ss << msg;                           \
    std::string log_str = log_ss.str();      \
    apsi::Log::DoLog(log_str, msg_level);

#define APSI_LOG_DEBUG(msg)                                     \
    do {                                                        \
        APSI_INTERNAL_CHECK_LOG_LEVEL(apsi::Log::Level::debug); \
        APSI_INTERNAL_DO_LOG(msg, apsi::Log::Level::debug);     \
    } while (0);

#define APSI_LOG_INFO(msg)                                     \
    do {                                                       \
        APSI_INTERNAL_CHECK_LOG_LEVEL(apsi::Log::Level::info); \
        APSI_INTERNAL_DO_LOG(msg, apsi::Log::Level::info);     \
    } while (0);

#define APSI_LOG_WARNING(msg)                                     \
    do {                                                          \
        APSI_INTERNAL_CHECK_LOG_LEVEL(apsi::Log::Level::warning); \
        APSI_INTERNAL_DO_LOG(msg, apsi::Log::Level::warning);     \
    } while (0);

#define APSI_LOG_ERROR(msg)                                     \
    do {                                                        \
        APSI_INTERNAL_CHECK_LOG_LEVEL(apsi::Log::Level::error); \
        APSI_INTERNAL_DO_LOG(msg, apsi::Log::Level::error);     \
    } while (0);
