// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "log.h"
#include <cstdio>
#include <cstdlib>
#include <memory>

#if !APSI_LOG_DISABLED
// Logging is not disabled

#include "log4cplus/consoleappender.h"
#include "log4cplus/fileappender.h"
#include "log4cplus/logger.h"
#include "log4cplus/nullappender.h"

using namespace std;
using namespace log4cplus;

#define CheckLogLevel(log_level)                                   \
    {                                                              \
        configure_if_needed();                                     \
        if (Logger::getInstance("APSI").getLogLevel() > log_level) \
        {                                                          \
            return;                                                \
        }                                                          \
    }

#define FormatLogMessage(format, log_level)              \
    {                                                    \
        string msg;                                      \
        va_list ap;                                      \
        va_start(ap, format);                            \
        format_msg(msg, format, ap);                     \
        va_end(ap);                                      \
        configure_if_needed();                           \
        Logger::getInstance("APSI").log(log_level, msg); \
    }

constexpr auto MSG_BUFFER_LEN = 512;

namespace apsi
{
    namespace logging
    {
        class LogProperties
        {
        public:
            bool configured = false;
            string log_file;
            bool disable_console = false;
        };

        static char msgBuffer[MSG_BUFFER_LEN];
        static LogProperties *log_properties;

        LogProperties &get_log_properties()
        {
            if (nullptr == log_properties)
            {
                log_properties = new LogProperties();
            }

            return *log_properties;
        }

        void exit_handler()
        {
            if (nullptr != log_properties)
            {
                delete log_properties;
                log_properties = nullptr;
            }
        }

        void configure()
        {
            if (nullptr != log_properties && log_properties->configured)
            {
                throw runtime_error("Logger is already configured.");
            }

            std::atexit(exit_handler);

            if (!get_log_properties().disable_console)
            {
                SharedAppenderPtr appender(new ConsoleAppender);
                appender->setLayout(make_unique<PatternLayout>("%-5p %D{%H:%M:%S:%Q}: %m%n"));
                Logger::getInstance("APSI").addAppender(appender);
            }

            if (!get_log_properties().log_file.empty())
            {
                SharedAppenderPtr appender(new RollingFileAppender(get_log_properties().log_file));
                appender->setLayout(make_unique<PatternLayout>("%-5p %D{%H:%M:%S:%Q}: %m%n"));
                Logger::getInstance("APSI").addAppender(appender);
            }

            if (get_log_properties().disable_console && get_log_properties().log_file.empty())
            {
                // Log4CPlus needs at least one appender. Use the null appender if the user doesn't want any output.
                SharedAppenderPtr appender(new NullAppender());
                Logger::getInstance("APSI").addAppender(appender);
            }

            get_log_properties().configured = true;
        }

        void configure_if_needed()
        {
            if (!get_log_properties().configured)
            {
                configure();
            }
        }

        void Log::info(const char *format, ...)
        {
            CheckLogLevel(INFO_LOG_LEVEL);
            FormatLogMessage(format, INFO_LOG_LEVEL);
        }

        void Log::warning(const char *format, ...)
        {
            CheckLogLevel(WARN_LOG_LEVEL);
            FormatLogMessage(format, WARN_LOG_LEVEL);
        }

        void Log::debug(const char *format, ...)
        {
            CheckLogLevel(DEBUG_LOG_LEVEL);
            FormatLogMessage(format, DEBUG_LOG_LEVEL);
        }

        void Log::error(const char *format, ...)
        {
            CheckLogLevel(ERROR_LOG_LEVEL);
            FormatLogMessage(format, ERROR_LOG_LEVEL);
        }

        void Log::set_log_level(Log::Level level)
        {
            // Verify level is a known log level
            LogLevel actual = ALL_LOG_LEVEL;
            switch (level)
            {
            case Level::level_all:
                actual = ALL_LOG_LEVEL;
                break;
            case Level::level_debug:
                actual = DEBUG_LOG_LEVEL;
                break;
            case Level::level_info:
                actual = INFO_LOG_LEVEL;
                break;
            case Level::level_warning:
                actual = WARN_LOG_LEVEL;
                break;
            case Level::level_error:
                actual = ERROR_LOG_LEVEL;
                break;
            default:
                throw invalid_argument("Unknown log level");
            }

            Logger::getInstance("APSI").setLogLevel(actual);
        }

        void Log::set_log_file(const string &file)
        {
            get_log_properties().log_file = file;
        }

        void Log::set_console_disabled(bool disable_console)
        {
            get_log_properties().disable_console = disable_console;
        }

        void Log::terminate()
        {
            log4cplus::deinitialize();
        }

        void Log::set_log_level(const string &level)
        {
            Log::Level actual;

            if (level == "debug")
            {
                actual = Log::Level::level_debug;
            }
            else if (level == "info")
            {
                actual = Log::Level::level_info;
            }
            else if (level == "warning")
            {
                actual = Log::Level::level_warning;
            }
            else if (level == "error")
            {
                actual = Log::Level::level_error;
            }
            else
            {
                throw invalid_argument("Unknown log level");
            }

            set_log_level(actual);
        }

        void Log::format_msg(string &msg, const char *format, va_list ap)
        {
            size_t length = static_cast<size_t>(vsnprintf(msgBuffer, MSG_BUFFER_LEN, format, ap));
            msg = string(msgBuffer, length);
        }
    } // namespace logging
} // namespace apsi

#else // !APSI_LOG_DISABLED
// Logging is enabled

namespace apsi
{
    namespace logging
    {
        void Log::info(const char *format, ...)
        {}

        void Log::debug(const char *format, ...)
        {}

        void Log::warning(const char *format, ...)
        {}

        void Log::error(const char *format, ...)
        {}

        void Log::set_log_level(Level level)
        {}

        void Log::set_log_level(const std::string &level)
        {}

        void Log::set_log_file(const std::string &file)
        {}

        void Log::set_console_disabled(bool console_disabled)
        {}

        void Log::terminate()
        {}

    } // namespace logging
} // namespace apsi

#endif // !APSI_LOG_DISABLED