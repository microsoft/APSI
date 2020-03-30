// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <cstdio>
#include <memory>
#include "log.h" 

#if !APSI_LOG_DISABLED
// Logging is not disabled

#include "log4cplus/logger.h"
#include "log4cplus/consoleappender.h"
#include "log4cplus/fileappender.h"
#include "log4cplus/nullappender.h"

using namespace std;
using namespace log4cplus;

#define CheckLogLevel(log_level) \
{\
    if (instance().getLogLevel() > log_level) \
    { \
        return; \
    } \
}

#define FormatLogMessage(format, log_level) \
{ \
    string msg; \
    va_list ap; \
    va_start(ap, format); \
    format_msg(msg, format, ap); \
    va_end(ap); \
    instance().log(log_level, msg); \
}

#define MSG_BUFFER_LEN 512

namespace apsi
{
    namespace logging
    {
        static bool configured = false;
        static Logger logger;
        static string log_file;
        static bool disable_console = false;
        static char msgBuffer[MSG_BUFFER_LEN];

#ifndef _MSC_VER
// auto_ptr shows a warning in GCC.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
        
        void configure()
        {
            if (configured)
            {
                throw runtime_error("Logger is already configured.");
            }

            logger = Logger::getInstance("APSI");

            if (!disable_console)
            {
                SharedAppenderPtr appender(new ConsoleAppender);
                appender->setLayout(make_unique<PatternLayout>("%-5p %D{%H:%M:%S:%Q}: %m%n"));
                logger.addAppender(appender);
            }

            if (!log_file.empty())
            {
                SharedAppenderPtr appender(new RollingFileAppender(log_file));
                appender->setLayout(make_unique<PatternLayout>("%-5p %D{%H:%M:%S:%Q}: %m%n"));
                logger.addAppender(appender);
            }

            if (disable_console && log_file.empty())
            {
                // Log4CPlus needs at least one appender. Use the null appender if the user doesn't want any output.
                SharedAppenderPtr appender(new NullAppender());
                logger.addAppender(appender);
            }

            configured = true;
        }

#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif

        Logger& instance()
        {
            if (!configured)
                configure();

            return logger;
        }

        void Log::info(const char* format, ...)
        {
            CheckLogLevel(INFO_LOG_LEVEL);
            FormatLogMessage(format, INFO_LOG_LEVEL);
        }

        void Log::warning(const char* format, ...)
        {
            CheckLogLevel(WARN_LOG_LEVEL);
            FormatLogMessage(format, WARN_LOG_LEVEL);
        }

        void Log::debug(const char* format, ...)
        {
            CheckLogLevel(DEBUG_LOG_LEVEL);
            FormatLogMessage(format, DEBUG_LOG_LEVEL);
        }

        void Log::error(const char* format, ...)
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

            instance().setLogLevel(actual);
        }

        void Log::set_log_file(const string& file)
        {
            log_file = file;
        }

        void Log::set_console_disabled(bool disable_console)
        {
            disable_console = disable_console;
        }

        void Log::set_log_level(const string& level)
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

        void Log::format_msg(string& msg, const char* format, va_list ap)
        {
            int length = vsnprintf(msgBuffer, MSG_BUFFER_LEN, format, ap);
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
        void Log::info(const char* format, ...)
        {
        }

        void Log::debug(const char* format, ...)
        {
        }

        void Log::warning(const char* format, ...)
        {
        }

        void Log::error(const char* format, ...)
        {
        }

        void Log::set_log_level(Level level)
        {
        }

        void Log::set_log_level(const std::string& level)
        {
        }

        void Log::set_log_file(const std::string& file)
        {
        }

        void Log::set_console_disabled(bool console_disabled)
        {
        }
    } // namespace logging
} // namespace apsi

#endif // !APSI_LOG_DISABLED