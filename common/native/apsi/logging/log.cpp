// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <cstddef>
#include <iostream>

// APSI
#include "apsi/logging/log.h"
#include "apsi/config.h"

using namespace std;

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

        static LogProperties *log_properties;

        constexpr auto MSG_BUFFER_LEN = 512;

        static char msg_buffer[MSG_BUFFER_LEN];

        LogProperties &get_log_properties()
        {
            if (nullptr == log_properties)
            {
                log_properties = new LogProperties();
            }

            return *log_properties;
        }

        void Log::set_log_file(const string &file)
        {
            get_log_properties().log_file = file;
        }

        void Log::set_console_disabled(bool disable_console)
        {
            get_log_properties().disable_console = disable_console;
        }

        void Log::configure_if_needed()
        {
            if (!get_log_properties().configured)
            {
                configure();
            }
        }

        Log::Level Log::log_level_ = Log::Level::off;

        void Log::set_log_level(const string &level)
        {
            Log::Level ll;

            if (level == "all")
            {
                ll = Log::Level::all;
            }
            else if (level == "info")
            {
                ll = Log::Level::info;
            }
            else if (level == "debug")
            {
                ll = Log::Level::debug;
            }
            else if (level == "warning")
            {
                ll = Log::Level::warning;
            }
            else if (level == "error")
            {
                ll = Log::Level::error;
            }
            else if (level == "off")
            {
                ll = Log::Level::off;
            }
            else
            {
                throw invalid_argument("unknown log level");
            }

            set_log_level(ll);
        }

        Log::Level Log::get_log_level()
        {
            return log_level_;
        }
    }
}

#ifdef APSI_USE_LOG4CPLUS

#include "log4cplus/consoleappender.h"
#include "log4cplus/fileappender.h"
#include "log4cplus/logger.h"
#include "log4cplus/nullappender.h"

using namespace log4cplus;

namespace apsi
{
    namespace logging
    {
        namespace
        {
            void exit_handler()
            {
                if (nullptr != log_properties)
                {
                    delete log_properties;
                    log_properties = nullptr;
                }
            }
        }

        void Log::configure()
        {
            if (nullptr != log_properties && log_properties->configured)
            {
                throw runtime_error("Logger is already configured.");
            }

            atexit(exit_handler);

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
                // Log4cplus needs at least one appender. Use the null appender if the user doesn't want any output.
                SharedAppenderPtr appender(new NullAppender());
                Logger::getInstance("APSI").addAppender(appender);
            }

            get_log_properties().configured = true;
        }

        void Log::do_log(string msg, Level msg_level)
        {
            LogLevel ll;
            switch (msg_level)
            {
                case Level::all:
                    ll = ALL_LOG_LEVEL;
                    break;
                case Level::info:
                    ll = INFO_LOG_LEVEL;
                    break;
                case Level::debug:
                    ll = DEBUG_LOG_LEVEL;
                    break;
                case Level::warning:
                    ll = WARN_LOG_LEVEL;
                    break;
                case Level::error:
                    ll = ERROR_LOG_LEVEL;
                    break;
                case Level::off:
                    ll = OFF_LOG_LEVEL;
                    break;
                default:
                    throw invalid_argument("unknown log level");
            }
            Logger::getInstance("APSI").log(ll, msg);
        }

        void Log::set_log_level(Log::Level level)
        {
            // Verify level is a known log level
            LogLevel ll = ALL_LOG_LEVEL;
            switch (level)
            {
            case Level::all:
                ll = ALL_LOG_LEVEL;
                break;
            case Level::debug:
                ll = DEBUG_LOG_LEVEL;
                break;
            case Level::info:
                ll = INFO_LOG_LEVEL;
                break;
            case Level::warning:
                ll = WARN_LOG_LEVEL;
                break;
            case Level::error:
                ll = ERROR_LOG_LEVEL;
                break;
            case Level::off:
                ll = OFF_LOG_LEVEL;
                break;
            default:
                throw invalid_argument("unknown log level");
            }

            log_level_ = level;
            Logger::getInstance("APSI").setLogLevel(ll);
        }

        void Log::terminate()
        {
            log4cplus::deinitialize();
        }
    } // namespace logging
} // namespace apsi

#else

namespace apsi
{
    namespace logging
    {
        void Log::set_log_level(Level level)
        {}

        void Log::configure()
        {}

        void Log::terminate()
        {}

        void Log::do_log(string msg, Level msg_level)
        {}
    } // namespace logging
} // namespace apsi

#endif // !APSI_LOG_DISABLED
