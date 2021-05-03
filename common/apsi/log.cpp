// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>

// APSI
#include "apsi/config.h"
#include "apsi/log.h"

using namespace std;

namespace apsi {
    class LogProperties {
    public:
        bool configured = false;
        string log_file;
        bool disable_console = false;
    };

    static unique_ptr<LogProperties> log_properties;

    LogProperties &get_log_properties()
    {
        if (nullptr == log_properties) {
            log_properties = make_unique<LogProperties>();
        }

        return *log_properties;
    }

    void Log::SetLogFile(const string &file)
    {
        get_log_properties().log_file = file;
        get_log_properties().configured = false;
    }

    void Log::SetConsoleDisabled(bool disable_console)
    {
        get_log_properties().disable_console = disable_console;
        get_log_properties().configured = false;
    }

    void Log::ConfigureIfNeeded()
    {
        if (!get_log_properties().configured) {
            Configure();
        }
    }

    Log::Level Log::log_level_ = Log::Level::off;

    void Log::SetLogLevel(const string &level)
    {
        Log::Level ll;

        if (level == "all") {
            ll = Log::Level::all;
        } else if (level == "debug") {
            ll = Log::Level::debug;
        } else if (level == "info") {
            ll = Log::Level::info;
        } else if (level == "warning") {
            ll = Log::Level::warning;
        } else if (level == "error") {
            ll = Log::Level::error;
        } else if (level == "off") {
            ll = Log::Level::off;
        } else {
            throw invalid_argument("unknown log level");
        }

        SetLogLevel(ll);
    }

    Log::Level Log::GetLogLevel()
    {
        return log_level_;
    }
} // namespace apsi

#ifdef APSI_USE_LOG4CPLUS

#include "log4cplus/consoleappender.h"
#include "log4cplus/fileappender.h"
#include "log4cplus/logger.h"
#include "log4cplus/nullappender.h"

using namespace log4cplus;

namespace apsi {
    void Log::Configure()
    {
        if (nullptr != log_properties && log_properties->configured) {
            throw runtime_error("Logger is already configured.");
        }

        Logger::getInstance("APSI").removeAllAppenders();

        if (!get_log_properties().disable_console) {
            SharedAppenderPtr appender(new ConsoleAppender);
            appender->setLayout(make_unique<PatternLayout>("%-5p %D{%H:%M:%S:%Q}: %m%n"));
            Logger::getInstance("APSI").addAppender(appender);
        }

        if (!get_log_properties().log_file.empty()) {
            SharedAppenderPtr appender(new RollingFileAppender(get_log_properties().log_file));
            appender->setLayout(make_unique<PatternLayout>("%-5p %D{%H:%M:%S:%Q}: %m%n"));
            Logger::getInstance("APSI").addAppender(appender);
        }

        if (get_log_properties().disable_console && get_log_properties().log_file.empty()) {
            // Log4cplus needs at least one appender. Use the null appender if the user doesn't want
            // any output.
            SharedAppenderPtr appender(new NullAppender());
            Logger::getInstance("APSI").addAppender(appender);
        }

        get_log_properties().configured = true;
    }

    void Log::DoLog(string msg, Level msg_level)
    {
        LogLevel ll;
        switch (msg_level) {
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

    void Log::SetLogLevel(Log::Level level)
    {
        // Verify level is a known log level
        LogLevel ll = ALL_LOG_LEVEL;
        switch (level) {
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

    void Log::Terminate()
    {
        log4cplus::deinitialize();
        log_properties = nullptr;
    }
} // namespace apsi

#else

namespace apsi {
    void Log::SetLogLevel(Level level)
    {}

    void Log::Configure()
    {}

    void Log::Terminate()
    {}

    void Log::DoLog(string msg, Level msg_level)
    {}
} // namespace apsi

#endif // !APSI_LOG_DISABLED
