// STD
#include <cstdio>

// APSI
#include "log.h" 

// Logging
#include "log4cplus/logger.h"
#include "log4cplus/consoleappender.h"


using namespace std;
using namespace apsi;
using namespace apsi::logging;
using namespace log4cplus;


#define CheckLogLevel(log_level) \
    if (instance().getLogLevel() > log_level) \
    { \
        return; \
    }


namespace
{
    bool configured_ = false;

    Logger logger_ = Logger::getInstance("APSI");

    void configure()
    {
        if (configured_)
            throw runtime_error("Logger is already configured.");

        SharedAppenderPtr appender(new ConsoleAppender);
        appender->setLayout(auto_ptr<Layout>(new PatternLayout("%-5p %D{%H:%M:%S:%Q}: %m%n")));
        logger_.addAppender(appender);

        configured_ = true;
    }

    Logger& instance()
    {
        if (!configured_)
            configure();

        return logger_;
    }
}


void Log::info(const char* format, ...)
{
    CheckLogLevel(INFO_LOG_LEVEL);

    va_list ap;
    va_start(ap, format);
    string msg = format_msg(format, ap);
    va_end(ap);

    instance().log(INFO_LOG_LEVEL, msg);
}

void Log::warning(const char* format, ...)
{
    CheckLogLevel(WARN_LOG_LEVEL);

    va_list ap;
    va_start(ap, format);
    string msg = format_msg(format, ap);
    va_end(ap);

    instance().log(WARN_LOG_LEVEL, msg);
}

void Log::debug(const char* format, ...)
{
    CheckLogLevel(DEBUG_LOG_LEVEL);

    va_list ap;
    va_start(ap, format);
    string msg = format_msg(format, ap);
    va_end(ap);

    instance().log(DEBUG_LOG_LEVEL, msg);
}

void Log::error(const char* format, ...)
{
    CheckLogLevel(ERROR_LOG_LEVEL);

    va_list ap;
    va_start(ap, format);
    string msg = format_msg(format, ap);
    va_end(ap);

    instance().log(ERROR_LOG_LEVEL, msg);
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
        throw std::invalid_argument("Unknown log level");
    }

    instance().setLogLevel(actual);
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

string Log::format_msg(const char* format, va_list ap)
{
    string msg;
    msg.resize(1000);

    vsnprintf(msg.data(), msg.size(), format, ap);

    return msg;
}
