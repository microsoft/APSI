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

#define FormatLogMessage(format, log_level) \
{ \
    string msg; \
    va_list ap; \
    va_start(ap, format); \
    format_msg(msg, format, ap); \
    va_end(ap); \
    instance().log(log_level, msg); \
}


namespace
{
    bool configured_ = false;

    Logger logger_ = Logger::getInstance("APSI");

#ifndef _MSC_VER
// auto_ptr shows a warning in GCC.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    
    void configure()
    {
        if (configured_)
            throw runtime_error("Logger is already configured.");

        SharedAppenderPtr appender(new ConsoleAppender);
        appender->setLayout(auto_ptr<Layout>(new PatternLayout("%-5p %D{%H:%M:%S:%Q}: %m%n")));
        logger_.addAppender(appender);

        configured_ = true;
    }

#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif

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

void Log::format_msg(std::string& msg, const char* format, va_list ap)
{
    msg.resize(1000);
    vsnprintf(msg.data(), msg.size(), format, ap);
}
