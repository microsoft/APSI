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


namespace
{
    bool configured_ = false;

    Logger logger_ = Logger::getInstance("APSI");

    void configure()
    {
        if (configured_)
            throw runtime_error("Logger is already configured.");

        SharedAppenderPtr appender(new ConsoleAppender);
        appender->setLayout(make_unique<PatternLayout>("%-5p %D{%H:%M:%S:%Q}: %m%n"));
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
    va_list ap;
    va_start(ap, format);
    string msg = format_msg(format, ap);
    va_end(ap);

    instance().log(INFO_LOG_LEVEL, msg);
}

void Log::warning(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    string msg = format_msg(format, ap);
    va_end(ap);

    instance().log(WARN_LOG_LEVEL, msg);
}

void Log::debug(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    string msg = format_msg(format, ap);
    va_end(ap);

    instance().log(DEBUG_LOG_LEVEL, msg);
}

void Log::error(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    string msg = format_msg(format, ap);
    va_end(ap);

    instance().log(ERROR_LOG_LEVEL, msg);
}

string Log::format_msg(const char* format, va_list ap)
{
    string msg;
    msg.resize(1000);

    vsnprintf(msg.data(), msg.size(), format, ap);

    return msg;
}
