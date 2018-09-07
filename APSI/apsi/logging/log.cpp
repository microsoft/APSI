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


void Log::info(const string& msg)
{
    instance().log(INFO_LOG_LEVEL, msg);
}

void Log::warning(const string& msg)
{
    instance().log(WARN_LOG_LEVEL, msg);
}

void Log::debug(const string& msg)
{
    instance().log(DEBUG_LOG_LEVEL, msg);
}

void Log::error(const string& msg)
{
    instance().log(ERROR_LOG_LEVEL, msg);
}
