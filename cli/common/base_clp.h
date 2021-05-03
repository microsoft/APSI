// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <string>

// TCLAP
#ifdef _MSC_VER
#pragma warning(push, 0)
#endif
#include "tclap/CmdLine.h"
#ifdef _MSC_VER
#pragma warning(pop)
#endif

// APSI
#include "apsi/log.h"

/**
Command line processor based on TCLAP. This is a base class that contains common arguments for both
parties.
*/
class BaseCLP : public TCLAP::CmdLine {
public:
    BaseCLP(const std::string &description, const std::string &version)
        : TCLAP::CmdLine(description, /* delim */ ' ', version)
    {
        std::vector<std::string> log_levels = { "all", "debug", "info", "warning", "error", "off" };
        log_level_constraint_ = std::make_unique<TCLAP::ValuesConstraint<std::string>>(log_levels);
        log_level_arg_ = std::make_unique<TCLAP::ValueArg<std::string>>(
            "l",
            "logLevel",
            "One of \"all\", \"debug\", \"info\" (default), \"warning\", \"error\", \"off\"",
            false,
            "info",
            log_level_constraint_.get(),
            *this);
    }

    virtual ~BaseCLP()
    {}

    /**
    Add additional arguments to the Command Line Processor.
    */
    virtual void add_args() = 0;

    /**
    Get the value of the additional arguments.
    */
    virtual void get_args() = 0;

    bool parse_args(int argc, char **argv)
    {
        TCLAP::ValueArg<std::size_t> threads_arg(
            "t",
            "threads",
            "Number of threads to use",
            /* req */ false,
            /* value */ 0,
            /* type desc */ "unsigned integer");
        add(threads_arg);

        TCLAP::ValueArg<std::string> logfile_arg(
            "f", "logFile", "Log file path", false, "", "file path");
        add(logfile_arg);

        TCLAP::SwitchArg silent_arg("s", "silent", "Do not write output to console", false);
        add(silent_arg);

        // No need to add log_level_arg_, already added in constructor

        // Additional arguments
        add_args();

        try {
            parse(argc, argv);

            silent_ = silent_arg.getValue();
            log_file_ = logfile_arg.getValue();
            threads_ = threads_arg.getValue();
            log_level_ = log_level_arg_->getValue();

            apsi::Log::SetConsoleDisabled(silent_);
            apsi::Log::SetLogFile(log_file_);
            apsi::Log::SetLogLevel(log_level_);

            get_args();
        } catch (...) {
            return false;
        }

        return true;
    }

    std::size_t threads() const
    {
        return threads_;
    }

    const std::string &log_level() const
    {
        return log_level_;
    }

    const std::string &log_file() const
    {
        return log_file_;
    }

    bool silent() const
    {
        return silent_;
    }

private:
    // Parameters from command line
    std::size_t threads_;
    std::string log_level_;
    std::string log_file_;
    bool silent_;

    // Parameters with constraints
    std::unique_ptr<TCLAP::ValueArg<std::string>> log_level_arg_;
    std::unique_ptr<TCLAP::ValuesConstraint<std::string>> log_level_constraint_;
};
