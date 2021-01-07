// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <string>
#include <memory>

// TCLAP
#pragma warning(push, 0)
#include "tclap/CmdLine.h"
#pragma warning(pop)

/**
Command line processor based on TCLAP. This is a base class that contains common arguments for both parties.
*/
class BaseCLP : public TCLAP::CmdLine
{
public:
    BaseCLP(const std::string &description, const std::string &version)
        : TCLAP::CmdLine(description, /* delim */ ' ', version)
    {
        std::vector<std::string> log_levels = { "all", "debug", "info", "warning", "error", "off" };
        log_level_constraint_ = std::make_unique<TCLAP::ValuesConstraint<std::string>>(log_levels);
        log_level_arg_ = std::make_unique<TCLAP::ValueArg<std::string>>(
            "l",
            "logLevel",
            "Level for application logging",
            false,
            "info",
            log_level_constraint_.get(),
            *this
        );
    }

    virtual ~BaseCLP() {}

    /**
    Add additional arguments to the Command Line Processor.
    */
    virtual void add_args() = 0;

    /**
    Get the value of the additional arguments.
    */
    virtual void get_args() = 0;

    bool parse_args(int argc, char** argv)
    {
        TCLAP::ValueArg<int> threads_arg(
            "t",
            "threads",
            "Number of threads to use",
            /* req */ false,
            /* value */ 1,
            /* type desc */ "int"
        );
        add(threads_arg);

        TCLAP::ValueArg<std::string> logfile_arg(
            "f",
            "logFile",
            "File where logs will be written to",
            false,
            "",
            "file path"
        );
        add(logfile_arg);

        TCLAP::SwitchArg enable_console_log_arg(
            "c",
            "logToConsole",
            "Output log to console",
            false);
        add(enable_console_log_arg);

        // No need to add log_level_arg_, already added in constructor

        // Additional arguments
        add_args();

        try
        {
            parse(argc, argv);

            threads_ = threads_arg.getValue();
            cout_param("threads", threads_);

            log_level_ = log_level_arg_->getValue();
            cout_param("logLevel", log_level_);

            enable_console_ = enable_console_log_arg.getValue();
            cout_param("logToConsole", enable_console_);

            log_file_ = logfile_arg.getValue();
            cout_param("logFile", log_file_);

            get_args();

            std::cout << std::endl;
        }
        catch (...)
        {
            std::cout << "Error parsing parameters.";
            return false;
        }

        return true;
    }

    int threads() const { return threads_; }

    const std::string& log_level() const { return log_level_; }

    const std::string& log_file() const { return log_file_; }

    bool enable_console() const { return enable_console_; }

protected:
    template <typename T>
    void cout_param(const std::string &param_name, const T &param)
    {
        std::ostringstream ss;
        ss << param_name << "=" << param;
        std::cout << std::setw(column_width) << std::left << ss.str();
        param_cols++;

        if (param_cols >= column_number)
        {
            std::cout << std::endl;
            param_cols = 0;
        }
    }

private:
    // For printing parameters
    const int column_number = 4;
    const int column_width = 20;
    int param_cols = 0;

    // Parameters from command line
    int threads_;
    std::string log_level_;
    std::string log_file_;
    bool enable_console_;

    // Parameters with constraints
    std::unique_ptr<TCLAP::ValueArg<std::string>> log_level_arg_;
    std::unique_ptr<TCLAP::ValuesConstraint<std::string>> log_level_constraint_;
};
