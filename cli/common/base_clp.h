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
// TCLAP 1.2.5's CmdLine.h pulls in HelpVisitor.h (which references ExitException) before any
// header that defines it; include ArgException.h first so the reference resolves under libc++.
#include "tclap/ArgException.h"
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
        std::vector<std::string> log_levels = {
            "trace", "debug", "info", "warning", "error", "suppress",
        };
        log_level_constraint_ = std::make_unique<TCLAP::ValuesConstraint<std::string>>(log_levels);
        log_level_arg_ = std::make_unique<TCLAP::ValueArg<std::string>>(
            "l",
            "logLevel",
            R"(One of "trace", "debug", "info" (default), "warning", "error", "suppress")",
            false,
            "info",
            log_level_constraint_.get(),
            *this);
    }

    ~BaseCLP() override = default;

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

            apsi::SetLogLevel(log_level_);
            std::shared_ptr<apsi::Logger> logger;
            if (!log_file_.empty()) {
                logger = apsi::NewFileLogger(log_file_, /*also_console=*/!silent_);
            } else if (silent_) {
                // Empty handler arrays produce a no-op Logger that drops every emission.
                logger = apsi::Logger::Create({}, {}, {});
            } else {
                logger = apsi::NewDefaultLogger();
            }
            apsi::SetLogger(std::move(logger));

            get_args();
        } catch (...) {
            return false;
        }

        return true;
    }

    [[nodiscard]] std::size_t threads() const
    {
        return threads_;
    }

    [[nodiscard]] const std::string &log_level() const
    {
        return log_level_;
    }

    [[nodiscard]] const std::string &log_file() const
    {
        return log_file_;
    }

    [[nodiscard]] bool silent() const
    {
        return silent_;
    }

private:
    // Parameters from command line
    std::size_t threads_{};
    std::string log_level_;
    std::string log_file_;
    bool silent_{};

    // Parameters with constraints
    std::unique_ptr<TCLAP::ValueArg<std::string>> log_level_arg_;
    std::unique_ptr<TCLAP::ValuesConstraint<std::string>> log_level_constraint_;
};
