#pragma once

// STD
#include <string>

// APSI
#include "apsi/apsidefines.h"

// TCLAP
#pragma warning(push, 0)
#include "tclap/CmdLine.h"
#pragma warning(pop)

namespace apsi
{
    /**
    Command line processor based on TCLAP.
    
    This is a base class that contains common arguments.
    */
    class BaseCLP : public TCLAP::CmdLine
    {
    public:
        BaseCLP(const std::string& description, const std::string& version)
            : TCLAP::CmdLine(description, /* delim */ ' ', version)
        {
            std::vector<std::string> log_levels = { "debug", "info", "warning", "error" };
            log_level_constraint_ = std::make_unique<TCLAP::ValuesConstraint<std::string>>(log_levels);
            log_level_arg_ = std::make_unique<TCLAP::ValueArg<std::string>>("", "logLevel", "Level for application logging", false, "info", log_level_constraint_.get(), *this);
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
            TCLAP::ValueArg<int> threadsArg("t", "threads", "Number of threads to use", /* req */ false, /* value */ 1, "int");
            add(threadsArg);

            // No need to add log_level_arg_, already added in constructor

            // Additional arguments
            add_args();

            try
            {
                parse(argc, argv);

                threads_ = threadsArg.getValue();
                cout_param("threads", threads_);

                log_level_ = log_level_arg_->getValue();
                cout_param("logLevel", log_level_);

                get_args();
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

    protected:
        template<class T>
        void cout_param(const std::string param_name, const T param)
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

        // Parameters with constraints
        std::unique_ptr<TCLAP::ValueArg<std::string>> log_level_arg_;
        std::unique_ptr<TCLAP::ValuesConstraint<std::string>> log_level_constraint_;
    };
}
