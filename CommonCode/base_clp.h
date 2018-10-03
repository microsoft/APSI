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

            TCLAP::ValueArg<unsigned> secLvlArg("", "secLevel", "Security level", false, 40, "unsigned");
            add(secLvlArg);

            TCLAP::ValueArg<int> logTblSzArg("", "logTableSize", "Table Size", false, 10, "int");
            add(logTblSzArg);

            TCLAP::ValueArg<int> splitCntArg("", "splitCount", "Split count", false, 128, "int");
            add(splitCntArg);

            TCLAP::ValueArg<int> wndSzArg("w", "windowSize", "Window size", false, 1, "int");
            add(wndSzArg);

            TCLAP::ValueArg<int> polyModArg("", "polyModulus", "Poly Modulus degree", false, 4096, "int");
            add(polyModArg);

            TCLAP::MultiArg<u64> coeffModArg("", "coeffModulus", "Coefficient Modulus", false, "u64");
            add(coeffModArg);

            TCLAP::ValueArg<u64> plainModArg("", "plainModulus", "Plain Modulus", false, 0x13ff, "u64");
            add(plainModArg);

            TCLAP::ValueArg<int> dbcArg("", "dbc", "Decomposition Bit Count", false, 30, "int");
            add(dbcArg);

            TCLAP::ValueArg<int> exFldDegreeArg("", "exfieldDegree", "exField degree", false, 8, "int");
            add(exFldDegreeArg);

            // No need to add log_level_arg_, already added in constructor

            // Additional arguments
            add_args();

            try
            {
                parse(argc, argv);

                threads_ = threadsArg.getValue();
                cout_param("threads", threads_);

                sec_level_ = secLvlArg.getValue();
                cout_param("secLevel", sec_level_);

                log_table_size_ = logTblSzArg.getValue();
                cout_param("logTableSize", log_table_size_);

                split_count_ = splitCntArg.getValue();
                cout_param("splitCount", split_count_);

                window_size_ = wndSzArg.getValue();
                cout_param("windowSize", window_size_);

                poly_modulus_ = polyModArg.getValue();
                cout_param("polyModulus", poly_modulus_);

                coeff_modulus_ = coeffModArg.getValue();
                std::string coeffVal;
                if (coeff_modulus_.size() == 0)
                {
                    coeffVal = "N/A";
                }
                else
                {
                    std::ostringstream ss;
                    for (auto& coeff : coeff_modulus_)
                    {
                        ss << coeff << ", ";
                    }
                    coeffVal = ss.str();
                }
                cout_param("coeffModulus", coeffVal);

                plain_modulus_ = plainModArg.getValue();
                cout_param("plainModulus", plain_modulus_);

                dbc_ = dbcArg.getValue();
                cout_param("dbc", dbc_);

                exfield_degree_ = exFldDegreeArg.getValue();
                cout_param("exfieldDegree", exfield_degree_);

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
        unsigned sec_level() const { return sec_level_; }
        int log_table_size() const { return log_table_size_; }
        int split_count() const { return split_count_; }
        int window_size() const { return window_size_; }
        int poly_modulus() const { return poly_modulus_; }
        const std::vector<u64>& coeff_modulus() const { return coeff_modulus_; }
        u64 plain_modulus() const { return plain_modulus_; }
        int dbc() const { return dbc_; }
        int exfield_degree() const { return exfield_degree_; }
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
        unsigned sec_level_;
        int log_table_size_;
        int split_count_;
        int window_size_;
        int poly_modulus_;
        std::vector<u64> coeff_modulus_;
        u64 plain_modulus_;
        int dbc_;
        int exfield_degree_;
        std::string log_level_;

        // Parameters with constraints
        std::unique_ptr<TCLAP::ValueArg<std::string>> log_level_arg_;
        std::unique_ptr<TCLAP::ValuesConstraint<std::string>> log_level_constraint_;
    };
}
