#pragma once

#include <string>
#include <iostream>
#include <vector>

#ifdef _MSC_VER
#pragma warning(push, 0)
#endif

#include <tclap/CmdLine.h>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "apsi/apsidefines.h"

namespace apsi
{
    /**
    * Command Line Processor based on TCLAP
    */
    class CLP : public TCLAP::CmdLine
    {
    public:
        CLP(const std::string& desc)
            : TCLAP::CmdLine(desc)
        {}

        bool parse_args(int argc, char** argv)
        {
            TCLAP::ValueArg<int> threadsArg("t", "threads", "Number of threads to use", /* req */ false, /* value */ 1, "int");
            add(threadsArg);

            TCLAP::ValueArg<unsigned> senderSzArg("s", "senderSize", "Size of sender database", false, 20, "unsigned");
            add(senderSzArg);

            TCLAP::ValueArg<unsigned> secLvlArg("", "secLevel", "Security level", false, 40, "unsigned");
            add(secLvlArg);

            TCLAP::ValueArg<unsigned> itmBitLengthArg("b", "itemBitLength", "Item bit length", false, 60, "unsigned");
            add(itmBitLengthArg);

            TCLAP::SwitchArg labelsArg("l", "useLabels", "Use labels", false);
            add(labelsArg);

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

            TCLAP::SwitchArg oprfArg("o", "oprf", "Use OPRF", false);
            add(oprfArg);

            TCLAP::ValueArg<int> recThrArg("r", "recThreads", "Receiver threads", false, 1, "int");
            add(recThrArg);

            try
            {
                parse(argc, argv);

                threads_ = threadsArg.getValue();
                cout_param("threads", threads_);

                sender_size_ = senderSzArg.getValue();
                cout_param("senderSize", sender_size_);

                sec_level_ = secLvlArg.getValue();
                cout_param("secLevel", sec_level_);

                item_bit_length_ = itmBitLengthArg.getValue();
                cout_param("itemBitLength", item_bit_length_);

                use_labels_ = labelsArg.getValue();
                cout_param("useLabels", use_labels_ ? "true" : "false");

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

                oprf_ = oprfArg.getValue();
                cout_param("oprf", oprf_ ? "true" : "false");

                rec_threads_ = recThrArg.getValue();
                cout_param("recThreads", rec_threads_);

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
        unsigned sender_size() const { return sender_size_; }
        unsigned sec_level() const { return sec_level_; }
        unsigned item_bit_length() const { return item_bit_length_; }
        bool use_labels() const { return use_labels_; }
        int log_table_size() const { return log_table_size_; }
        int split_count() const { return split_count_; }
        int window_size() const { return window_size_; }
        int poly_modulus() const { return poly_modulus_; }
        const std::vector<u64>& coeff_modulus() const { return coeff_modulus_; }
        u64 plain_modulus() const { return plain_modulus_; }
        int dbc() const { return dbc_; }
        int exfield_degree() const { return exfield_degree_; }
        bool oprf() const { return oprf_; }
        int rec_threads() const { return rec_threads_; }

    private:
        // For printing parameters
        const int column_number = 4;
        const int column_width = 20;
        int param_cols = 0;

        // Parameters from command line
        int threads_;
        unsigned sender_size_;
        unsigned sec_level_;
        unsigned item_bit_length_;
        bool use_labels_;
        int log_table_size_;
        int split_count_;
        int window_size_;
        int poly_modulus_;
        std::vector<u64> coeff_modulus_;
        u64 plain_modulus_;
        int dbc_;
        int exfield_degree_;
        bool oprf_;
        int rec_threads_;


        template<class T>
        void cout_param(std::string param_name, T param)
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
    };
}
