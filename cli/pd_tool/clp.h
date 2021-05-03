// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <iostream>
#include <string>
#include <vector>

// TCLAP
#ifdef _MSC_VER
#pragma warning(push, 0)
#endif
#include "tclap/CmdLine.h"
#ifdef _MSC_VER
#pragma warning(pop)
#endif

/**
Command Line Processor for pd_tool.
*/
class CLP : public TCLAP::CmdLine {
public:
    CLP(const std::string &description, const std::string &version)
        : TCLAP::CmdLine(description, /* delim */ ' ', version)
    {}

    bool parse_args(int argc, char **argv)
    {
        TCLAP::ValueArg<std::uint32_t> bound_arg(
            "b",
            "bound",
            "Up to what power we want to compute (max_items_per_bin)",
            /* req */ true,
            /* value */ 1,
            /* type desc */ "unsigned integer");
        add(bound_arg);

        TCLAP::ValueArg<std::uint32_t> ps_low_degree_arg(
            "p",
            "ps_low_degree",
            "Low power when using Paterson-Stockmeyer for polynomial evaluation",
            /* req */ false,
            /* value */ 0,
            /* type desc */ "unsigned integer");
        add(ps_low_degree_arg);

        TCLAP::ValueArg<std::string> dot_file_arg(
            "o",
            "out",
            "Write the PowersDag in DOT format to given file",
            /* req */ false,
            /* value */ "",
            /* type desc */ "string");
        add(dot_file_arg);

        TCLAP::UnlabeledMultiArg<std::uint32_t> sources_arg(
            "sources",
            "The source powers",
            /* req */ true,
            "list of unsigned integers");
        add(sources_arg);

        try {
            parse(argc, argv);

            bound_ = bound_arg.getValue();
            ps_low_degree_ = ps_low_degree_arg.getValue();
            if (dot_file_arg.isSet()) {
                dot_file_ = dot_file_arg.getValue();
            }
            sources_ = sources_arg.getValue();
        } catch (...) {
            std::cout << "Error parsing parameters.";
            return false;
        }

        return true;
    }

    std::uint32_t bound() const
    {
        return bound_;
    }

    std::uint32_t ps_low_degree() const
    {
        return ps_low_degree_;
    }

    std::string dot_file() const
    {
        return dot_file_;
    }

    const std::vector<std::uint32_t> &sources() const
    {
        return sources_;
    }

private:
    std::uint32_t bound_;

    std::uint32_t ps_low_degree_ = 0;

    std::string dot_file_;

    std::vector<std::uint32_t> sources_;
};
