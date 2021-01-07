// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <iostream>
#include <string>

// TCLAP
#pragma warning(push, 0)
#include "tclap/CmdLine.h"
#pragma warning(pop)

/**
Command Line Processor for pd_tool.
*/
class CLP : public TCLAP::CmdLine
{
public:
    CLP(const std::string &description, const std::string &version)
        : TCLAP::CmdLine(description, /* delim */ ' ', version)
    {}

    bool parse_args(int argc, char** argv)
    {
        TCLAP::ValueArg<std::uint32_t> seed_arg(
            "s",
            "seed",
            "32-bit seed for creating the PowersDag",
            /* req */ true,
            /* value */ 0,
            /* type desc */ "unsigned integer"
        );

        TCLAP::ValueArg<std::uint32_t> depth_bound_arg(
            "d",
            "depth-bound",
            "Try to find a seed that provides at most this depth",
            /* req */ true,
            /* value */ 0,
            /* type desc */ "unsigned integer"
        );

        xorAdd(seed_arg, depth_bound_arg);

        TCLAP::ValueArg<std::uint32_t> attempts_arg(
            "a",
            "attempts",
            "Number of attempts; has effect only when --depth-bound is given",
            /* req */ false,
            /* value */ 100'000'000,
            /* type desc */ "unsigned integer"
        );
        add(attempts_arg);

        TCLAP::ValueArg<std::uint32_t> up_to_power_arg(
            "p",
            "up-to-power",
            "Up to what power we want to compute (max_items_per_bin)",
            /* req */ true,
            /* value */ 1,
            /* type desc */ "unsigned integer"
        );
        add(up_to_power_arg);

        TCLAP::ValueArg<std::uint32_t> source_count_arg(
            "c",
            "source-count",
            "How many source nodes should we have (query_powers_count)",
            /* req */ true,
            /* value */ 1,
            /* type desc */ "unsigned integer"
        );
        add(source_count_arg);

        TCLAP::ValueArg<std::string> dot_file_arg(
            "f",
            "dot-file",
            "Write the PowersDag in DOT format to given file",
            /* req */ false,
            /* value */ "",
            /* type desc */ "string"
        );
        add(dot_file_arg);

        try
        {
            parse(argc, argv);

            seed_given_ = seed_arg.isSet();
            if (seed_given_)
            {
                seed_ = seed_arg.getValue();
            }
            else
            {
                depth_bound_ = depth_bound_arg.getValue();
            }

            attempts_ = attempts_arg.getValue();
            up_to_power_ = up_to_power_arg.getValue();
            source_count_ = source_count_arg.getValue();

            if (dot_file_arg.isSet())
            {
                dot_file_ = dot_file_arg.getValue();
            }
        }
        catch (...)
        {
            std::cout << "Error parsing parameters.";
            return false;
        }

        return true;
    }

    bool seed_given() const
    {
        return seed_given_;
    }

    std::uint32_t attempts() const
    {
        return attempts_;
    }

    std::uint32_t seed() const
    {
        if (!seed_given_)
        {
            throw std::logic_error("seed was not given");
        }
        return seed_;
    }

    std::uint32_t depth_bound() const
    {
        if (seed_given_)
        {
            throw std::logic_error("depth bound was not given");
        }
        return depth_bound_;
    }

    std::uint32_t up_to_power() const
    {
        return up_to_power_;
    }

    std::uint32_t source_count() const
    {
        return source_count_;
    }

    std::string dot_file() const
    {
        return dot_file_;
    }

private:
    std::uint32_t attempts_;

    std::uint32_t seed_;

    std::uint32_t depth_bound_;

    std::uint32_t up_to_power_;

    std::uint32_t source_count_;

    std::string dot_file_;

    bool seed_given_;
};
