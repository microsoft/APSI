// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <sstream>

// APSI
#include "apsi/powers.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/common.h"
#include "seal/util/defines.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    using namespace util;

    bool PowersDag::configure(
        uint32_t seed,
        uint32_t up_to_power,
        uint32_t source_count)
    {
        reset();

        if (up_to_power < 1 || source_count < 1 )
        {
            return false;
        }
        if (source_count > up_to_power)
        {
            return false;
        }

        // Set up the PRNG
        mt_.seed(seed);

        // We add a new node when mt_ samples a number larger than the following bound corresponding to a roughly 90%
        // probability.
        uint32_t new_node_dice_bound = 3865470565;

        // Initialize the first power; parents are left to zero, because the first power must always be a source node.
        nodes_[1] = PowersNode{/* power */ 1, /* depth */ 0};

        // Keep track of the total number of source nodes and the largest encountered depth
        uint32_t curr_source_count = 1;
        uint32_t curr_depth = 0;

        // In order, handle second, third, fourth, etc. powers
        uint32_t curr_power = 2;
        for (; curr_power <= up_to_power && curr_source_count <= source_count; curr_power++)
        {
            // The idea of the algorithm is to add a new source node with some small probability. Otherwise, we look
            // for a depth-optimal way of reaching this node from the nodes we have already available.
            uint32_t dice = mt_();

            // If we have enough source node budget available to add the rest of the nodes, then we do that.
            if (dice > new_node_dice_bound || up_to_power - curr_power + 1 <= source_count - curr_source_count)
            {
                // In this case we have decided to add a new source node
                curr_source_count++;
                nodes_[curr_power] = PowersNode{ curr_power, 0 };
                continue;
            }

            // We decided to obtain this node from two nodes of lower power. We need to first find a depth-optimal
            // way to split the current power into a sum of two smaller powers.
            uint32_t optimal_depth = curr_power - 1;
            uint32_t optimal_s1 = curr_power - 1;
            uint32_t optimal_s2 = 1;

            // Loop over possible values for the first parent
            for (uint32_t s1 = 1; s1 < curr_power; s1++)
            {
                // Second parent is fully determined
                uint32_t s2 = curr_power - s1;

                // Compute the depth for this choice of parents for the current power
                uint32_t depth = max(nodes_.at(s1).depth, nodes_.at(s2).depth) + 1;

                // Is this choice for the parents better than any we saw before?
                if (depth < optimal_depth)
                {
                    optimal_depth = depth;
                    optimal_s1 = s1;
                    optimal_s2 = s2;
                }
            }

            // We have found an optimal way to obtain the current power from two lower powers. Now add data for the
            // new node.
            nodes_[curr_power] = PowersNode{
                curr_power,
                optimal_depth,
                make_pair(optimal_s1, optimal_s2) };

            // The maximal required depth is updated according to the depth of the newly added node.
            curr_depth = max(curr_depth, optimal_depth);
        }

        // If we were able to construct all powers, return true. This may not be the best possible solution, of course.
        if (curr_power > up_to_power)
        {
            // Found a good configuration
            configured_ = true;
            up_to_power_ = up_to_power;
            depth_ = curr_depth;
            source_count_ = source_count;
            return true;
        }

        // Tried but failed
        reset();
        return false;
    }

    uint32_t PowersDag::up_to_power() const
    {
        if (!configured_)
        {
            throw logic_error("PowersDag has not been configured");
        }
        return up_to_power_;
    }

    uint32_t PowersDag::depth() const
    {
        if (!configured_)
        {
            throw logic_error("PowersDag has not been configured");
        }
        return depth_;
    }

    uint32_t PowersDag::source_count() const
    {
        if (!configured_)
        {
            throw logic_error("PowersDag has not been configured");
        }
        return source_count_;
    }

    vector<PowersDag::PowersNode> PowersDag::source_nodes() const
    {
        if (!configured_)
        {
            throw logic_error("PowersDag has not been configured");
        }

        vector<PowersNode> result;
        for (auto node : nodes_)
        {
            if (!node.second.parents.first && !node.second.parents.second)
            {
                result.push_back(node.second);
            }
        }

        return result;
    }

    string PowersDag::to_dot() const
    {
        if (!configured_)
        {
            throw logic_error("PowersDag has not been configured");
        }

        stringstream ss;
        ss << "digraph powers {" << endl;
        for (auto &node : nodes_)
        {
            // Add the node
            uint32_t power = node.second.power;
            ss << "\t" << power << ";" << endl;

            // Add the two parent edges if they are non-zero
            auto p1 = node.second.parents.first;
            auto p2 = node.second.parents.second;
            if (p1)
            {
                ss << "\t" << power << " -> " << p1 << ";" << endl;
            }
            if (p2)
            {
                ss << "\t" << power << " -> " << p2 << ";" << endl;
            }
        }

        ss << "}" << endl;

        return ss.str();
    }
}
