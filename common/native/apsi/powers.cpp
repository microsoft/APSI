// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <sstream>

// APSI
#include "apsi/powers.h"
#include "apsi/powers_generated.h"
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
        uint32_t up_to_power,
        uint32_t depth_bound,
        uint32_t source_count_bound)
    {
        reset();

        if (up_to_power < 1)
        {
            return false;
        }

        // Initialize the first power; parents are left to zero, because the first power must always be a source node.
        nodes_[1] = PowersNode{/* power */ 1, /* depth */ 0};

        // We try to find a valid configuration attempts_ many times before giving up
        for (uint32_t att = 0; att < attempts_; att++)
        {
            // Keep track of the total number of source nodes and the largest encountered depth
            uint32_t source_count = 1;
            uint32_t required_depth = 0;

            // In order, handle second, third, fourth, etc. powers
            for (uint32_t curr_power = 2; curr_power <= up_to_power; curr_power++)
            {
                // The idea of the algorithm is to add a new source node with some small probability. Otherwise, we look
                // for a depth-optimal way of reaching this node from the nodes we have already available.
                //
                // If we have enough source node budget available to add the rest of the nodes, then we do that. This
                // makes the optimal_powers function work correctly when a lot of source nodes are requested.
                double dice = rnd_(mt_);
                if (dice > 0.9 || up_to_power - curr_power + 1 <= source_count_bound - source_count)
                {
                    // In this case we have decided to add a new source node
                    source_count++;
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
                required_depth = max(required_depth, optimal_depth);
            }

            // If we are within bounds for the source node count or the maximal depth, return. This may not be the best
            // possible configuration, of course.
            if (source_count <= source_count_bound && required_depth <= depth_bound)
            {
                // Found a good configuration
                configured_ = true;
                up_to_power_ = up_to_power;
                depth_ = required_depth;
                source_count_ = source_count;
                return true;
            }
        }

        // Tried many time but failed
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

    size_t PowersDag::save(ostream &out) const
    {
        if (!configured_)
        {
            throw logic_error("PowersDag has not been configured");
        }

        flatbuffers::FlatBufferBuilder fbs_builder(1024);

        auto nodes = fbs_builder.CreateVectorOfStructs([&]() {
            vector<fbs::Node> temp;
            for (auto &node : nodes_)
            {
                temp.emplace_back(node.second.power, node.second.parents.first, node.second.parents.second);
            }
            return temp;
        }());

        auto pd = fbs::CreatePowersDag(fbs_builder, up_to_power_, depth_, source_count_, nodes);
        fbs_builder.FinishSizePrefixed(pd);

        out.write(
            reinterpret_cast<const char*>(fbs_builder.GetBufferPointer()),
            safe_cast<streamsize>(fbs_builder.GetSize()));

        return fbs_builder.GetSize();
    }

    size_t PowersDag::load(istream &in)
    {
        reset();

        vector<seal_byte> in_data(read_from_stream(in));

        auto verifier = flatbuffers::Verifier(reinterpret_cast<const uint8_t*>(in_data.data()), in_data.size());
        bool safe = fbs::VerifySizePrefixedPowersDagBuffer(verifier);
        if (!safe)
        {
            throw runtime_error("invalid buffer");
        }

        auto pd = fbs::GetSizePrefixedPowersDag(in_data.data());

        // These need to be validated against the nodes data
        up_to_power_ = pd->up_to_power();
        depth_ = pd->depth();
        source_count_ = pd->source_count();

        // Check that the size equals up_to_power_
        auto &nodes = *pd->nodes();
        if (nodes.size() != up_to_power_)
        {
            reset();
            throw runtime_error("incorrect number of nodes");
        }

        uint32_t source_count = 0;
        for (auto node : nodes)
        {
            // Check that either both parents are non-zero and less than the current power, or they are both zero, in
            // which case this is a source node.
            if (!node->first_parent() ^ !node->second_parent())
            {
                reset();
                throw runtime_error("invalid node");
            }
            if (node->first_parent() >= node->power() || node->second_parent() >= node->power())
            {
                reset();
                throw runtime_error("invalid node");
            }

            // Increase source_count if this is a source node
            source_count += !node->first_parent() && !node->second_parent();

            // Add the node but don't add parents yet; set depth to zero initially
            nodes_[node->power()] = PowersNode{ node->power(), 0 };
        }

        // Check that the computed source count matches the source_count field
        if (source_count != source_count_)
        {
            reset();
            throw runtime_error("incorrect source count");
        }

        // Set the parents
        for (auto node : nodes)
        {
            nodes_[node->power()].parents = make_pair(node->first_parent(), node->second_parent());
        }

        // Compute the depths for all nodes
        uint32_t depth = 0;
        for (std::uint32_t power = 1; power <= up_to_power_; power++)
        {
            auto &node = nodes_[power];
            if (!node.is_source())
            {
                node.depth = max(nodes_[node.parents.first].depth, nodes_[node.parents.second].depth) + 1;
                depth = max(depth, node.depth);
            }
        }

        // Mismatch with the depth field
        if (depth != depth_)
        {
            reset();
            throw runtime_error("incorrect depth");
        }

        // Set the configured_ state; everything is good
        configured_ = true;

        return in_data.size();
    }

    PowersDag optimal_powers(uint32_t up_to_power, uint32_t source_count)
    {
        if (!source_count)
        {
            throw invalid_argument("at least one source term must be given");
        }
        if (up_to_power < source_count)
        {
            throw invalid_argument("source_count is too large");
        }

        PowersDag pd;
        uint32_t depth_bound = 0;

        // This loop always terminates at latest when depth_bound equals up_to_power - 1
        while (
            !pd.configure(up_to_power, depth_bound++, source_count) ||
                pd.source_count() < source_count);

        return pd;
    }
}
