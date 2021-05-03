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

namespace apsi {
    using namespace util;

    bool PowersDag::configure(set<uint32_t> source_powers, set<uint32_t> target_powers)
    {
        reset();

        // Source powers cannot contain 0 and must contain 1
        if (source_powers.find(0) != source_powers.cend() ||
            source_powers.find(1) == source_powers.cend()) {
            return false;
        }

        // Target powers cannot contain 0 and must contain 1
        if (target_powers.find(0) != target_powers.cend() ||
            target_powers.find(1) == target_powers.cend()) {
            return false;
        }

        // Source powers must be a subset of target powers
        if (!includes(
                target_powers.cbegin(),
                target_powers.cend(),
                source_powers.cbegin(),
                source_powers.cend())) {
            return false;
        }

        // Insert all source nodes
        for (uint32_t s : source_powers) {
            nodes_[s] = PowersNode{ /* power */ s, /* depth */ 0 };
        }

        // Keep track of the largest encountered depth
        uint32_t curr_depth = 0;

        // Now compute the non-source powers
        for (uint32_t curr_power : target_powers) {
            // Do nothing if this is a source power
            if (source_powers.find(curr_power) != source_powers.cend()) {
                continue;
            }

            // The current power should be written as a sum of two lower powers in a depth-optimal
            // way.
            uint32_t optimal_depth = curr_power - 1;
            uint32_t optimal_s1 = curr_power - 1;
            uint32_t optimal_s2 = 1;

            // Loop over possible values for the first parent
            for (uint32_t s1 : target_powers) {
                // Only go up to the current target power for the first parent
                if (s1 >= curr_power) {
                    break;
                }

                // Second parent is fully determined and must be a target power as well
                uint32_t s2 = curr_power - s1;
                if (target_powers.find(s2) == target_powers.cend()) {
                    continue;
                }

                // Compute the depth for this choice of parents for the current power
                uint32_t depth = max(nodes_.at(s1).depth, nodes_.at(s2).depth) + 1;

                // Is this choice for the parents better than any we saw before?
                if (depth < optimal_depth) {
                    optimal_depth = depth;
                    optimal_s1 = s1;
                    optimal_s2 = s2;
                }
            }

            // We have found an optimal way to obtain the current power from two lower powers. Now
            // add data for the new node.
            nodes_[curr_power] =
                PowersNode{ curr_power, optimal_depth, make_pair(optimal_s1, optimal_s2) };

            // The maximal required depth is updated according to the depth of the newly added node.
            curr_depth = max(curr_depth, optimal_depth);
        }

        // Success
        configured_ = true;
        target_powers_ = target_powers;
        depth_ = curr_depth;
        source_count_ = static_cast<uint32_t>(source_powers.size());
        return true;
    }

    set<uint32_t> PowersDag::target_powers() const
    {
        if (!configured_) {
            throw logic_error("PowersDag has not been configured");
        }
        return target_powers_;
    }

    uint32_t PowersDag::depth() const
    {
        if (!configured_) {
            throw logic_error("PowersDag has not been configured");
        }
        return depth_;
    }

    uint32_t PowersDag::source_count() const
    {
        if (!configured_) {
            throw logic_error("PowersDag has not been configured");
        }
        return source_count_;
    }

    vector<PowersDag::PowersNode> PowersDag::source_nodes() const
    {
        if (!configured_) {
            throw logic_error("PowersDag has not been configured");
        }

        vector<PowersNode> result;
        for (auto &node : nodes_) {
            if (!node.second.parents.first && !node.second.parents.second) {
                result.push_back(node.second);
            }
        }

        return result;
    }

    string PowersDag::to_dot() const
    {
        if (!configured_) {
            throw logic_error("PowersDag has not been configured");
        }

        stringstream ss;
        ss << "digraph powers {" << endl;
        for (auto &node : nodes_) {
            // Add the node
            uint32_t power = node.second.power;
            ss << "\t" << power << ";" << endl;

            // Add the two parent edges if they are non-zero
            auto p1 = node.second.parents.first;
            auto p2 = node.second.parents.second;
            if (p1) {
                ss << "\t" << power << " -> " << p1 << ";" << endl;
            }
            if (p2) {
                ss << "\t" << power << " -> " << p2 << ";" << endl;
            }
        }

        ss << "}" << endl;

        return ss.str();
    }
} // namespace apsi
