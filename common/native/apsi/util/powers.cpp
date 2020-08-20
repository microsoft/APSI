// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <sstream>

// APSI
#include "apsi/util/powers.h"
#include "apsi/util/powers_generated.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/common.h"
#include "seal/util/defines.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    namespace util
    {
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

            // Initialize the first power; parents left null
            nodes_[1] = PowersNode{/* power */ 1, /* depth */ 0};

            for (uint32_t att = 0; att < attempts_; att++)
            {
                uint32_t source_count = 1;
                uint32_t required_depth = 0;

                for (uint32_t curr_power = 2; curr_power <= up_to_power; curr_power++)
                {
                    // With some probability add a new node; also if we have enough source node budget available to add
                    // the rest of the nodes, then do that.
                    double dice = rnd_(mt_);
                    if (dice > 0.9 || up_to_power - curr_power + 1 <= source_count_bound - source_count)
                    {
                        source_count++;
                        nodes_[curr_power] = PowersNode{ curr_power, 0 };
                        continue;
                    }

                    // Find the optimal degree; initialize with worst possible case
                    uint32_t optimal_depth = curr_power - 1;
                    uint32_t optimal_s1 = curr_power - 1;
                    uint32_t optimal_s2 = 1;
                    for (uint32_t s1 = 1; s1 < curr_power; s1++)
                    {
                        uint32_t s2 = curr_power - s1;
                        uint32_t depth = max(nodes_.at(s1).depth, nodes_.at(s2).depth) + 1;
                        if (depth < optimal_depth)
                        {
                            optimal_depth = depth;
                            optimal_s1 = s1;
                            optimal_s2 = s2;
                        }
                    }

                    // Now add data for the new node
                    nodes_[curr_power] = PowersNode{
                        curr_power,
                        optimal_depth,
                        make_pair(&nodes_[optimal_s1], &nodes_[optimal_s2]) };

                    required_depth = max(required_depth, optimal_depth);
                }

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
            if (!configured())
            {
                throw logic_error("PowersDag has not been configured");
            }
            return up_to_power_;
        }

        uint32_t PowersDag::depth() const
        {
            if (!configured())
            {
                throw logic_error("PowersDag has not been configured");
            }
            return depth_;
        }

        uint32_t PowersDag::source_count() const
        {
            if (!configured())
            {
                throw logic_error("PowersDag has not been configured");
            }
            return source_count_;
        }

        vector<PowersDag::PowersNode> PowersDag::source_nodes() const
        {
            if (!configured())
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
            if (!configured())
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

                // Add the two parent edges if they exist
                auto p1 = node.second.parents.first;
                auto p2 = node.second.parents.second;
                if (p1)
                {
                    ss << "\t" << power << " -> " << p1->power << ";" << endl;
                }
                if (p2)
                {
                    ss << "\t" << power << " -> " << p2->power << ";" << endl;
                }
            }

            ss << "}" << endl;

            return ss.str();
        }

        bool PowersDag::validate()
        {
            // TO DO
            return true;
        }

        size_t PowersDag::save(ostream &out)
        {
            if (!configured())
            {
                throw logic_error("PowersDag has not been configured");
            }

            flatbuffers::FlatBufferBuilder fbs_builder(1024);

            auto nodes = fbs_builder.CreateVectorOfStructs([&]() {
                vector<fbs::Node> temp;
                for (auto node : nodes_)
                {
                    temp.emplace_back(
                        node.second.power,
                        node.second.depth,
                        node.second.parents.first ? node.second.parents.first->power : 0,
                        node.second.parents.second ? node.second.parents.second->power : 0);
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

            vector<SEAL_BYTE> in_data(read_from_stream(in));

            auto verifier = flatbuffers::Verifier(reinterpret_cast<const uint8_t*>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedPowersDagBuffer(verifier);
            if (!safe)
            {
                throw runtime_error("failed to load PowersDag: invalid buffer");
            }

            auto pd = fbs::GetSizePrefixedPowersDag(in_data.data());

            // These need to be validated against the nodes data
            up_to_power_ = pd->up_to_power();
            depth_ = pd->depth();
            source_count_ = pd->source_count();

            // Required field
            auto &nodes = *pd->nodes();
            for (auto node : nodes)
            {
                // The parents will still need to be written in
                nodes_[node->power()] = PowersNode{ node->power(), node->depth() };
            }
            for (auto node : nodes)
            {
                // Set the parents
                nodes_[node->power()].parents = make_pair(
                    &nodes_[node->first_parent()],
                    &nodes_[node->second_parent()]
                );
            }

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
            while (
                !pd.configure(up_to_power, depth_bound++, source_count) ||
                    pd.source_count() < source_count);

            return pd;
        }
    }
}
