// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <future>
#include <iostream>
#include <memory>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// APSI
#include "apsi/thread_pool_mgr.h"

namespace apsi {
    /**
    PowersDag represents a DAG for computing all powers of a given query ciphertext in a
    depth-optimal manner given a certain "base" (sources) of powers of the query.

    For example, the computation up to power 7 with sources 1, 2, 5 one can represented as the DAG
    with nodes 1..7 and edges

        1 --> 3 <-- 2 (q^3 = q^1 * q^2)
        2 --> 4 <-- 2 (q^4 = q^2 * q^2; repeated edge)
        1 --> 6 <-- 5 (q^6 = q^1 * q^5)
        2 --> 7 <-- 5 (q^7 = q^2 * q^5)

    The graph above describes how q^1...q^7 can be computed from q^1, q^2, and q^5 with a depth 1
    circuit. A PowersDag is configured from a given set of source powers ({ 1, 2, 5 } in the example
    above). The class contains no mechanism for discovering a good set of source powers: it is up to
    the user to find using methods external to APSI.
    */
    class PowersDag {
    public:
        /**
        Represents an individual node in the PowersDag. The node holds the power it represents, and
        depth in the DAG. Source nodes (i.e., powers of a query that are given directly and do not
        need to be computed), have depth zero. The node also holds the powers of its parents; parent
        values both 0 denotes that this is a source node. If only one of the parent values is zero
        this node is invalid and the PowersDag is in an invalid state. For the DAG to be in a valid
        state, for each non-source node, the sum of the powers of the parent nodes of a given must
        equal the power of that node.
        */
        struct PowersNode {
            /**
            The power represented by this node. In a valid PowersDag this can never be zero.
            */
            std::uint32_t power = 0;

            /**
            The depth of this node in the DAG.
            */
            std::uint32_t depth = 0;

            /**
            Holds the powers of the two parents of this node. Both values must either be zero
            indicating that this is a source node, or non-zero.
            */
            std::pair<std::uint32_t, std::uint32_t> parents{ 0, 0 };

            /**
            Returns whether this is a source node.
            */
            bool is_source() const
            {
                return !parents.first && !parents.second;
            }
        };

        /**
        Creates a new PowersDag. The DAG must be configured before it can be used.
        */
        PowersDag() = default;

        /**
        Attempts to initialize the PowersDag from the given source powers, computing powers up to
        the given value. The function returns true on success.
        */
        bool configure(std::set<std::uint32_t> source_powers, std::uint32_t up_to_power);

        /**
        Reset all internal members of the PowersDag instance.
        */
        void reset()
        {
            up_to_power_ = 0;
            depth_ = 0;
            source_count_ = 0;
            configured_ = false;
        }

        /**
        Returns whether the PowersDag was successfully configured.
        */
        bool is_configured() const
        {
            return configured_;
        }

        /**
        Returns up to which power the PowersDag was configured to compute. If the PowersDag is not
        configured, this function throws an exception.
        */
        std::uint32_t up_to_power() const;

        /**
        Returns the maximal depth of the computation represented by the PowersDag. If the PowersDag
        is not configured, this function throws an exception.
        */
        std::uint32_t depth() const;

        /**
        Returns the number of source nodes required by the PowersDag. If the PowersDag is not
        configured, this function throws an exception.
        */
        std::uint32_t source_count() const;

        /**
        Returns a set of source nodes for this PowersDag. If the PowersDag is not configured, this
        function throws an exception.
        */
        std::vector<PowersNode> source_nodes() const;

        /**
        Returns this PowersDag in the DOT format as a string.
        */
        std::string to_dot() const;

        /**
        Applies a function in a topological order to each node in the PowersDag.
        */
        template <typename Func>
        void apply(Func &&func) const
        {
            if (!is_configured()) {
                throw std::logic_error("PowersDag has not been configured");
            }

            for (std::uint32_t power = 1; power <= up_to_power_; power++) {
                func(nodes_.at(power));
            }
        }

        /**
        Applies a function in a topological order to each node in the PowersDag using multiple
        threads.
        */
        template <typename Func>
        void parallel_apply(Func &&func) const
        {
            if (!is_configured()) {
                throw std::logic_error("PowersDag has not been configured");
            }

            ThreadPoolMgr tpm;

            enum class NodeState { Uncomputed = 0, Computing = 1, Computed = 2 };

            std::unique_ptr<std::atomic<NodeState>[]> node_states(
                new std::atomic<NodeState>[up_to_power_]);
            for (std::uint32_t i = 0; i < up_to_power_; i++) {
                if (nodes_.at(i + 1).is_source()) {
                    // Process source nodes right now
                    func(nodes_.at(i + 1));
                    node_states[i].store(NodeState::Computed);
                } else {
                    // Other nodes are still uncomputed
                    node_states[i].store(NodeState::Uncomputed);
                }
            }

            auto compute_powers = [&]() {
                // Start looking for work by going over node_states vector
                std::uint32_t ns = 0;
                while (true) {
                    // Check if everything is done
                    bool done = std::all_of(
                        node_states.get(), node_states.get() + up_to_power_, [](auto &ns) {
                            return ns == NodeState::Computed;
                        });
                    if (done) {
                        return;
                    }

                    NodeState state = NodeState::Uncomputed;
                    bool cmp = node_states[ns].compare_exchange_strong(state, NodeState::Computing);

                    if (!cmp) {
                        // Either done or already being processed
                        ns = (ns + 1) % up_to_power_;
                        continue;
                    }

                    // Check for parents
                    auto node = nodes_.at(ns + 1);
                    auto p1 = node.parents.first;
                    auto p2 = node.parents.second;
                    bool p1_computed = node_states[p1 - 1] == NodeState::Computed;
                    bool p2_computed = node_states[p2 - 1] == NodeState::Computed;

                    if (!(p1_computed && p2_computed)) {
                        // Parents are not done
                        NodeState state = NodeState::Computing;
                        node_states[ns].compare_exchange_strong(state, NodeState::Uncomputed);

                        // Move on to the next node
                        ns = (ns + 1) % up_to_power_;
                        continue;
                    }

                    // Parents are done so process this node
                    func(nodes_.at(ns + 1));

                    state = NodeState::Computing;
                    node_states[ns].compare_exchange_strong(state, NodeState::Computed);

                    // Move on to the next node
                    ns = (ns + 1) % up_to_power_;
                }
            };

            std::size_t task_count = ThreadPoolMgr::GetThreadCount();
            std::vector<std::future<void>> futures(task_count);
            for (std::size_t t = 0; t < task_count; t++) {
                futures[t] = tpm.thread_pool().enqueue(compute_powers);
            }

            for (auto &f : futures) {
                f.get();
            }
        }

        /**
        Creates a new PowersDag instance by copying a given one.
        */
        PowersDag(const PowersDag &pd) = default;

    private:
        std::unordered_map<std::uint32_t, PowersNode> nodes_;

        bool configured_ = false;

        std::uint32_t up_to_power_;

        std::uint32_t depth_;

        std::uint32_t source_count_;
    };
} // namespace apsi
