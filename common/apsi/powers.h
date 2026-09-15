// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <exception>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

// APSI
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/task_group.h"

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
            [[nodiscard]] bool is_source() const
            {
                return !parents.first && !parents.second;
            }
        };

        /**
        Creates a new PowersDag. The DAG must be configured before it can be used.
        */
        PowersDag() = default;

        /**
        Attempts to initialize the PowersDag by computing target powers from source powers. The
        function returns true on success.
        */
        bool configure(
            std::set<std::uint32_t> source_powers, std::set<std::uint32_t> target_powers);

        /**
        Reset all internal members of the PowersDag instance.
        */
        void reset()
        {
            target_powers_.clear();
            depth_ = 0;
            source_count_ = 0;
            configured_ = false;
        }

        /**
        Returns whether the PowersDag was successfully configured.
        */
        [[nodiscard]] bool is_configured() const
        {
            return configured_;
        }

        /**
        Returns the target powers that this PowersDag computes. If the PowersDag is not
        configured, this function throws an exception.
        */
        [[nodiscard]] std::set<std::uint32_t> target_powers() const;

        /**
        Returns the maximal depth of the computation represented by the PowersDag. If the PowersDag
        is not configured, this function throws an exception.
        */
        [[nodiscard]] std::uint32_t depth() const;

        /**
        Returns the number of source nodes required by the PowersDag. If the PowersDag is not
        configured, this function throws an exception.
        */
        [[nodiscard]] std::uint32_t source_count() const;

        /**
        Returns a set of source nodes for this PowersDag. If the PowersDag is not configured, this
        function throws an exception.
        */
        [[nodiscard]] std::vector<PowersNode> source_nodes() const;

        /**
        Returns this PowersDag in the DOT format as a string.
        */
        [[nodiscard]] std::string to_dot() const;

        /**
        Applies a function in a topological order to each node in the PowersDag.
        */
        template <typename Func>
        void apply(Func &&func) const
        {
            if (!is_configured()) {
                throw std::logic_error("PowersDag has not been configured");
            }

            for (std::uint32_t power : target_powers_) {
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

            // Create a temporary vector of target powers instead so we can index into it
            std::vector<std::uint32_t> target_powers_vec(
                target_powers_.cbegin(), target_powers_.cend());
            std::size_t target_powers_count = target_powers_vec.size();

            enum class NodeState { Uncomputed = 0, Computing = 1, Computed = 2 };

            // Initialize all nodes as uncomputed
            std::vector<std::atomic<NodeState>> node_states(target_powers_count);
            for (std::size_t power_idx = 0; power_idx < target_powers_count; power_idx++) {
                node_states[power_idx].store(NodeState::Uncomputed);
            }

            // Shared failure state. A worker that throws leaves its node in the Computing state
            // forever, so the completion check below could never pass again: every other worker
            // would spin at 100% CPU and never return, which in turn makes ~ThreadPool block
            // forever waiting for them. Recording the failure lets all workers exit promptly; the
            // first exception is rethrown after every worker has been joined.
            std::atomic<bool> failed(false);
            std::mutex failure_mutex;
            std::exception_ptr first_exception;

            auto capture_failure = [&]() {
                {
                    std::lock_guard<std::mutex> lock(failure_mutex);
                    if (!first_exception) {
                        first_exception = std::current_exception();
                    }
                }
                failed.store(true);
            };

            auto node_worker = [&]() {
                // Start looking for work by going over node_states vector
                std::size_t power_idx = 0;
                while (true) {
                    // Give up as soon as any worker has failed
                    if (failed.load()) {
                        return;
                    }

                    // Check if everything is done
                    bool done = std::all_of(
                        node_states.data(),
                        node_states.data() + target_powers_count,
                        [](auto &node_state) { return node_state == NodeState::Computed; });
                    if (done) {
                        return;
                    }

                    std::uint32_t power = target_powers_vec[power_idx];
                    NodeState state = NodeState::Uncomputed;
                    bool cmp =
                        node_states[power_idx].compare_exchange_strong(state, NodeState::Computing);

                    if (!cmp) {
                        // Either done or already being processed. Yield before trying the next
                        // node: when few nodes remain, every worker but one lands here on each
                        // pass and would otherwise spin the loop hot against the workers that
                        // are making progress.
                        power_idx = (power_idx + 1) % target_powers_count;
                        std::this_thread::yield();
                        continue;
                    }

                    // Get the current node
                    auto node = nodes_.at(power);

                    // If this is a source we can immediately process it
                    if (node.is_source()) {
                        // We can immediately process a source node
                        func(nodes_.at(power));

                        // Done with this source node; mark it as computed
                        state = NodeState::Computing;
                        node_states[power_idx].compare_exchange_strong(state, NodeState::Computed);

                        // Move on to the next node
                        power_idx = (power_idx + 1) % target_powers_count;
                        continue;
                    }

                    // Next check if parents have been computed; start by finding the parent powers
                    std::uint32_t p1 = node.parents.first;
                    std::uint32_t p2 = node.parents.second;

                    // The parents are always found in target_powers_vec
                    auto p1_power_iter =
                        std::find(target_powers_vec.cbegin(), target_powers_vec.cend(), p1);
                    auto p2_power_iter =
                        std::find(target_powers_vec.cbegin(), target_powers_vec.cend(), p2);
                    if (p1_power_iter == target_powers_vec.cend() ||
                        p2_power_iter == target_powers_vec.cend()) {
                        throw std::runtime_error("PowersDag is in an invalid state");
                    }

                    // Compute the locations in node_states
                    std::size_t p1_power_idx = static_cast<std::size_t>(
                        std::distance(target_powers_vec.cbegin(), p1_power_iter));
                    std::size_t p2_power_idx = static_cast<std::size_t>(
                        std::distance(target_powers_vec.cbegin(), p2_power_iter));

                    // Are the parents computed?
                    bool p1_computed = node_states[p1_power_idx] == NodeState::Computed;
                    bool p2_computed = node_states[p2_power_idx] == NodeState::Computed;

                    if (!(p1_computed && p2_computed)) {
                        // Parents are not done
                        NodeState computing_state = NodeState::Computing;
                        node_states[power_idx].compare_exchange_strong(
                            computing_state, NodeState::Uncomputed);

                        // Move on to the next node. Yield to give other workers a chance to
                        // make progress on parent nodes; without this, this thread will
                        // spin-loop hot when only a few nodes are still in flight.
                        power_idx = (power_idx + 1) % target_powers_count;
                        std::this_thread::yield();
                        continue;
                    }

                    // Parents are done so process this node
                    func(nodes_.at(power));

                    // Done with this node; mark it as computed
                    state = NodeState::Computing;
                    node_states[power_idx].compare_exchange_strong(state, NodeState::Computed);

                    // Move on to the next node
                    power_idx = (power_idx + 1) % target_powers_count;
                }
            };

            // Declared last, and so destroyed first: the workers hold references to every local
            // above, and the TaskGroup's destructor waits for all of them. ~ThreadPoolMgr sitting
            // below it releases this scope's reference to the shared pool; it blocks for the
            // workers only when it happens to be the last reference, which it usually is not --
            // Sender::RunQuery, for instance, holds one of its own further up the stack.
            ThreadPoolMgr tpm;
            util::TaskGroup tasks(tpm.thread_pool());

            std::size_t task_count = ThreadPoolMgr::GetThreadCount();
            tasks.reserve(task_count);
            try {
                for (std::size_t t = 0; t < task_count; t++) {
                    tasks.add([&]() {
                        try {
                            node_worker();
                        } catch (...) {
                            capture_failure();
                        }
                    });
                }

                // Every worker must be joined before any of the state it captured by reference
                // goes out of scope.
                tasks.join();
            } catch (...) {
                // Either a task could not be queued, or join() surfaced an exception that a worker
                // was unable to record itself. Workers spin until every node is computed or a
                // failure is recorded, so they must be told to stop; anything still running is
                // then drained by the TaskGroup destructor.
                capture_failure();
            }

            if (first_exception) {
                std::rethrow_exception(first_exception);
            }
        }

        /**
        Creates a new PowersDag instance by copying a given one.
        */
        PowersDag(const PowersDag &pd) = default;

    private:
        std::unordered_map<std::uint32_t, PowersNode> nodes_;

        bool configured_ = false;

        std::set<std::uint32_t> target_powers_;

        std::uint32_t depth_{};

        std::uint32_t source_count_{};
    };
} // namespace apsi
