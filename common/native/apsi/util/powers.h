// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <utility>
#include <memory>
#include <unordered_map>
#include <random>
#include <string>
#include <vector>
#include <stdexcept>
#include <thread>
#include <atomic>
#include <algorithm>
#include <iostream>

namespace apsi
{
    namespace util
    {
        class PowersDag
        {
        public:
            struct PowersNode
            {
                std::uint32_t power = 0;

                std::uint32_t depth = 0;

                std::pair<PowersNode*, PowersNode*> parents{ nullptr, nullptr };

                bool is_source() const
                {
                    return !parents.first && !parents.second;
                }
            };

            PowersDag() : mt_(std::random_device{}())
            {}

            bool configure(
                std::uint32_t up_to_power,
                std::uint32_t depth_bound,
                std::uint32_t source_count_bound);

            void reset()
            {
                nodes_.clear();
                up_to_power_ = 0;
                depth_ = 0;
                source_count_ = 0;
                configured_ = false;
            }

            bool configured() const
            {
                return configured_;
            }

            std::uint32_t up_to_power() const;

            std::uint32_t depth() const;

            std::uint32_t source_count() const;

            std::vector<PowersNode> source_nodes() const;

            std::string to_dot() const;

            template<typename Func>
            void apply(Func &&func) const
            {
                if (!configured())
                {
                    throw std::logic_error("PowersDag has not been configured");
                }

                for (std::uint32_t power = 1; power <= up_to_power_; power++)
                {
                    func(nodes_.at(power));
                }
            }

            template<typename Func>
            void parallel_apply(Func &&func, std::size_t thread_count = 0) const
            {
                if (!configured())
                {
                    throw std::logic_error("PowersDag has not been configured");
                }

                thread_count = thread_count < 1 ? std::thread::hardware_concurrency() : thread_count;

                enum class NodeState
                {
                    Uncomputed = 0,
                    Computing = 1,
                    Done = 2
                };

                std::unique_ptr<std::atomic<NodeState>[]> node_states(new std::atomic<NodeState>[up_to_power_]);
                for (std::uint32_t i = 0; i < up_to_power_; i++)
                {
                    if (nodes_.at(i + 1).is_source())
                    {
                        // Process source nodes right now
                        func(nodes_.at(i + 1));
                        node_states[i].store(NodeState::Done);
                    }
                    else
                    {
                        // Other nodes are still uncomputed
                        node_states[i].store(NodeState::Uncomputed);
                    }
                }

                std::vector<std::thread> threads;
                for (std::size_t t = 0; t < thread_count; t++)
                {
                    threads.emplace_back([&, t]() {
                        // Start looking for work by going over node_states vector
                        std::uint32_t ns = 0;
                        while (true)
                        {
                            // Check if everything is done
                            bool done = std::all_of(node_states.get(), node_states.get() + up_to_power_, [](auto &ns) {
                                return ns == NodeState::Done;
                            });
                            if (done)
                            {
                                return;
                            }

                            NodeState state = NodeState::Uncomputed;
                            bool cmp = node_states[ns].compare_exchange_strong(
                                state, NodeState::Computing);

                            if (!cmp)
                            {
                                // Either done or already being processed
                                ns = (ns + 1) % up_to_power_;
                                continue;
                            }

                            // Check for parents 
                            auto node = nodes_.at(ns + 1);
                            auto p1 = node.parents.first;
                            auto p2 = node.parents.second;
                            bool p1_done = node_states[p1->power - 1] == NodeState::Done;
                            bool p2_done = node_states[p2->power - 1] == NodeState::Done;

                            if (!(p1_done && p2_done))
                            {
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
                            node_states[ns].compare_exchange_strong(state, NodeState::Done);

                            // Move on to the next node
                            ns = (ns + 1) % up_to_power_;
                        }
                    });
                }

                for (auto &th : threads)
                {
                    th.join();
                }
            }

            /**
            Writes the PowersDag to a stream.
            */
            std::size_t save(std::ostream &out) const;

            /**
            Reads the PowersDag from a stream.
            */
            std::size_t load(std::istream &in);

        private:
            static constexpr std::uint32_t attempts_ = 1000;

            std::unordered_map<std::uint32_t, PowersNode> nodes_;

            std::mt19937 mt_;

            std::uniform_real_distribution<double> rnd_{ 0, 1 };

            bool configured_ = false;

            std::uint32_t up_to_power_;

            std::uint32_t depth_;

            std::uint32_t source_count_;
        };

        PowersDag optimal_powers(std::uint32_t up_to_power, std::uint32_t source_count);
    }
}
