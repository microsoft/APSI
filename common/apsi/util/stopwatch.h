// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <chrono>
#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <ostream>
#include <string>
#include <vector>

// Macro Magic to generate unique variable names. This is used for the STOPWATCH macro.
#define PP_CAT_II(p, res) res
#define PP_CAT_I(a, b) PP_CAT_II(~, a##b)
#define PP_CAT(a, b) PP_CAT_I(a, b)
#define UNIQUE_STOPWATCH_NAME(base) PP_CAT(base, __LINE__)

// Measure a block
#define STOPWATCH(stopwatch, name) \
    apsi::util::StopwatchScope UNIQUE_STOPWATCH_NAME(stopwatchscope)(stopwatch, name);

namespace apsi {
    namespace util {
        /**
        Class used to time events
        */
        class Stopwatch {
            friend class StopwatchScope;

        public:
            using time_unit = std::chrono::high_resolution_clock::time_point;

            /**
            Structure used to accumulate data about timespan timing events
            */
            struct TimespanSummary {
                std::string event_name;
                int event_count;
                double avg;
                std::uint64_t min;
                std::uint64_t max;
            };

            /**
            Structure used to report single events
            */
            struct Timepoint {
                std::string event_name;
                time_unit time_point;
            };

            /**
            Used as a reference point for single events
            */
            const static time_unit start_time;

            /**
            Add a single time event
            */
            void add_event(const std::string &name);

            /**
            Get the timespan timings we have stored at the moment.
            */
            void get_timespans(std::vector<TimespanSummary> &timespans) const;

            /**
            Get the single event timings we have stored at the moment.
            */
            void get_events(std::vector<Timepoint> &events) const;

            /**
            Get the length of the longest single event name
            */
            int get_max_event_name_length() const
            {
                return max_event_name_length_;
            }

            /**
            Get the length of the longest timespan event name
            */
            int get_max_timespan_event_name_length() const
            {
                return max_timespan_event_name_length_;
            }

        private:
            // Single events
            std::list<Timepoint> events_;
            mutable std::mutex events_mtx_;

            // Events that have a beginning and end
            std::map<std::string, TimespanSummary> timespan_events_;
            mutable std::mutex timespan_events_mtx_;

            // Useful for generating reports
            int max_event_name_length_ = 0;
            int max_timespan_event_name_length_ = 0;

            /**
            Add a time event with beginning and end
            */
            void add_timespan_event(
                const std::string &name, const time_unit &start, const time_unit &end);
        }; // class Stopwatch

        /**
        Class used to time a scope. Simply declare a variable of this type in the scope that you
        want to measure.
        */
        class StopwatchScope {
        public:
            StopwatchScope(Stopwatch &stopwatch, const std::string &event_name);
            ~StopwatchScope();

        private:
            Stopwatch &stopwatch_;
            std::string event_name_;
            Stopwatch::time_unit start_;
        }; // class StopwatchScope

        /**
        Global Stopwatch objects for sender and receiver to use.
        */
        extern Stopwatch sender_stopwatch, recv_stopwatch;
    } // namespace util
} // namespace apsi
