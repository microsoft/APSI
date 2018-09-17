#pragma once

// STD
#include <list>
#include <string>
#include <chrono>
#include <ostream>
#include <mutex>
#include <vector>

// APSI
#include "apsi/apsidefines.h"


namespace apsi
{
    namespace tools
    {
        /**
        Class used to time events
        */
        class Stopwatch
        {
        public:
            typedef std::chrono::high_resolution_clock::time_point time_unit;

        private:
            /**
            Represents a time event
            */
            class StopwatchEvent
            {
            public:
                StopwatchEvent() = delete;
                StopwatchEvent(const std::string& name, const time_unit& start)
                    : name_(name), start_(start)
                {}

                const std::string& name() const { return name_; }
                const time_unit& start() const { return start_; }

            private:
                std::string name_;
                time_unit start_;
            };

            /**
            Represents a time event with beginning and end
            */
            class StopwatchBeginEndEvent : public StopwatchEvent
            {
            public:
                StopwatchBeginEndEvent() = delete;
                StopwatchBeginEndEvent(const std::string& name, const time_unit& start, const time_unit& end)
                    : StopwatchEvent(name, start), end_(end)
                {}

                const time_unit& end() const { return end_; }

            private:
                time_unit end_;
            };

        public:
            /**
            Structure used to accumulate data about timespan timing events
            */
            struct TimespanSummary
            {
                std::string event_name;
                int event_count;
                double avg;
                apsi::u64 sum;
                apsi::u64 min;
                apsi::u64 max;
            };

            /**
            Structure used to report single events
            */
            struct Timepoint
            {
                std::string event_name;
                time_unit time_point;
            };

            /**
            Default constructor
            */
            Stopwatch()
                : max_event_name_length_(0),
                  max_timespan_event_name_length_(0)
            {}

            /**
            Used as a reference point for single events
            */
            const static time_unit start_time;

            /**
            Add a single time event
            */
            void add_event(const std::string& name);

            /**
            Add a time event with beginning and end
            */
            void add_timespan_event(const std::string& name, const time_unit& start, const time_unit& end);

            /**
            Get the timespan timings we have stored at the moment.
            */
            void get_timespans(std::vector<TimespanSummary>& timespans);

            /**
            Get the single event timings we have stored at the moment.
            */
            void get_events(std::vector<Timepoint>& events);

            /**
            Get the length of the longest single event name
            */
            int get_max_event_name_length() const { return max_event_name_length_; }

            /**
            Get the length of the longest timespan event name
            */
            int get_max_timespan_event_name_length() const { return max_timespan_event_name_length_; }

        private:
            // Single events
            std::list<StopwatchEvent> events_;
            std::mutex events_mtx_;

            // Events that have a beginning and end
            std::list<StopwatchBeginEndEvent> timespan_events_;
            std::mutex timespan_events_mtx_;

            // Useful for generating reports
            int max_event_name_length_;
            int max_timespan_event_name_length_;
        };

        /**
        Class used to time a scope.
        
        Simply declare a variable of this type in the scope that you want to measure.
        */
        class StopwatchScope
        {
        public:
            StopwatchScope(Stopwatch& stopwatch, const std::string& event_name);
            ~StopwatchScope();

        private:
            Stopwatch& stopwatch_;
            std::string event_name_;
            Stopwatch::time_unit start_;
        };
    }
}
