#pragma once

// STD
#include <list>
#include <string>
#include <chrono>
#include <ostream>
#include <mutex>
#include <vector>
#include <map>

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
            friend class StopwatchScope;

        public:
            typedef std::chrono::high_resolution_clock::time_point time_unit;

            /**
            Structure used to accumulate data about timespan timing events
            */
            struct TimespanSummary
            {
                std::string event_name;
                int event_count;
                double avg;
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
            std::list<Timepoint> events_;
            std::mutex events_mtx_;

            // Events that have a beginning and end
            std::map<std::string, TimespanSummary> timespan_events_;
            std::mutex timespan_events_mtx_;

            // Useful for generating reports
            int max_event_name_length_;
            int max_timespan_event_name_length_;

            /**
            Add a time event with beginning and end
            */
            void add_timespan_event(const std::string& name, const time_unit& start, const time_unit& end);
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
