#pragma once

// STD
#include <list>
#include <string>
#include <chrono>
#include <ostream>
#include <mutex>


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
            Represents a measurable event
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
            Represents a measurable event with beginning and end
            */
            class StopwatchBeginEndEvent : public StopwatchEvent
            {
            public:
                StopwatchBeginEndEvent() = delete;
                StopwatchBeginEndEvent(const std::string& name, const time_unit& start, const time_unit& end)
                    : StopwatchEvent(name, start), end_(end)
                {}

            private:
                time_unit end_;
            };

        public:
            const static time_unit start_time;
            std::list< std::pair<time_unit, std::string> > time_points;
            const time_unit &set_time_point(const std::string &message);

            friend std::ostream &operator <<(std::ostream &out, const Stopwatch &stopwatch);

            /**
            Add a single time event
            */
            void add_event(const std::string& name, const time_unit& start);

            /**
            Add a time event with beginning and end
            */
            void add_timespan_event(const std::string& name, const time_unit& start, const time_unit& end);

        private:
            // Single events
            std::list<StopwatchEvent> events_;
            std::mutex events_mtx_;

            // Events that have a beginning and end
            std::list<StopwatchBeginEndEvent> timespan_events_;
            std::mutex timespan_events_mtx_;
        };

        /**
        Class used to time a scope.
        
        Simply create a variable of this type in the scope that you want to measure.
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
