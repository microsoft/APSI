// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "apsi/util/stopwatch.h"
#include <sstream>

using namespace std;

namespace apsi
{
    namespace util
    {
        const Stopwatch::time_unit Stopwatch::start_time(Stopwatch::time_unit::clock::now());

        Stopwatch::Stopwatch()
            : events_mtx_(make_shared<mutex>()), timespan_events_mtx_(make_shared<mutex>()), max_event_name_length_(0),
              max_timespan_event_name_length_(0)
        {}

        void Stopwatch::add_event(const string &name)
        {
            unique_lock<mutex> events_lock(*events_mtx_);
            events_.push_back(Timepoint{ name, time_unit::clock::now() });

            if (static_cast<int>(name.length()) > max_event_name_length_)
            {
                max_event_name_length_ = static_cast<int>(name.length());
            }
        }

        void Stopwatch::add_timespan_event(const string &name, const time_unit &start, const time_unit &end)
        {
            unique_lock<mutex> timespan_events_lock(*timespan_events_mtx_);
            uint64_t duration = static_cast<uint64_t>(chrono::duration_cast<chrono::milliseconds>(end - start).count());
            auto timespan_evt = timespan_events_.find(name);

            if (timespan_evt == timespan_events_.end())
            {
                // Insert new
                TimespanSummary summ = { /* name */ name,
                                         /* count */ 1,
                                         /* average */ static_cast<double>(duration),
                                         /* min */ duration,
                                         /* max */ duration };

                timespan_events_[name] = summ;

                if (static_cast<int>(name.length()) > max_timespan_event_name_length_)
                {
                    max_timespan_event_name_length_ = static_cast<int>(name.length());
                }
            }
            else
            {
                // Update existing
                timespan_evt->second.event_count++;
                timespan_evt->second.avg =
                    (timespan_evt->second.avg * (timespan_evt->second.event_count - 1) + duration) /
                    timespan_evt->second.event_count;

                if (timespan_evt->second.min > duration)
                {
                    timespan_evt->second.min = duration;
                }

                if (timespan_evt->second.max < duration)
                {
                    timespan_evt->second.max = duration;
                }
            }
        }

        void Stopwatch::get_timespans(vector<TimespanSummary> &timespans)
        {
            unique_lock<mutex> timespan_events_lock(*timespan_events_mtx_);

            timespans.clear();
            for (const auto &timespan_evt : timespan_events_)
            {
                timespans.push_back(timespan_evt.second);
            }
        }

        void Stopwatch::get_events(vector<Timepoint> &events)
        {
            unique_lock<mutex> events_lock(*events_mtx_);

            events.clear();
            for (const auto &evt : events_)
            {
                events.push_back(evt);
            }
        }

        StopwatchScope::StopwatchScope(Stopwatch &stopwatch, const string &event_name)
            : stopwatch_(stopwatch), event_name_(event_name), start_(Stopwatch::time_unit::clock::now())
        {}

        StopwatchScope::~StopwatchScope()
        {
            Stopwatch::time_unit end = Stopwatch::time_unit::clock::now();
            stopwatch_.add_timespan_event(event_name_, start_, end);
        }
    } // namespace util
} // namespace apsi
