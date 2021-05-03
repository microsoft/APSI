// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSI
#include "apsi/util/stopwatch.h"

using namespace std;

namespace apsi {
    namespace util {
        const Stopwatch::time_unit Stopwatch::start_time(Stopwatch::time_unit::clock::now());

        void Stopwatch::add_event(const string &name)
        {
            Timepoint tp{ name, time_unit::clock::now() };
            lock_guard<mutex> events_lock(events_mtx_);
            events_.push_back(tp);

            if (static_cast<int>(name.length()) > max_event_name_length_) {
                max_event_name_length_ = static_cast<int>(name.length());
            }
        }

        void Stopwatch::add_timespan_event(
            const string &name, const time_unit &start, const time_unit &end)
        {
            uint64_t duration = static_cast<uint64_t>(
                chrono::duration_cast<chrono::milliseconds>(end - start).count());
            lock_guard<mutex> timespan_events_lock(timespan_events_mtx_);
            auto timespan_evt = timespan_events_.find(name);

            if (timespan_evt == timespan_events_.end()) {
                // Insert new
                TimespanSummary summ = { /* name */ name,
                                         /* count */ 1,
                                         /* average */ static_cast<double>(duration),
                                         /* min */ duration,
                                         /* max */ duration };

                timespan_events_[name] = summ;

                if (static_cast<int>(name.length()) > max_timespan_event_name_length_) {
                    max_timespan_event_name_length_ = static_cast<int>(name.length());
                }
            } else {
                // Update existing
                timespan_evt->second.event_count++;
                timespan_evt->second.avg =
                    (timespan_evt->second.avg * (timespan_evt->second.event_count - 1) +
                     static_cast<double>(duration)) /
                    timespan_evt->second.event_count;

                if (timespan_evt->second.min > duration) {
                    timespan_evt->second.min = duration;
                }

                if (timespan_evt->second.max < duration) {
                    timespan_evt->second.max = duration;
                }
            }
        }

        void Stopwatch::get_timespans(vector<TimespanSummary> &timespans) const
        {
            lock_guard<mutex> timespan_events_lock(timespan_events_mtx_);

            timespans.clear();
            for (const auto &timespan_evt : timespan_events_) {
                timespans.push_back(timespan_evt.second);
            }
        }

        void Stopwatch::get_events(vector<Timepoint> &events) const
        {
            lock_guard<mutex> events_lock(events_mtx_);

            events.clear();
            for (const auto &evt : events_) {
                events.push_back(evt);
            }
        }

        StopwatchScope::StopwatchScope(Stopwatch &stopwatch, const string &event_name)
            : stopwatch_(stopwatch), event_name_(event_name),
              start_(Stopwatch::time_unit::clock::now())
        {}

        StopwatchScope::~StopwatchScope()
        {
            Stopwatch::time_unit end = Stopwatch::time_unit::clock::now();
            stopwatch_.add_timespan_event(event_name_, start_, end);
        }

        Stopwatch sender_stopwatch;
        Stopwatch recv_stopwatch;
    } // namespace util
} // namespace apsi
