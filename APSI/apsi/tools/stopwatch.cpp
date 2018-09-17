// STD
#include <cstdint>
#include <algorithm>
#include <iomanip>
#include <map>
#include <sstream>

// APSI
#include "apsi/tools/stopwatch.h"

using namespace std;
using namespace apsi;
using namespace apsi::tools;


const Stopwatch::time_unit Stopwatch::start_time(Stopwatch::time_unit::clock::now());

const Stopwatch::time_unit &Stopwatch::set_time_point(const std::string &message)
{
    time_points.push_back(make_pair(time_unit::clock::now(), message));
    return time_points.back().first;
}

ostream &apsi::tools::operator <<(ostream &out, const Stopwatch &stopwatch)
{
    size_t length = 0; 
    for (auto tp : stopwatch.time_points)
    {
        length = std::max<size_t>(tp.second.size(), length);
    }

    auto prev_time = stopwatch.start_time;
    for (auto tp : stopwatch.time_points)
    {
        out << std::setw(length) << std::setfill(' ') << tp.second
            << " | Since last: "
            << std::setw(5) << std::setfill(' ') << chrono::duration_cast<chrono::milliseconds>(tp.first - prev_time).count()
            << " milliseconds"
            << " | Total: "
            << std::setw(5) << std::setfill(' ') << chrono::duration_cast<chrono::milliseconds>(tp.first - stopwatch.start_time).count()
            << " milliseconds"
            << endl;
        prev_time = tp.first;
    }

    return out;
}

void Stopwatch::add_event(const string& name, const time_unit& start)
{
    unique_lock<mutex> events_lock(events_mtx_);
    events_.emplace_back(name, start);
}

void Stopwatch::add_timespan_event(const string& name, const time_unit& start, const time_unit& end)
{
    unique_lock<mutex> timespan_events_lock(timespan_events_mtx_);
    timespan_events_.emplace_back(name, start, end);
}


void Stopwatch::get_timespans(vector<TimespanSummary>& timespans)
{
    map<string, TimespanSummary> evts;
    unique_lock<mutex> timespan_events_lock(timespan_events_mtx_);

    for (const auto& evt : timespan_events_)
    {
        auto evtcalc = evts.find(evt.name());
        u64 duration = static_cast<u64>(chrono::duration_cast<chrono::milliseconds>(evt.end() - evt.start()).count());
        if (evtcalc == evts.end())
        {
            // Insert new
            TimespanSummary summ = {/* name */ evt.name(),
                                    /* count */ 1,
                                    /* average */ static_cast<double>(duration),
                                    /* sum */ duration,
                                    /* min */ duration,
                                    /* max */ duration };
            evts.insert_or_assign(evt.name(), summ);
        }
        else
        {
            // Update existing
            evtcalc->second.event_count++;
            evtcalc->second.sum += duration;
            evtcalc->second.avg = static_cast<double>(evtcalc->second.sum) / evtcalc->second.event_count;

            if (evtcalc->second.min > duration)
            {
                evtcalc->second.min = duration;
            }

            if (evtcalc->second.max < duration)
            {
                evtcalc->second.max = duration;
            }
        }
    }

    timespans.clear();
    for (const auto& evtsumm : evts)
    {
        timespans.push_back(evtsumm.second);
    }
}

void Stopwatch::get_events(vector<Timepoint>& events)
{
    unique_lock<mutex> events_lock(events_mtx_);

    events.clear();
    for (const auto& evt : events_)
    {
        Timepoint timept = { evt.name(), evt.start() };
        events.push_back(timept);
    }
}

StopwatchScope::StopwatchScope(Stopwatch& stopwatch, const std::string& event_name)
    : stopwatch_(stopwatch), event_name_(event_name), start_(Stopwatch::time_unit::clock::now())
{
}

StopwatchScope::~StopwatchScope()
{
    Stopwatch::time_unit end = Stopwatch::time_unit::clock::now();
    stopwatch_.add_timespan_event(event_name_, start_, end);
}
