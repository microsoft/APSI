#include "apsi/tools/stopwatch.h"
#include <cstdint>
#include <algorithm>
#include <iomanip>

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


StopwatchScope::StopwatchScope(Stopwatch& stopwatch, const std::string& event_name)
    : stopwatch_(stopwatch), event_name_(event_name), start_(Stopwatch::time_unit::clock::now())
{
}

StopwatchScope::~StopwatchScope()
{
    Stopwatch::time_unit end = Stopwatch::time_unit::clock::now();
    stopwatch_.add_timespan_event(event_name_, start_, end);
}
