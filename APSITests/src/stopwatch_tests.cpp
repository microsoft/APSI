#include "stopwatch_tests.h"
#include "apsi/tools/stopwatch.h"
#include <algorithm>
#include <thread>


using namespace std;
using namespace APSITests;
using namespace apsi;
using namespace apsi::tools;

CPPUNIT_TEST_SUITE_REGISTRATION(StopwatchTests);

namespace {
    void get_thread_name(int idx, string& str)
    {
        stringstream ss;
        ss << "th" << idx;
        str = ss.str();
    }
}

void StopwatchTests::single_event_test()
{
    Stopwatch sw;

    sw.add_event("one");
    this_thread::sleep_for(51ms);
    sw.add_event("two");

    // Difference should be at least 50ms
    vector<Stopwatch::Timepoint> timepoints;
    sw.get_events(timepoints);

    CPPUNIT_ASSERT("one" == timepoints[0].event_name);
    CPPUNIT_ASSERT("two" == timepoints[1].event_name);

    auto diff = chrono::duration_cast<chrono::milliseconds>(timepoints[1].time_point - timepoints[0].time_point).count();
    string msg;
    {
        stringstream ss;
        ss << "Duration should be at least 50ms, it is: " << diff;
        msg = ss.str();
    }

    CPPUNIT_ASSERT_MESSAGE(msg.c_str(), diff >= 50);
}

void StopwatchTests::single_event_multithreading_test()
{
    Stopwatch sw;

    vector<thread> threads(20);
    for (int i = 0; i < threads.size(); i++)
    {
        threads[i] = thread([&](int idx)
        {
            string evt_name;
            get_thread_name(idx, evt_name);

            for (int j = 0; j < 6; j++)
            {
                int millis = (std::rand() * 10 / RAND_MAX);
                chrono::milliseconds ms(millis);
                this_thread::sleep_for(ms);

                sw.add_event(evt_name);
            }
        }, i);
    }

    for (auto& thr : threads)
    {
        thr.join();
    }

    vector<Stopwatch::Timepoint> tps;
    sw.get_events(tps);

    CPPUNIT_ASSERT_EQUAL((size_t)120, tps.size());
}

void StopwatchTests::stopwatch_block_test()
{
    Stopwatch sw;

    thread th1([&sw]
    {
        StopwatchScope sc(sw, "one");
        this_thread::sleep_for(60ms);
    });

    thread th2([&sw]
    {
        StopwatchScope sc(sw, "two");
        this_thread::sleep_for(30ms);
    });

    thread th3([&sw]
    {
        StopwatchScope sc(sw, "one");
        this_thread::sleep_for(40ms);
    });

    th1.join();
    th2.join();
    th3.join();

    vector<Stopwatch::TimespanSummary> tsp;
    sw.get_timespans(tsp);

    CPPUNIT_ASSERT_EQUAL((size_t)2, tsp.size());

    auto timesp = std::find_if(tsp.begin(), tsp.end(), [](Stopwatch::TimespanSummary& tss) { return tss.event_name == "one"; });
    CPPUNIT_ASSERT(timesp != tsp.end());
    CPPUNIT_ASSERT_EQUAL(2, timesp->event_count);

    string msg;
    {
        stringstream ss;
        ss << "Avg should be >= 50.0, it is: " << timesp->avg;
        msg = ss.str();
    }
    CPPUNIT_ASSERT_MESSAGE(msg.c_str(), timesp->avg >= 50.0);

    {
        stringstream ss;
        ss << "Min should be >= 40 && < 60, it is: " << timesp->min;
        msg = ss.str();
    }
    CPPUNIT_ASSERT_MESSAGE(msg.c_str(), timesp->min >= 40 && timesp->min < 60);

    {
        stringstream ss;
        ss << "Max should be >= 60 && < 80, it is: " << timesp->max;
        msg = ss.str();
    }
    CPPUNIT_ASSERT_MESSAGE(msg.c_str(), timesp->max >= 60 && timesp->max < 80);

    timesp = std::find_if(tsp.begin(), tsp.end(), [](Stopwatch::TimespanSummary& tss) { return tss.event_name == "two"; });
    CPPUNIT_ASSERT(timesp != tsp.end());
    CPPUNIT_ASSERT_EQUAL(1, timesp->event_count);
}

void StopwatchTests::stopwatch_multithreading_test()
{
    Stopwatch sw;

    vector<thread> threads(30);
    for (int i = 0; i < threads.size(); i++)
    {
        threads[i] = thread([&](int idx)
        {
            string thr_name;
            get_thread_name(idx, thr_name);

            {
                StopwatchScope sw1(sw, thr_name);
                this_thread::sleep_for(15ms);
            }

            {
                StopwatchScope sw2(sw, thr_name);
                this_thread::sleep_for(15ms);
            }

            {
                StopwatchScope sw3(sw, thr_name);
                this_thread::sleep_for(15ms);
            }
        }, i);
    }

    for (auto& thr : threads)
    {
        thr.join();
    }

    vector<Stopwatch::TimespanSummary> tsp;
    sw.get_timespans(tsp);

    CPPUNIT_ASSERT_EQUAL((size_t)30, tsp.size());
    for (auto& tss : tsp)
    {
        CPPUNIT_ASSERT_EQUAL(3, tss.event_count);
    }
}
