#include "stopwatch.h"
#include <cstdint>

using namespace std;

namespace hipsi
{
	namespace tools
	{
		const Stopwatch::time_unit Stopwatch::start_time(Stopwatch::time_unit::clock::now());

		const Stopwatch::time_unit &Stopwatch::set_time_point(const std::string &message)
		{
			time_points.push_back(make_pair(time_unit::clock::now(), message));
			return time_points.back().first;
		}

		ostream &operator <<(ostream &out, const Stopwatch &stopwatch)
		{
			auto prev_time = stopwatch.start_time;
			for (auto tp : stopwatch.time_points)
			{
				out << tp.second
					<< " | Total: "
					<< chrono::duration_cast<chrono::microseconds>(tp.first - stopwatch.start_time).count()
					<< " microseconds"
					<< " | Since last: "
					<< chrono::duration_cast<chrono::microseconds>(tp.first - prev_time).count()
					<< " microseconds"
					<< endl;
				prev_time = tp.first;
			}

			return out;
		}
	}
}