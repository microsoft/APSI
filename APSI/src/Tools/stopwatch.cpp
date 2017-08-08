#include "Tools/stopwatch.h"
#include <cstdint>

using namespace std;

namespace apsi
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
					<< " | Since last: "
					<< chrono::duration_cast<chrono::milliseconds>(tp.first - prev_time).count()
					<< " milliseconds"
					<< " | Total: "
					<< chrono::duration_cast<chrono::milliseconds>(tp.first - stopwatch.start_time).count()
					<< " milliseconds"
					<< endl;
				prev_time = tp.first;
			}

			return out;
		}
	}
}