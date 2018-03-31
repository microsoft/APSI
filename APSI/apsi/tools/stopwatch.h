#pragma once

#include <list>
#include <utility>
#include <string>
#include <chrono>
#include <ostream>

namespace apsi
{
	namespace tools
	{
		class Stopwatch
		{
		public:
			typedef std::chrono::high_resolution_clock::time_point time_unit;

			const static time_unit start_time;
			std::list< std::pair<time_unit, std::string> > time_points;
			const time_unit &set_time_point(const std::string &message);

			friend std::ostream &operator <<(std::ostream &out, const Stopwatch &stopwatch);
		};
	}
}