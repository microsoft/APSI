#include "log.h"
#include <iostream>

using namespace std;

namespace apsi
{
	namespace tools
	{
		LogStream Log::out(std::cout);

		void Log::set_sink(std::ostream &stream)
		{
			Log::out.stream_ = &stream;
		}

		LogStream &LogStream::operator <<(const Log::Modifier in)
		{
			switch (in)
			{
			case Log::Modifier::endl:
				*stream_ << endl;
				break;
			case Log::Modifier::flush:
				stream_->flush();
				break;
			case Log::Modifier::lock:
				mutex_.lock();
				break;
			case Log::Modifier::unlock:
				mutex_.unlock();
				break;
			}
			return *this;
		}
	}
}