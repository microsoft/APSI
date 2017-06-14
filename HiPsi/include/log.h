#pragma once

#include <string>
#include <ostream>
#include <mutex>

namespace apsi
{
	namespace tools
	{
		class LogStream;

		class Log
		{
		public:
			enum Modifier
			{
				endl,
				flush,
				lock,
				unlock
			};

			static void set_sink(std::ostream &stream);

			static LogStream out;

		private:

			friend class LogStream;
		};

		class LogStream
		{
		public:

		private:
			LogStream(std::ostream& stream) : stream_(&stream)
			{
			}

			~LogStream()
			{
				if (stream_)
				{
					stream_->flush();
				}
			}

			template<typename T>
			inline LogStream &operator <<(const T &in)
			{
				*stream_ << in;
				return *this;
			}

			LogStream &operator <<(const Log::Modifier in);

			std::ostream *stream_;
			std::mutex mutex_;

			friend class Log;
		};
	}
}