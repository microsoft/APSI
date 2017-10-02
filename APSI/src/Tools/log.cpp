#include "Tools/log.h"
#include <iostream>
//#include <Windows.h>

using namespace std;

namespace apsi
{
    namespace tools
    {
        void Log::setThreadName(const std::string name)
        {
            setThreadName(name.c_str());
        }
        void Log::setThreadName(const char* name)
        {
#ifdef _DEBUG
#ifdef _MSC_VER
            const DWORD MS_VC_EXCEPTION = 0x406D1388;

#pragma pack(push,8)
            typedef struct tagTHREADNAME_INFO
            {
                DWORD dwType; // Must be 0x1000.
                LPCSTR szName; // Pointer to name (in user addr space).
                DWORD dwThreadID; // Thread ID (-1=caller thread).
                DWORD dwFlags; // Reserved for future use, must be zero.
            } THREADNAME_INFO;
#pragma pack(pop)

            THREADNAME_INFO info;
            info.dwType = 0x1000;
            info.szName = name;
            info.dwThreadID = -1;
            info.dwFlags = 0;

            __try
            {
                RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
#endif
#endif
        }

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
