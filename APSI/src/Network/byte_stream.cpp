#include "Network/byte_stream.h"
#include <string.h>
#include <sstream>

namespace apsi 
{
    namespace network
    {
        ByteStream::ByteStream(uint64_t maxlen)
        {
            mCapacity = maxlen; mPutHead = 0; mGetHead = 0;
            mData = mCapacity ? new uint8_t[mCapacity]() : nullptr;
        }


        ByteStream::ByteStream(const ByteStream& os)
        {
            mCapacity = os.mCapacity;
            mPutHead = os.mPutHead;
            mData = new uint8_t[mCapacity]();
            memcpy(mData, os.mData, mPutHead * sizeof(uint8_t));
            mGetHead = os.mGetHead;
        }

        ByteStream::ByteStream(const uint8_t * data, uint64_t length)
            :mPutHead(0),
            mCapacity(0),
            mGetHead(0),
            mData(nullptr)
        {
            append(data, length);
        }

        void ByteStream::reserve(uint64_t l)
        {
            if (l > mCapacity) {
                uint8_t* nd = new uint8_t[l]();
                memcpy(nd, mData, mPutHead * sizeof(uint8_t));

                if (mData)
                    delete[] mData;

                mData = nd;
                mCapacity = l;
            }
        }

        void ByteStream::resize(uint64_t length)
        {
            reserve(length);
            setp(length);
        }

        void ByteStream::shrinkToFit()
        {
            if (mPutHead != mCapacity) {
                uint8_t* nd = new uint8_t[mPutHead];
                memcpy(nd, mData, mPutHead * sizeof(uint8_t));

                if (mData)
                    delete[] mData;

                mData = nd;
                mCapacity = mPutHead;
            }
        }

        void ByteStream::setg(uint64_t loc) {
            if (loc > mPutHead) throw std::runtime_error("");
            mGetHead = loc;
        }

        void ByteStream::setp(uint64_t loc)
        {
            if (loc > mCapacity) throw std::runtime_error("");
            mPutHead = loc;
            mGetHead = std::min(mGetHead, mPutHead);
        }

        uint64_t ByteStream::tellg()const
        {
            return mGetHead;
        }

        uint64_t ByteStream::tellp()const
        {
            return mPutHead;
        }

        ByteStream& ByteStream::operator=(const ByteStream& os)
        {
            if (os.mPutHead >= mCapacity)
            {
                delete[] mData;
                mCapacity = os.mCapacity;
                mData = new uint8_t[mCapacity]();
            }
            mPutHead = os.mPutHead;
            memcpy(mData, os.mData, mPutHead * sizeof(uint8_t));
            mGetHead = os.mGetHead;

            return *this;
        }

        bool ByteStream::operator==(const ByteStream& a) const
        {
            if (mPutHead != a.mPutHead) { return false; }
            for (uint64_t i = 0; i < mPutHead; i++)
            {
                if (mData[i] != a.mData[i]) { return false; }
            }
            return true;
        }


        bool ByteStream::operator!=(const ByteStream& a) const
        {
            return !(*this == a);
        }

        void ByteStream::append(const uint8_t* x, const uint64_t l)
        {
            if (tellp() + l > mCapacity)
            {
                reserve(std::max(mCapacity * 2, tellp() + l));
            }

            memcpy(mData + mPutHead, x, l * sizeof(uint8_t));
            mPutHead += l;
        }

        void ByteStream::append(const block& b)
        {
            append((const uint8_t*)(&b), sizeof(block));
        }

        void ByteStream::consume(uint8_t* x, const uint64_t l)
        {
            if (mGetHead + l > mPutHead) throw std::runtime_error("");
            memcpy(x, mData + mGetHead, l * sizeof(uint8_t));
            mGetHead += l;
        }


        std::ostream& operator<<(std::ostream& s, const ByteStream& o)
        {
            std::stringstream ss;
            ss << std::hex;
            for (uint64_t i = 0; i < o.mPutHead; i++)
            {
                uint32_t t0 = o.mData[i] & 15;
                uint32_t t1 = o.mData[i] >> 4;
                ss << t1 << t0;
            }
            s << ss.str();
            return s;
        }


        void ByteStream::ChannelBufferResize(uint64_t length)
        {
            if (length > mCapacity)
            {
                delete[] mData;
                mData = new uint8_t[mCapacity = length]();
            }
            mPutHead = length;
            mGetHead = 0;
        }
    }
}
