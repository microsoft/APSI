#pragma once
 
#include "channel.h" 
#include "array_view.h"
#include "apsidefines.h"

namespace apsi 
{ 
    namespace network
    {
        template <class T>
        class BSIterator
        {
            T* mCur, *mBegin, *mEnd;


        public:
            BSIterator(T* cur, T* begin, T*end)
                :
                mCur(cur),
                mBegin(begin),
                mEnd(end)
            {}

            T& operator*()
            {
                if (mCur >= mEnd || mCur < mBegin)
                    throw std::runtime_error("");

                return *mCur;
            }

            BSIterator& operator++()
            {
                ++mCur;
                if (mCur == mEnd)
                    throw std::runtime_error("");
                return *this;
            }

            BSIterator operator++(int)
            {
                BSIterator ret(*this);
                ++mCur;
                if (mCur > mEnd)
                    throw std::runtime_error("");
                return ret;
            }

            BSIterator& operator+(int i)
            {
                mCur += i;
                if (mCur > mEnd)
                    throw std::runtime_error("");
                return *this;
            }

            BSIterator& operator--()
            {
                --mCur;
                if (mCur < mBegin)
                    throw std::runtime_error("");

                return *this;
            }
            BSIterator operator--(int)
            {
                BSIterator ret(*this);
                --mCur;
                if (mCur < mBegin)
                    throw std::runtime_error("");

                return ret;
            }

            BSIterator& operator-(int i)
            {
                mCur -= i;
                if (mCur < mBegin)
                    throw std::runtime_error("");
                return *this;
            }


            T* operator->()
            {
                return raw();
            }


            T* raw()
            {
                if (mCur >= mEnd || mCur < mBegin)
                    throw std::runtime_error("");
                return mCur;
            }

            bool operator==(const BSIterator& rhs) const
            {
                return mCur == rhs.mCur;
            }


            bool operator!=(const BSIterator& rhs) const
            {
                return mCur != rhs.mCur;
            }

            bool operator>(const BSIterator& rhs) const
            {
                return mCur > rhs.mCur;
            }
            bool operator>=(const BSIterator& rhs) const
            {
                return mCur >= rhs.mCur;
            }
            bool operator<(const BSIterator& rhs) const
            {
                return mCur < rhs.mCur;
            }
            bool operator<=(const BSIterator& rhs) const
            {
                return mCur <= rhs.mCur;
            }

        };

        class ByteStream : public ChannelBuffer
        {
            friend std::ostream& operator<<(std::ostream& s, const ByteStream& o);
            friend class PRNG;

        public:
            ByteStream(std::uint64_t maxlen = 0);
            ByteStream(const ByteStream& os);
            ByteStream(const std::uint8_t* data, std::uint64_t length);

            ~ByteStream() { delete[] mData; }

            /// <summary>The size of the unconsumed steam/data.</summary>
            std::uint64_t size() const { return tellp() - tellg(); }

            /// <summary>The capacity of the container.</summary>
            std::uint64_t capacity() const { return mCapacity; }

            /// <summary>The location of the data.</summary>
            std::uint8_t* data() const { return mData; }

            /// <summary>The start location of that data unconsumed data.</summary>
            std::uint8_t* begin() const { return mData + tellg(); }

            /// <summary>The end location of that data.</summary>
            std::uint8_t* end() const { return mData + tellp(); }

            /// <summary>Returns the offset of where data will be PUT in the stream.</summary>
            std::uint64_t tellp() const;

            /// <summary>Sets the offset of where data will be PUT in the stream.</summary>
            void setp(std::uint64_t loc);

            /// <summary>Returns the offset of where data will be GET in the stream.</summary>
            std::uint64_t tellg()const;

            /// <summary>Sets the offset of where data will be GET in the stream.</summary>
            void setg(std::uint64_t loc);

            /// <summary>Grows the size of the underlying container to fit length bytes</summary>
            void reserve(std::uint64_t length);

            /// <summary>Grows the size of the container to length bytes</summary>
            void resize(std::uint64_t length);

            void shrinkToFit();

            /// <summary>Copies length bytes starting at data to the end of the container tellp().</summary>
            void append(const std::uint8_t* data, const std::uint64_t length);

            /// <summary>Copies the next length bytes starting at data() + tellg()  to dest</summary>
            void consume(std::uint8_t* dest, const std::uint64_t length);

            void append(const block& b);

            ByteStream& operator=(const ByteStream& os);
            bool operator==(const ByteStream& rhs) const;
            bool operator!=(const ByteStream& rhs) const;

            template<class T>
            BSIterator<T>	begin();

            template<class T>
            BSIterator<T>	end();

            template<class T>
            ArrayView<T> getArrayView() const;

        protected:
            std::uint8_t* ChannelBufferData() const override { return begin(); }
            std::uint64_t ChannelBufferSize() const override { return size(); };
            void ChannelBufferResize(std::uint64_t length) override;

        private:

            std::uint64_t mPutHead, mCapacity, mGetHead;
            std::uint8_t *mData;
        };


        template<class T>
        inline BSIterator<T> ByteStream::begin()
        {
            return BSIterator<T>((T*)mData, (T*)mData, ((T*)mData) + ((mPutHead + sizeof(T) - 1) / sizeof(T)));
        }

        template<class T>
        inline BSIterator<T> ByteStream::end()
        {
            auto end = ((T*)mData) + ((mPutHead + sizeof(T) - 1) / sizeof(T));
            return BSIterator<T>(end, (T*)mData, end);
        }

        template<class T>
        inline ArrayView<T> ByteStream::getArrayView() const
        {
            return ArrayView<T>((T*)mData, (T*)mData + (mPutHead / sizeof(T)), false);
        }
    }
}

