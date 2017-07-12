#pragma once

#include <vector>
#include <array>

namespace apsi 
{
    namespace network
    {
        template<class T>
        class ArrayView
        {

            T* mData;
            std::uint64_t mSize;
            bool mOwner;
        public:
            typedef T* Iterator;


            ArrayView()
                :mData(nullptr),
                mSize(0),
                mOwner(false)
            {
            }

            ArrayView(const ArrayView& av) :
                mData(av.mData),
                mSize(av.mSize),
                mOwner(false)
            { }

            ArrayView(ArrayView&& av) :
                mData(av.mData),
                mSize(av.mSize),
                mOwner(true)
            {
                av.mData = nullptr;
                av.mSize = 0;
                av.mOwner = false;
            }

            ArrayView(std::uint64_t size) :
                mData(new T[size]),
                mSize(size),
                mOwner(true)
            { }

            ArrayView(T* data, std::uint64_t size, bool owner = false) :
                mData(data),
                mSize(size),
                mOwner(owner)
            {}


            ArrayView(T* begin, T* end, bool owner) :
                mData(begin),
                mSize(end - begin),
                mOwner(owner)
            {}

            ArrayView(std::vector<T>& container)
                : mData(container.data()),
                mSize(container.size()),
                mOwner(false)
            {
            }

            template<std::uint64_t n>
            ArrayView(std::array<T, n>& container)
                : mData(container.data()),
                mSize(container.size()),
                mOwner(false)
            {
            }

            ~ArrayView()
            {
                if (mOwner) delete[] mData;
            }


            const ArrayView<T>& operator=(const ArrayView<T>& copy)
            {
                mData = copy.mData;
                mSize = copy.mSize;
                mOwner = false;

                return *this;
            }


            std::uint64_t size() const { return mSize; }

            T* data() const { return mData; };

            Iterator begin() const { return mData; };
            Iterator end() const { return mData + mSize; }

            //T& operator[](int idx) { if (idx >= mSize) throw std::runtime_error(""); return mData[idx]; }
            T& operator[](std::uint64_t idx) const
            {
#ifndef NDEBUG
                if (idx >= mSize)
                {
                    //Log::out << "ArrayView index out of range " << idx << ", size = " << mSize << Log::endl;
                    throw std::runtime_error("");
                }
#endif

                return mData[idx];
            }
        };
    }
}