#pragma once

#include <queue>
#include <mutex>

namespace apsi
{
    namespace network
    {
        template <typename T>
        class ConcurrentQueue
        {
        public:

            /// <summary>Remove one Element from the front of the queue and return it by value.</summary>
            T pop()
            {
                std::unique_lock<std::mutex> mlock(mMutex);
                while (mQueue.empty())
                {
                    mCondVar.wait(mlock);
                }
                auto item = mQueue.front();
                mQueue.pop();
                return item;
            }

            /// <summary>Remove one Element from the front of the queue and assign it to item.</summary>
            void pop(T& item)
            {
                std::unique_lock<std::mutex> mlock(mMutex);
                while (mQueue.empty())
                {
                    mCondVar.wait(mlock);
                }
                item = mQueue.front();
                mQueue.pop();
            }

            /// <summary>Add one referenced Element to the back of the queue.</summary>
            void push(const T& item)
            {
                std::unique_lock<std::mutex> mlock(mMutex);
                mQueue.push(item);
                mlock.unlock();
                mCondVar.notify_one();
            }

            /// <summary>Add one moved Element to the back of the queue.</summary>
            void push(T&& item)
            {
                std::unique_lock<std::mutex> mlock(mMutex);
                mQueue.push(std::move(item));
                mlock.unlock();
                mCondVar.notify_one();
            }

        private:
            std::queue<T> mQueue;
            std::mutex mMutex;
            std::condition_variable mCondVar;
        };
    }
}