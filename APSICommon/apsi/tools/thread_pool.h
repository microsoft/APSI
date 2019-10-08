// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <vector>
#include <queue>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <future>
#include <functional>
#include <stdexcept>

namespace apsi
{
    namespace tools
    {
        /**
        Implementation of a thread pool that accepts lambdas and tasks
        */
        class ThreadPool
        {
        public:
            /**
            Constructor.
            @param[in] threads The number of threads used by the thread pool.
            */
            ThreadPool(size_t threads)
                : stop_(false)
            {
                for (size_t i = 0; i < threads; ++i)
                {
                    workers_.emplace_back([this]
                    {
                        for (;;)
                        {
                            std::function<void()> task;

                            {
                                std::unique_lock<std::mutex> lock(this->queue_mutex_);
                                this->condition_.wait(lock,
                                    [this]
                                    {
                                        return this->stop_ || !this->tasks_.empty();
                                    });

                                if (this->stop_ && this->tasks_.empty())
                                    return;

                                task = std::move(this->tasks_.front());
                                this->tasks_.pop();
                            }

                            task();
                        }
                    });
                }
            }

            /**
            Add a new work item to the pool
            */
            template<class F, class... Args>
            auto enqueue(F&& f, Args&&... args)
                ->std::future<typename std::result_of<F(Args...)>::type>
            {
                using return_type = typename std::result_of<F(Args...)>::type;

                auto task = std::make_shared< std::packaged_task<return_type()> >(
                    std::bind(std::forward<F>(f), std::forward<Args>(args)...)
                    );

                std::future<return_type> res = task->get_future();
                {
                    std::unique_lock<std::mutex> lock(queue_mutex_);

                    // don't allow enqueueing after stopping the pool
                    if (stop_)
                        throw std::runtime_error("enqueue on stopped ThreadPool");

                    tasks_.emplace([task]() { (*task)(); });
                }
                condition_.notify_one();

                return res;
            }

            /**
            The destructor joins all threads.
            */
            ~ThreadPool()
            {
                {
                    std::unique_lock<std::mutex> lock(queue_mutex_);
                    stop_ = true;
                }

                condition_.notify_all();

                for (std::thread &worker : workers_)
                {
                    worker.join();
                }
            }

        private:
            // need to keep track of threads so we can join them
            std::vector< std::thread > workers_;

            // the task queue
            std::queue< std::function<void()> > tasks_;

            // synchronization
            std::mutex queue_mutex_;
            std::condition_variable condition_;
            bool stop_;
        };
    }
}
