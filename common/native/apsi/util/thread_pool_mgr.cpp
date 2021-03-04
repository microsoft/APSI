// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <memory>
#include <mutex>

// APSI
#include "thread_pool_mgr.h"

using namespace std;
using namespace apsi;
using namespace apsi::util;

// Static reference count that will manage the lifetime of the single ThreadPool
//object that all users of this class will share.
size_t ThreadPoolMgr::ref_count_ = 0;

namespace {
    mutex tp_mutex_;
    size_t thread_count_ = thread::hardware_concurrency();
    unique_ptr<ThreadPool> thread_pool_;
}

ThreadPoolMgr::ThreadPoolMgr()
{
    unique_lock<mutex> lock(tp_mutex_);

    if (ref_count_ == 0) {
        thread_pool_ = make_unique<ThreadPool>(thread_count_);
    }

    ref_count_++;
}

ThreadPoolMgr::~ThreadPoolMgr()
{
    unique_lock<mutex> lock(tp_mutex_);

    ref_count_--;
    if (ref_count_ == 0) {
        thread_pool_ = nullptr;
    }
}

ThreadPool& ThreadPoolMgr::thread_pool() const
{
    if (!thread_pool_)
        throw runtime_error("Thread pool is not available");

    return *thread_pool_;
}

void ThreadPoolMgr::set_thread_count(size_t threads)
{
    unique_lock<mutex> lock(tp_mutex_);

    thread_count_ = threads != 0 ? threads : thread::hardware_concurrency();

    if (thread_pool_) {
        thread_pool_->set_pool_size(thread_count_);
    }
}
