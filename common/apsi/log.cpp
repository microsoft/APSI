// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <time.h> // NOLINT(modernize-deprecated-headers,hicpp-deprecated-headers): localtime_r
#include <utility>

// APSI
#include "apsi/log.h"

using namespace std;

namespace apsi {
    namespace {
        // Global emission threshold. A trivially destructible atomic, so it is safe to leave at
        // namespace scope even if it is read during static destruction at process exit.
        std::atomic<LogLevel> log_level_{ LogLevel::suppress };

        // Immortal singleton holding the global logger and the mutex guarding it. It is
        // heap-allocated exactly once and never destroyed, so the logger stays valid even when
        // APSI is called from a host's static/global destructor during process teardown. This
        // avoids the static destruction-order fiasco: a namespace-scope mutex / shared_ptr
        // destroyed before a host static that logs on its way out would otherwise be locked /
        // read after destruction (undefined behavior). Because ~Logger therefore never runs for
        // the global logger, the bundled sinks flush on every write (see build_sinks) instead of
        // relying on a close() at teardown to drain a buffered file stream; std::cout / std::cerr
        // are additionally flushed by the standard library at exit.
        struct LoggerState {
            std::mutex mtx;
            std::shared_ptr<Logger> logger;
        };

        LoggerState &logger_state()
        {
            // NOLINTNEXTLINE(cppcoreguidelines-owning-memory): intentional immortal singleton.
            static LoggerState &state = *new LoggerState();
            return state;
        }

        // Returns the global logger, creating the default one on first use. The caller must hold
        // logger_state().mtx.
        std::shared_ptr<Logger> get_or_init_default_unlocked()
        {
            auto &state = logger_state();
            if (!state.logger) {
                state.logger = NewDefaultLogger();
            }
            return state.logger;
        }

        const char *level_label(LogLevel level)
        {
            switch (level) {
            case LogLevel::trace:
                return "TRACE";
            case LogLevel::debug:
                return "DEBUG";
            case LogLevel::info:
                return "INFO ";
            case LogLevel::warning:
                return "WARN ";
            case LogLevel::error:
                return "ERROR";
            case LogLevel::suppress:
                return "SUPP ";
            }
            return "?????";
        }

        string format_log_line(LogLevel level, const string &msg)
        {
            auto now = std::chrono::system_clock::now();
            auto t = std::chrono::system_clock::to_time_t(now);
            auto ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) %
                1000;
            std::tm tm{};
#ifdef _WIN32
            localtime_s(&tm, &t);
#else
            localtime_r(&t, &tm);
#endif
            std::array<char, 32> timebuf{};
            std::snprintf(
                timebuf.data(),
                timebuf.size(),
                "%02d:%02d:%02d:%03d",
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec,
                static_cast<int>(ms.count()));

            string out;
            out.reserve(6 + timebuf.size() + msg.size() + 4);
            out.append(level_label(level));
            out.append(" ");
            out.append(timebuf.data());
            out.append(": ");
            out.append(msg);
            out.append("\n");
            return out;
        }
    } // namespace

    void SetLogLevel(LogLevel level)
    {
        switch (level) {
        case LogLevel::trace:
        case LogLevel::debug:
        case LogLevel::info:
        case LogLevel::warning:
        case LogLevel::error:
        case LogLevel::suppress:
            break;
        default:
            throw invalid_argument("unknown log level");
        }
        log_level_.store(level, std::memory_order_relaxed);
    }

    void SetLogLevel(const string &level)
    {
        if (level == "trace") {
            SetLogLevel(LogLevel::trace);
        } else if (level == "debug") {
            SetLogLevel(LogLevel::debug);
        } else if (level == "info") {
            SetLogLevel(LogLevel::info);
        } else if (level == "warning") {
            SetLogLevel(LogLevel::warning);
        } else if (level == "error") {
            SetLogLevel(LogLevel::error);
        } else if (level == "suppress") {
            SetLogLevel(LogLevel::suppress);
        } else {
            throw invalid_argument("unknown log level");
        }
    }

    LogLevel GetLogLevel()
    {
        return log_level_.load(std::memory_order_relaxed);
    }

    void SetLogger(shared_ptr<Logger> logger)
    {
        shared_ptr<Logger> old_logger;
        {
            auto &state = logger_state();
            lock_guard<mutex> lock(state.mtx);
            old_logger = std::move(state.logger);
            state.logger = std::move(logger);
        }
        if (old_logger) {
            old_logger->close();
        }
    }

    shared_ptr<Logger> GetLogger()
    {
        auto &state = logger_state();
        lock_guard<mutex> lock(state.mtx);
        return get_or_init_default_unlocked();
    }

    void ResetDefaultLogger()
    {
        SetLogger(NewDefaultLogger());
    }

    void CloseLogger()
    {
        shared_ptr<Logger> old_logger;
        {
            auto &state = logger_state();
            lock_guard<mutex> lock(state.mtx);
            old_logger = std::move(state.logger);
        }
        if (old_logger) {
            old_logger->close();
        }
    }

    namespace internal {
        void DoLog(LogLevel level, const string &msg)
        {
            shared_ptr<Logger> logger;
            {
                auto &state = logger_state();
                lock_guard<mutex> lock(state.mtx);
                logger = get_or_init_default_unlocked();
            }
            if (logger) {
                logger->log(level, msg);
            }
        }
    } // namespace internal

    shared_ptr<Logger> Logger::Create(
        array<log_handler_t, level_count> log_handlers,
        array<flush_handler_t, level_count> flush_handlers,
        array<close_handler_t, level_count> close_handlers)
    {
        return shared_ptr<Logger>(new Logger(
            std::move(log_handlers), std::move(flush_handlers), std::move(close_handlers)));
    }

    Logger::Logger(
        array<log_handler_t, level_count> log_handlers,
        array<flush_handler_t, level_count> flush_handlers,
        array<close_handler_t, level_count> close_handlers)
        : log_handlers_(std::move(log_handlers)), flush_handlers_(std::move(flush_handlers)),
          close_handlers_(std::move(close_handlers))
    {}

    Logger::~Logger()
    {
        try {
            close_internal();
        } catch (...) { // NOLINT(bugprone-empty-catch) // Intentional
            // We must not throw in a destructor.
        }
    }

    void Logger::log(LogLevel level, const string &msg)
    {
        auto idx = static_cast<size_t>(level);
        if (idx >= level_count) {
            return;
        }
        // Invoke the handler while holding the mutex. Serializing all emissions on a given
        // logger means the bundled console/file sinks (and any user handler that is not itself
        // thread-safe) can be called from multiple threads without a data race, and a concurrent
        // close() cannot race the handler invocation. The cost is that a slow handler blocks
        // other emitters, which is acceptable. Handlers must not re-enter the logger
        // (e.g. by calling APSI_LOG_*): mtx_ is not recursive and would deadlock.
        std::lock_guard<std::mutex> lk(mtx_);
        if (closed_) {
            return;
        }
        if (log_handlers_[idx]) {
            log_handlers_[idx](msg);
        }
    }

    void Logger::flush()
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (closed_) {
            return;
        }
        for (auto &f : flush_handlers_) {
            if (f) {
                f();
            }
        }
    }

    void Logger::close()
    {
        close_internal();
    }

    void Logger::close_internal()
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (closed_) {
            return;
        }
        for (auto &f : flush_handlers_) {
            if (f) {
                f();
            }
        }
        for (auto &c : close_handlers_) {
            if (c) {
                c();
            }
        }
        log_handlers_.fill(nullptr);
        flush_handlers_.fill(nullptr);
        close_handlers_.fill(nullptr);
        closed_ = true;
    }

    namespace {
        // Builds the four per-level handler arrays for a logger that fans out to a console
        // stream (stdout for debug/info, stderr for warning/error) and/or a shared file
        // stream. Either (or both) may be null/empty.
        struct DefaultLoggerSinks {
            array<Logger::log_handler_t, Logger::level_count> log_handlers{};
            array<Logger::flush_handler_t, Logger::level_count> flush_handlers{};
            array<Logger::close_handler_t, Logger::level_count> close_handlers{};
        };

        DefaultLoggerSinks build_sinks(
            const shared_ptr<ofstream> &file_stream, bool console_enabled)
        {
            DefaultLoggerSinks sinks;

            auto build_handler = [console_enabled, file_stream](LogLevel level, ostream *console) {
                return [level, console, file_stream, console_enabled](const string &msg) {
                    string line = format_log_line(level, msg);
                    // Flush on every write. The global logger is an immortal singleton whose
                    // ~Logger never runs, so there is no close()/flush at process exit to drain a
                    // buffered file stream; flushing per line keeps both the file and console
                    // current with no data loss. std::cerr is already unit-buffered, and the cost
                    // is negligible at APSI's logging rates.
                    if (console_enabled && console) {
                        *console << line;
                        console->flush();
                    }
                    if (file_stream && file_stream->is_open()) {
                        *file_stream << line;
                        file_stream->flush();
                    }
                };
            };

            sinks.log_handlers[static_cast<size_t>(LogLevel::trace)] =
                build_handler(LogLevel::trace, &std::cout);
            sinks.log_handlers[static_cast<size_t>(LogLevel::debug)] =
                build_handler(LogLevel::debug, &std::cout);
            sinks.log_handlers[static_cast<size_t>(LogLevel::info)] =
                build_handler(LogLevel::info, &std::cout);
            sinks.log_handlers[static_cast<size_t>(LogLevel::warning)] =
                build_handler(LogLevel::warning, &std::cerr);
            sinks.log_handlers[static_cast<size_t>(LogLevel::error)] =
                build_handler(LogLevel::error, &std::cerr);

            auto flush_fn = [file_stream]() {
                std::cout.flush();
                std::cerr.flush();
                if (file_stream && file_stream->is_open()) {
                    file_stream->flush();
                }
            };
            sinks.flush_handlers[static_cast<size_t>(LogLevel::trace)] = flush_fn;
            sinks.flush_handlers[static_cast<size_t>(LogLevel::debug)] = flush_fn;
            sinks.flush_handlers[static_cast<size_t>(LogLevel::info)] = flush_fn;
            sinks.flush_handlers[static_cast<size_t>(LogLevel::warning)] = flush_fn;
            sinks.flush_handlers[static_cast<size_t>(LogLevel::error)] = flush_fn;

            // A single close action on the file stream; std::cout / std::cerr are not closed.
            sinks.close_handlers[static_cast<size_t>(LogLevel::error)] = [file_stream]() {
                if (file_stream && file_stream->is_open()) {
                    file_stream->close();
                }
            };

            return sinks;
        }
    } // namespace

    shared_ptr<Logger> NewDefaultLogger()
    {
        auto sinks = build_sinks(/*file_stream=*/nullptr, /*console_enabled=*/true);
        return Logger::Create(
            std::move(sinks.log_handlers),
            std::move(sinks.flush_handlers),
            std::move(sinks.close_handlers));
    }

    shared_ptr<Logger> NewFileLogger(const string &log_file, bool also_console)
    {
        if (log_file.empty()) {
            throw invalid_argument("log_file path is empty");
        }
        auto file_stream = make_shared<ofstream>(log_file, std::ios::app);
        if (!file_stream->is_open()) {
            throw runtime_error("failed to open log file: " + log_file);
        }
        auto sinks = build_sinks(file_stream, also_console);
        return Logger::Create(
            std::move(sinks.log_handlers),
            std::move(sinks.flush_handlers),
            std::move(sinks.close_handlers));
    }
} // namespace apsi
