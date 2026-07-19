// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>

namespace apsi {
    /**
    Supported log levels, ordered from most verbose to least. `trace`/`debug`/`info`/`warning`/
    `error` are the actionable emission levels; `suppress` is a threshold-only sentinel used by
    SetLogLevel to drop everything. This mirrors the LogLevel enums in the sibling cppvrf and
    mpss libraries.
    */
    enum class LogLevel : std::uint8_t { trace, debug, info, warning, error, suppress };

    class Logger;

    /**
    Sets the global emission threshold. Messages below this level are dropped before the
    formatting cost is paid. Throws std::invalid_argument if `level` is outside the enum range.
    */
    void SetLogLevel(LogLevel level);

    /**
    Parses a level name ("trace", "debug", "info", "warning", "error", "suppress") and sets the
    global threshold. Throws std::invalid_argument on unknown input.
    */
    void SetLogLevel(const std::string &level);

    /**
    Returns the current global emission threshold.
    */
    LogLevel GetLogLevel();

    /**
    Replaces the global logger. The previous logger (if any) is closed before being released.
    Pass nullptr to clear; the next GetLogger() call will lazily install a fresh
    NewDefaultLogger().
    */
    void SetLogger(std::shared_ptr<Logger> logger);

    /**
    Returns the current global logger, lazily installing the default stdout/stderr logger
    if none has been set.
    */
    std::shared_ptr<Logger> GetLogger();

    /**
    Replaces the global logger with a fresh NewDefaultLogger(). Convenience for
    SetLogger(NewDefaultLogger()).
    */
    void ResetDefaultLogger();

    /**
    Closes and clears the global logger. The next emission lazily installs a fresh default.
    The level threshold is unaffected.
    */
    void CloseLogger();

    /**
    Thread-safe logger that dispatches messages to per-level handlers. Construct via
    Logger::Create with arrays of std::function callbacks indexed by LogLevel. The handler
    at index static_cast<size_t>(level) is invoked for each message at that level; pass an
    empty std::function for any level that should be suppressed.

    The handler arrays have apsi::Logger::level_count slots, indexed by the integer value of
    LogLevel. Slots for trace, debug, info, warning, and error are the actionable handlers;
    LogLevel::suppress is a threshold-only sentinel with no slot (its integer value equals
    level_count, so no message is ever emitted at that level).

    Logger::log invokes the handler while holding an internal mutex, so all emissions on a
    given logger are serialized. Handlers therefore need not be thread-safe, and a concurrent
    close() cannot race a handler invocation. The handler must not re-enter the logger (for
    example by calling APSI_LOG_*), as the mutex is not recursive and would deadlock.
    */
    class Logger {
    public:
        using log_handler_t = std::function<void(const std::string &)>;
        using flush_handler_t = std::function<void()>;
        using close_handler_t = std::function<void()>;

        /**
        Number of handler slots, equal to the integer value of LogLevel::suppress. Slots are
        indexed by static_cast<size_t>(LogLevel::*).
        */
        static constexpr std::size_t level_count = static_cast<std::size_t>(LogLevel::suppress);

        /**
        Creates a logger with the given callback handlers. Pass an empty std::function for
        any level or operation that should be suppressed. To create a no-op logger, pass
        three default-constructed (all-empty) arrays.
        */
        static std::shared_ptr<Logger> Create(
            std::array<log_handler_t, level_count> log_handlers,
            std::array<flush_handler_t, level_count> flush_handlers,
            std::array<close_handler_t, level_count> close_handlers);

        ~Logger();

        Logger(const Logger &) = delete;
        Logger &operator=(const Logger &) = delete;
        Logger(Logger &&) = delete;
        Logger &operator=(Logger &&) = delete;

        /**
        Logs a message at the given level. No-op if the corresponding handler is empty or
        if the logger has been closed.
        */
        void log(LogLevel level, const std::string &msg);

        /**
        Invokes every non-empty flush handler.
        */
        void flush();

        /**
        Invokes every non-empty flush handler, then every non-empty close handler, then
        resets all handlers to empty. After close() returns, log/flush calls are no-ops;
        the logger cannot be reused.
        */
        void close();

    private:
        Logger(
            std::array<log_handler_t, level_count> log_handlers,
            std::array<flush_handler_t, level_count> flush_handlers,
            std::array<close_handler_t, level_count> close_handlers);

        void close_internal();

        std::mutex mtx_;
        std::array<log_handler_t, level_count> log_handlers_{};
        std::array<flush_handler_t, level_count> flush_handlers_{};
        std::array<close_handler_t, level_count> close_handlers_{};
        bool closed_ = false;
    }; // class Logger

    /**
    Builds the default logger: stdout for trace/debug/info, stderr for warning/error. Lines are
    formatted as "LEVEL HH:MM:SS:mmm: message\n".
    */
    std::shared_ptr<Logger> NewDefaultLogger();

    /**
    Builds a logger that appends each line to `log_file`. If `also_console` is true, every
    line is additionally written to stdout (trace/debug/info) or stderr (warning/error). Throws
    if the file cannot be opened.
    */
    std::shared_ptr<Logger> NewFileLogger(const std::string &log_file, bool also_console = true);

    namespace internal {
        /**
        Macro-internal: emit a message at the given level through the active logger.
        Callers should use the APSI_LOG_* macros rather than this directly.
        */
        void DoLog(LogLevel level, const std::string &msg);
    } // namespace internal
} // namespace apsi

// The msg argument of APSI_INTERNAL_DO_LOG is intentionally not parenthesized: the macro is
// a stream-style emitter, so callers write `APSI_LOG_INFO("foo " << bar)` and the body relies
// on left-associativity of `<<` (`log_ss << "foo " << bar`). Wrapping `msg` in parentheses
// would break the chain by forcing `("foo " << bar)` to be evaluated independently. The
// bugprone-macro-parentheses check cannot tell the difference, so the macros are bracketed
// with NOLINTBEGIN/NOLINTEND.
// NOLINTBEGIN(bugprone-macro-parentheses)
#define APSI_INTERNAL_CHECK_LOG_LEVEL(log_level) \
    if (apsi::GetLogLevel() > (log_level)) {     \
        break;                                   \
    }

#define APSI_INTERNAL_DO_LOG(msg, msg_level) \
    std::stringstream log_ss;                \
    log_ss << msg;                           \
    apsi::internal::DoLog((msg_level), log_ss.str());

#define APSI_LOG_TRACE(msg)                                   \
    do {                                                      \
        APSI_INTERNAL_CHECK_LOG_LEVEL(apsi::LogLevel::trace); \
        APSI_INTERNAL_DO_LOG(msg, apsi::LogLevel::trace);     \
    } while (0)

#define APSI_LOG_DEBUG(msg)                                   \
    do {                                                      \
        APSI_INTERNAL_CHECK_LOG_LEVEL(apsi::LogLevel::debug); \
        APSI_INTERNAL_DO_LOG(msg, apsi::LogLevel::debug);     \
    } while (0)

#define APSI_LOG_INFO(msg)                                   \
    do {                                                     \
        APSI_INTERNAL_CHECK_LOG_LEVEL(apsi::LogLevel::info); \
        APSI_INTERNAL_DO_LOG(msg, apsi::LogLevel::info);     \
    } while (0)

#define APSI_LOG_WARNING(msg)                                   \
    do {                                                        \
        APSI_INTERNAL_CHECK_LOG_LEVEL(apsi::LogLevel::warning); \
        APSI_INTERNAL_DO_LOG(msg, apsi::LogLevel::warning);     \
    } while (0)

#define APSI_LOG_ERROR(msg)                                   \
    do {                                                      \
        APSI_INTERNAL_CHECK_LOG_LEVEL(apsi::LogLevel::error); \
        APSI_INTERNAL_DO_LOG(msg, apsi::LogLevel::error);     \
    } while (0)
// NOLINTEND(bugprone-macro-parentheses)
