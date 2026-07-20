// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// APSI
#include "apsi/log.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;

namespace APSITests {
    namespace {
        // Capturing logger: each level appends "[level] msg" to a shared vector. Tests inspect
        // the vector to verify routing, level filtering, and lifecycle.
        struct CapturedLog {
            string level;
            string msg;
        };

        // Logger::log invokes the handler while holding its internal mutex, so emissions on a
        // given logger are serialized and a handler need not be thread-safe. This capture struct
        // still takes its own mutex so the concurrency test below exercises dispatch correctness
        // (no lost/duplicated/torn messages) independently of Logger's own serialization.
        struct LogCapture {
            std::mutex mtx;
            vector<CapturedLog> entries;
            bool flushed = false;
            bool closed = false;
        };

        shared_ptr<Logger> make_capturing_logger(LogCapture &cap)
        {
            using LH = Logger::log_handler_t;
            using FH = Logger::flush_handler_t;
            using CH = Logger::close_handler_t;

            array<LH, Logger::level_count> log_handlers{};
            array<FH, Logger::level_count> flush_handlers{};
            array<CH, Logger::level_count> close_handlers{};

            auto push = [&cap](string level) {
                return [&cap, level = std::move(level)](const string &msg) {
                    std::lock_guard<std::mutex> lk(cap.mtx);
                    cap.entries.push_back({ level, msg });
                };
            };
            log_handlers[static_cast<size_t>(LogLevel::trace)] = push("trace");
            log_handlers[static_cast<size_t>(LogLevel::debug)] = push("debug");
            log_handlers[static_cast<size_t>(LogLevel::info)] = push("info");
            log_handlers[static_cast<size_t>(LogLevel::warning)] = push("warning");
            log_handlers[static_cast<size_t>(LogLevel::error)] = push("error");

            auto flush_fn = [&cap]() {
                cap.flushed = true;
            };
            flush_handlers[static_cast<size_t>(LogLevel::trace)] = flush_fn;
            flush_handlers[static_cast<size_t>(LogLevel::debug)] = flush_fn;
            flush_handlers[static_cast<size_t>(LogLevel::info)] = flush_fn;
            flush_handlers[static_cast<size_t>(LogLevel::warning)] = flush_fn;
            flush_handlers[static_cast<size_t>(LogLevel::error)] = flush_fn;

            close_handlers[static_cast<size_t>(LogLevel::error)] = [&cap]() {
                cap.closed = true;
            };

            return Logger::Create(
                std::move(log_handlers), std::move(flush_handlers), std::move(close_handlers));
        }

        // Each test takes ownership of the global logger and restores it on scope exit, so test
        // ordering does not matter and one test cannot leak state into the next.
        class GlobalLoggerScope {
        public:
            GlobalLoggerScope() : saved_level_(GetLogLevel())
            {}
            ~GlobalLoggerScope()
            {
                // Drop any custom logger and rebuild the default; then restore the saved level.
                CloseLogger();
                SetLogLevel(saved_level_);
            }
            GlobalLoggerScope(const GlobalLoggerScope &) = delete;
            GlobalLoggerScope &operator=(const GlobalLoggerScope &) = delete;

        private:
            LogLevel saved_level_;
        };
    } // namespace

    TEST(LogTests, MacroRoutesToCustomLogger)
    {
        GlobalLoggerScope scope;
        LogCapture cap;
        SetLogger(make_capturing_logger(cap));
        SetLogLevel(LogLevel::trace);

        APSI_LOG_TRACE("trc " << 0);
        APSI_LOG_DEBUG("dbg " << 1);
        APSI_LOG_INFO("inf " << 2);
        APSI_LOG_WARNING("wrn " << 3);
        APSI_LOG_ERROR("err " << 4);

        ASSERT_EQ(size_t(5), cap.entries.size());
        EXPECT_EQ("trace", cap.entries[0].level);
        EXPECT_EQ("trc 0", cap.entries[0].msg);
        EXPECT_EQ("debug", cap.entries[1].level);
        EXPECT_EQ("dbg 1", cap.entries[1].msg);
        EXPECT_EQ("info", cap.entries[2].level);
        EXPECT_EQ("inf 2", cap.entries[2].msg);
        EXPECT_EQ("warning", cap.entries[3].level);
        EXPECT_EQ("wrn 3", cap.entries[3].msg);
        EXPECT_EQ("error", cap.entries[4].level);
        EXPECT_EQ("err 4", cap.entries[4].msg);
    }

    TEST(LogTests, LevelFiltersBeforeDispatch)
    {
        GlobalLoggerScope scope;
        LogCapture cap;
        SetLogger(make_capturing_logger(cap));
        SetLogLevel(LogLevel::warning);

        APSI_LOG_TRACE("filtered trace");
        APSI_LOG_DEBUG("filtered debug");
        APSI_LOG_INFO("filtered info");
        APSI_LOG_WARNING("kept warning");
        APSI_LOG_ERROR("kept error");

        ASSERT_EQ(size_t(2), cap.entries.size());
        EXPECT_EQ("warning", cap.entries[0].level);
        EXPECT_EQ("kept warning", cap.entries[0].msg);
        EXPECT_EQ("error", cap.entries[1].level);
        EXPECT_EQ("kept error", cap.entries[1].msg);
    }

    TEST(LogTests, LevelSuppressSuppressesEverything)
    {
        GlobalLoggerScope scope;
        LogCapture cap;
        SetLogger(make_capturing_logger(cap));
        SetLogLevel(LogLevel::suppress);

        APSI_LOG_TRACE("x");
        APSI_LOG_DEBUG("x");
        APSI_LOG_INFO("x");
        APSI_LOG_WARNING("x");
        APSI_LOG_ERROR("x");

        EXPECT_TRUE(cap.entries.empty());
    }

    TEST(LogTests, SetLogLevelStringMatchesEnum)
    {
        GlobalLoggerScope scope;

        SetLogLevel(string("trace"));
        EXPECT_EQ(LogLevel::trace, GetLogLevel());
        SetLogLevel(string("debug"));
        EXPECT_EQ(LogLevel::debug, GetLogLevel());
        SetLogLevel(string("info"));
        EXPECT_EQ(LogLevel::info, GetLogLevel());
        SetLogLevel(string("warning"));
        EXPECT_EQ(LogLevel::warning, GetLogLevel());
        SetLogLevel(string("error"));
        EXPECT_EQ(LogLevel::error, GetLogLevel());
        SetLogLevel(string("suppress"));
        EXPECT_EQ(LogLevel::suppress, GetLogLevel());
    }

    TEST(LogTests, SetLogLevelStringRejectsUnknown)
    {
        GlobalLoggerScope scope;
        EXPECT_THROW(SetLogLevel(string("nope")), std::invalid_argument);
    }

    TEST(LogTests, FlushInvokesHandlers)
    {
        GlobalLoggerScope scope;
        LogCapture cap;
        auto logger = make_capturing_logger(cap);
        SetLogger(logger);
        SetLogLevel(LogLevel::trace);

        APSI_LOG_INFO("trigger");
        EXPECT_FALSE(cap.flushed);

        logger->flush();
        EXPECT_TRUE(cap.flushed);
    }

    TEST(LogTests, CloseInvokesCloseHandlerAndRendersLoggerInert)
    {
        GlobalLoggerScope scope;
        LogCapture cap;
        auto logger = make_capturing_logger(cap);
        SetLogger(logger);
        SetLogLevel(LogLevel::trace);

        APSI_LOG_INFO("before close");
        ASSERT_EQ(size_t(1), cap.entries.size());

        logger->close();
        EXPECT_TRUE(cap.closed);

        APSI_LOG_INFO("after close");
        EXPECT_EQ(size_t(1), cap.entries.size()) << "log() on a closed Logger must be a no-op";
    }

    TEST(LogTests, CloseLoggerClearsCustomLogger)
    {
        GlobalLoggerScope scope;
        LogCapture cap;
        SetLogger(make_capturing_logger(cap));
        SetLogLevel(LogLevel::trace);

        APSI_LOG_INFO("captured");
        ASSERT_EQ(size_t(1), cap.entries.size());

        CloseLogger();
        EXPECT_TRUE(cap.closed) << "CloseLogger() should close the custom logger";

        // After CloseLogger, install a null logger so the next emission doesn't pollute test
        // runner output via the lazily-rebuilt default. Then verify cap.entries is unchanged
        // (the new logger doesn't feed cap) and emission does not crash.
        SetLogger(Logger::Create({}, {}, {}));
        APSI_LOG_INFO("after close");
        EXPECT_EQ(size_t(1), cap.entries.size());
    }

    TEST(LogTests, SetLoggerNullClearsAndLazyRebuildsDefault)
    {
        GlobalLoggerScope scope;
        LogCapture cap;
        SetLogger(make_capturing_logger(cap));
        SetLogLevel(LogLevel::trace);

        APSI_LOG_INFO("captured");
        ASSERT_EQ(size_t(1), cap.entries.size());

        // SetLogger(nullptr) closes the custom logger; the next GetLogger() call lazily
        // installs a fresh default. Suppress its stdout output by installing a null logger
        // afterwards.
        SetLogger(nullptr);
        EXPECT_TRUE(cap.closed) << "SetLogger(nullptr) should close the previous custom logger";

        SetLogger(Logger::Create({}, {}, {}));
        APSI_LOG_INFO("after reset");
        EXPECT_EQ(size_t(1), cap.entries.size())
            << "After SetLogger(nullptr), cap should not receive further emissions";
    }

    TEST(LogTests, DirectLoggerCallSkipsLevelGate)
    {
        // The level threshold lives in Log, not Logger. Calling Logger::log directly should always
        // dispatch (subject only to the handler being non-empty), regardless of SetLogLevel.
        GlobalLoggerScope scope;
        LogCapture cap;
        auto logger = make_capturing_logger(cap);
        SetLogger(logger);
        SetLogLevel(LogLevel::suppress);

        logger->log(LogLevel::debug, "bypass");
        ASSERT_EQ(size_t(1), cap.entries.size());
        EXPECT_EQ("debug", cap.entries[0].level);
        EXPECT_EQ("bypass", cap.entries[0].msg);
    }

    TEST(LogTests, LoggerLogAtSuppressSentinelIsHarmless)
    {
        // LogLevel::suppress is a threshold-only sentinel with no handler slot (its integer value
        // equals level_count). Logger::log must treat it as an out-of-range no-op rather than
        // index the handler array out of bounds or crash.
        GlobalLoggerScope scope;
        LogCapture cap;
        auto logger = make_capturing_logger(cap);
        SetLogger(logger);

        EXPECT_NO_THROW(logger->log(LogLevel::suppress, "ignored"));
        EXPECT_TRUE(cap.entries.empty());
    }

    // Captures a std::ostream's streambuf into a stringstream for the lifetime of the guard, and
    // restores the original streambuf on destruction. Used by the lazy-rebuild test below to
    // intercept stdout/stderr that the default logger writes to.
    class CoutCaptureGuard {
    public:
        explicit CoutCaptureGuard(std::ostream &target) : target_(target), saved_(target.rdbuf())
        {
            target_.rdbuf(capture_.rdbuf());
        }
        ~CoutCaptureGuard()
        {
            target_.rdbuf(saved_);
        }
        CoutCaptureGuard(const CoutCaptureGuard &) = delete;
        CoutCaptureGuard &operator=(const CoutCaptureGuard &) = delete;

        std::string str() const
        {
            return capture_.str();
        }

    private:
        std::ostream &target_;
        std::streambuf *saved_;
        std::stringstream capture_;
    };

    TEST(LogTests, SetLoggerNullLazilyRebuildsDefaultAndEmitsToStdout)
    {
        // Positive test for the lazy-rebuild path: after SetLogger(nullptr), the next emission
        // should route through a freshly built NewDefaultLogger, which writes INFO to stdout.
        // The existing SetLoggerNullClearsAndLazyRebuildsDefault test sidesteps this path by
        // installing a null logger before any emission.
        GlobalLoggerScope scope;
        SetLogger(nullptr);
        SetLogLevel(LogLevel::trace);

        std::string captured;
        {
            CoutCaptureGuard guard(std::cout);
            APSI_LOG_INFO("lazy_rebuild_marker_42");
            captured = guard.str();
        }

        EXPECT_NE(std::string::npos, captured.find("lazy_rebuild_marker_42"))
            << "default logger should have routed the INFO line to stdout; got: " << captured;
    }

    TEST(LogTests, SetLoggerNullLazilyRebuildsDefaultAndEmitsToStderr)
    {
        // Companion to the stdout test: warning/error go to stderr in the default logger.
        GlobalLoggerScope scope;
        SetLogger(nullptr);
        SetLogLevel(LogLevel::trace);

        std::string captured;
        {
            CoutCaptureGuard guard(std::cerr);
            APSI_LOG_ERROR("lazy_rebuild_err_marker_99");
            captured = guard.str();
        }

        EXPECT_NE(std::string::npos, captured.find("lazy_rebuild_err_marker_99"))
            << "default logger should have routed the ERROR line to stderr; got: " << captured;
    }

    TEST(LogTests, NewFileLoggerWritesAllLevelsToFile)
    {
        // Construct a unique path under the OS temp directory. The counter survives across tests
        // run in the same process so concurrent test workers (if anyone ever sets that up) get
        // distinct files even on the same second.
        namespace fs = std::filesystem;
        static std::atomic<std::uint64_t> seq{ 0 };
        fs::path log_path = fs::temp_directory_path() /
                            ("apsi_test_log_" + std::to_string(seq.fetch_add(1)) + ".log");

        // Ensure we don't leave the file behind even if the test asserts.
        struct RemoveOnExit {
            fs::path p;
            ~RemoveOnExit()
            {
                std::error_code ec;
                fs::remove(p, ec);
            }
        } cleanup{ log_path };

        {
            GlobalLoggerScope scope;
            SetLogger(NewFileLogger(log_path.string(), /*also_console=*/false));
            SetLogLevel(LogLevel::trace);

            APSI_LOG_DEBUG("file_dbg_marker");
            APSI_LOG_INFO("file_inf_marker");
            APSI_LOG_WARNING("file_wrn_marker");
            APSI_LOG_ERROR("file_err_marker");

            // GlobalLoggerScope's destructor calls CloseLogger() on the file logger, flushing
            // and closing the underlying ofstream.
        }

        std::ifstream in(log_path);
        ASSERT_TRUE(in.good()) << "expected log file to exist at " << log_path;
        std::stringstream ss;
        ss << in.rdbuf();
        std::string contents = ss.str();

        EXPECT_NE(std::string::npos, contents.find("file_dbg_marker")) << contents;
        EXPECT_NE(std::string::npos, contents.find("file_inf_marker")) << contents;
        EXPECT_NE(std::string::npos, contents.find("file_wrn_marker")) << contents;
        EXPECT_NE(std::string::npos, contents.find("file_err_marker")) << contents;
    }

    TEST(LogTests, NewFileLoggerThrowsOnUnopenablePath)
    {
        // A path inside a non-existent directory cannot be opened. NewFileLogger documents
        // "Throws if the file cannot be opened" — verify the contract.
        GlobalLoggerScope scope;
        std::string bad_path = "/this/path/should/not/exist/under/any/reasonable/test/setup.log";
        EXPECT_THROW(NewFileLogger(bad_path, false), std::runtime_error);
    }

    TEST(LogTests, LoggerConcurrencyDispatchesEveryMessageWithoutLoss)
    {
        // Logger invokes the handler while holding its internal mutex, so emissions are
        // serialized. What we verify here:
        //   1) No emission is lost or duplicated under concurrent macro calls — every call from
        //      every thread reaches the handler exactly once.
        //   2) Each formatted message survives the stringstream + dispatch unmangled (no torn
        //      writes from concurrent stringstreams).
        // The LogCapture struct still uses its own mutex; this test targets dispatch correctness,
        // while NewFileLoggerIsThreadSafe below targets the stream-sink data-race guarantee that
        // the under-lock dispatch provides.
        constexpr int thread_count = 8;
        static constexpr int lines_per_thread = 1000;

        GlobalLoggerScope scope;
        LogCapture cap;
        SetLogger(make_capturing_logger(cap));
        SetLogLevel(LogLevel::trace);

        std::vector<std::thread> threads;
        threads.reserve(thread_count);
        for (int t = 0; t < thread_count; t++) {
            threads.emplace_back([t] {
                for (int i = 0; i < lines_per_thread; i++) {
                    APSI_LOG_INFO("t" << t << "_i" << i);
                }
            });
        }
        for (auto &th : threads) {
            th.join();
        }

        ASSERT_EQ(size_t(thread_count) * size_t(lines_per_thread), cap.entries.size())
            << "Logger lost or duplicated entries under concurrent emission";

        for (const auto &e : cap.entries) {
            EXPECT_EQ("info", e.level);
            // Every well-formed message starts with 't<digit>' and contains '_i'. A torn write
            // would either crash the test, give a malformed string, or violate this shape.
            ASSERT_FALSE(e.msg.empty());
            EXPECT_EQ('t', e.msg[0]);
            EXPECT_NE(std::string::npos, e.msg.find("_i")) << e.msg;
        }
    }

    TEST(LogTests, NewFileLoggerIsThreadSafe)
    {
        // Regression guard for the file-logger data race: the bundled file sink writes to a
        // single shared ofstream with no internal lock, so its thread safety depends entirely on
        // Logger serializing handler invocations under its mutex. Under the previous
        // invoke-outside-the-lock dispatch this raced (TSan-detectable) and could interleave
        // characters from concurrent emissions into the same line. Hammer it from many threads
        // and assert every line arrives whole. Run under ThreadSanitizer to catch the race.
        namespace fs = std::filesystem;
        static std::atomic<std::uint64_t> seq{ 0 };
        fs::path log_path = fs::temp_directory_path() /
                            ("apsi_test_mtlog_" + std::to_string(seq.fetch_add(1)) + ".log");

        struct RemoveOnExit {
            fs::path p;
            ~RemoveOnExit()
            {
                std::error_code ec;
                fs::remove(p, ec);
            }
        } cleanup{ log_path };

        constexpr int thread_count = 8;
        static constexpr int lines_per_thread = 500;

        {
            GlobalLoggerScope scope;
            SetLogger(NewFileLogger(log_path.string(), /*also_console=*/false));
            SetLogLevel(LogLevel::trace);

            std::vector<std::thread> threads;
            threads.reserve(thread_count);
            for (int t = 0; t < thread_count; t++) {
                threads.emplace_back([t] {
                    for (int i = 0; i < lines_per_thread; i++) {
                        APSI_LOG_INFO("t" << t << "_i" << i);
                    }
                });
            }
            for (auto &th : threads) {
                th.join();
            }
            // GlobalLoggerScope's destructor calls CloseLogger(), flushing and closing the
            // underlying ofstream before we read it back below.
        }

        std::ifstream in(log_path);
        ASSERT_TRUE(in.good()) << "expected log file to exist at " << log_path;

        int line_count = 0;
        std::string line;
        while (std::getline(in, line)) {
            line_count++;
            // Every well-formed line carries exactly one message marker "_i". A character-level
            // interleave of two concurrent emissions would merge two messages into one line and
            // show up as two markers (or none, if the line was split mid-marker).
            std::size_t markers = 0;
            for (std::size_t pos = line.find("_i"); pos != std::string::npos;
                 pos = line.find("_i", pos + 1)) {
                markers++;
            }
            EXPECT_EQ(size_t(1), markers) << "torn/interleaved line: " << line;
        }

        EXPECT_EQ(thread_count * lines_per_thread, line_count)
            << "file logger lost, duplicated, or merged lines under concurrent emission";
    }
} // namespace APSITests
