# List of Changes

## Version 0.13.0

- Replaced the `apsi::Log` class with free functions in the `apsi` namespace (`SetLogLevel`, `GetLogLevel`, `SetLogger`, `GetLogger`, `CloseLogger`, and the new `ResetDefaultLogger`); the level enum is now `apsi::LogLevel` (was `apsi::Log::Level`). The optional `log4cplus` dependency and the `APSI_USE_LOG4CPLUS` option are removed in favor of a built-in logger (see [Logging](README.md#logging)). `Log::SetLogFile` and `Log::SetConsoleDisabled` are gone; use `SetLogger(NewFileLogger(...))` and `SetLogger(Logger::Create({}, {}, {}))`. The `APSI_LOG_*` macros are unchanged at call sites.
- Renamed the log levels to `trace` (most verbose, with a new `APSI_LOG_TRACE` macro), `debug`, `info`, `warning`, `error`, and `suppress` (previously named `off`). The `SetLogLevel(std::string)` and CLI `--logLevel` values change accordingly.
- Removed `Item::get_as<T>` and `receiver::LabelData::get_as<T>`. Use `Item::value()` / `LabelData::value()` instead. `LabelData::to_string()` is now a non-template returning `std::string`.
- Changed the receiver's label-key vectors from `std::vector<LabelKey>` to `apsi::LabelKeyVector`, whose allocator zeroes the buffer before freeing it so per-item label keys do not linger in the heap.
- APSI requires now C++17 or newer. The `APSI_USE_CXX17` option and macro are removed.
- vcpkg is now consumed in manifest mode (`vcpkg.json` at the project root), and the CMake minimum is raised from 3.16 to 3.25.
- The library comes now with CMake presets ([CMakePresets.json](CMakePresets.json)).
- `ThreadPoolMgr::SetThreadCount` now resizes the running pool immediately, rather than only on the next pool reconstruction.
- OPRF secret material on the stack is now wiped before scope exit.

## Version 0.12.0

- Merged [PR #60](https://github.com/microsoft/APSI/pull/60), [PR #70](https://github.com/microsoft/APSI/pull/70), and [PR #72](https://github.com/microsoft/APSI/pull/72).
- Addressed [Issue #66](https://github.com/microsoft/APSI/issues/66).

## Version 0.9.1

- Fixed a bug with SEAL dependency.

## Version 0.9.0

- Switching to use SEAL 4.1.0.
- Added $schema to cgmanifest.json [(PR #38)](https://github.com/microsoft/APSI/pull/38).
- Fixed a mistake in [README.md](README.md) that caused Windows configurations with `vcpkg` to fail.

## Version 0.8.2

Fixes the following GitHub issues:

- [#25](https://github.com/microsoft/APSI/issues/25) Force AVX when AVX2 is available
- [#31](https://github.com/microsoft/APSI/issues/31) Build fails on Mac M1
- [#32](https://github.com/microsoft/APSI/issues/32) Build fails on arm64-android
- [#33](https://github.com/microsoft/APSI/issues/33) Build fails on x86-windows
- [#34](https://github.com/microsoft/APSI/issues/34) Building arm64-windows

## Version 0.8.1

- Fixed the bug mentioned in [Issue 15](https://github.com/microsoft/APSI/issues/15)

## Version 0.8.0

- Fixed the bug mentioned in [Issue 21](https://github.com/microsoft/APSI/issues/21).

## Version 0.7.0

- The CMake system no longer builds unit tests and the CLI by default.
To build these, specify `-DAPSI_BUILD_CLI=ON` and `-DAPSI_BUILD_TESTS=ON`.

## Version 0.6.0

- The function `SenderDB::strip` now also clears the OPRF key from held by the `SenderDB` instance.
This can be useful in some situations, where the `SenderDB` should serve query requests in an untrusted environment and should have no access to the OPRF key.
Note that the OPRF requests still need to be served and do require the OPRF key, but this can be done, for example, by a different isolated machine.
It is essential to ensure that the OPRF key is saved before calling `SenderDB::strip`.
- Removed `parameters/16M-256.json`; use [parameters/16M-1024.json](parameters/16M-1024.json) instead.
- Added error handling code in [sender/apsi/zmq/sender_dispatcher.cpp](sender/apsi/zmq/sender_dispatcher.cpp).

## Version 0.5.0

- Added flexibility to use *any* value for `felts_per_item` in `PSIParams`, not just a power of two.
- Corrected parameter files to have < 2^(-40) false-positive probability per protocol execution.
