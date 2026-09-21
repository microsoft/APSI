# List of Changes

## Version 1.0.0

### Breaking changes

- Require Microsoft SEAL 4.4.5 or a newer 4.x release, and update the vcpkg baseline.
- The exported CMake package links `JsonCpp::JsonCpp` rather than `jsoncpp_static`, so APSI can be built against a shared jsoncpp. jsoncpp 1.9.5 or newer is now required.
- Retuned 31 of the 36 shipped parameter sets: twenty-seven were above the documented 2^-40 false-positive probability per query, and three more left only two or three bits of noise budget once their bins filled. Only `plain_modulus` and `coeff_modulus_bits` changed, and some sets now send a little more than before. A sender and a receiver must agree on their parameters, so both sides of a deployment want the new values.
- `PSIParams::log2_fpp` is now `PSIParams::log2_fpp_per_bin_bundle`, which is what it measures: it counts neither the bin bundles a location spills into nor the items a query carries. Added `sender::SenderDB::log2_fpp`, which counts both and is the figure a deployment should read.
- A `network::Channel` send throws when it cannot hand the data over. `ZMQChannel` no longer discards a message it has no route for or whose queue is full, and gives up after a bounded send timeout; `StreamChannel` flushes and reports a stream that refused the write. A send that returns still does not mean the peer received the data.
- Code that loops on a `nullptr` receive must consult the new `network::Channel::receive_failed` and `network::Channel::receive_failure_count`.
- `ThreadPoolMgr::SetPhysThreadCount` is now `ThreadPoolMgr::SetPoolWorkerCount`.
- `ThreadPoolMgr` is no longer copyable or movable.
- `SenderDB::get_reader_lock` returns a `std::shared_lock`. The `SenderDB` lock is now a `std::shared_mutex` rather than Microsoft SEAL's, whose implementation depended on how SEAL itself was built.
- `sender::util::CuckooFilter::add` and `remove` are `[[nodiscard]]`. An item the filter cannot store is not stored anywhere, so `has_dropped_items` reports that its negative answers are no longer conclusive, and a `BinBundle` whose filter says so searches the bin instead.
- `oprf::ECPoint::scalar_multiply` is `[[nodiscard]]` and leaves the point unchanged when it fails.

### Added

- Added an optional `timeout` to `Receiver::RequestParams`, `Receiver::RequestOPRF`, and `Receiver::request_query`, and a `--timeout` option to the receiver CLI.
- Added `network::ZMQChannel::end_point` and an optional `on_bound` callback to `ZMQSenderDispatcher::run`, so a sender can bind to port 0.
- Added `util::TaskGroup`, which throws if used from inside a task of the same pool.
- Added `ThreadPoolMgr::GetPoolWorkerCount`; the thread counts report what the pool obtained rather than what was requested.
- Added `util::secure_random_bytes`, which throws when the platform random number generator fails. All of APSI's randomness comes from it.
- Added `util::secure_zero_stack`, `util::StackScrubGuard`, `util::SecureZeroGuard` and `util::stack_scrub_byte_count` for clearing secret material left on the stack.
- Added `oprf::ECPoint::is_prime_order` and `oprf::ECPoint::clear`.
- Added `SenderDB::get_bin_bundle_count_unlocked` for callers that already hold a lock on the `SenderDB`.
- A JSON parameter file may name the serialization version it was written for in an optional top-level `version` key. One naming a version this build does not implement is refused while loading, rather than at the first exchange with a peer.

### Hardened

- Hardened `PSIParams` and the receiver against a hostile sender: bounded waits, validated parameters, and duplicate or out-of-range result packages are ignored.
- `oprf::OPRFReceiver::process_responses` rejects a response outside the prime-order subgroup, and `oprf::ECPoint::load` rejects a non-canonical point encoding.
- An OPRF request is limited to `oprf::oprf_query_count_max` items.
- `SenderDB::insert_or_assign` validates a labeled batch before modifying anything, and refuses it if a label is longer than the `SenderDB` holds or if an item appears twice. Repeats in an unlabeled batch are collapsed rather than refused.
- `Sender::RunQuery` rejects a query that the `SenderDB` parameters no longer describe.
- `SenderDB::Load` rejects a serialized `SenderDB` that omits a required field.
- `sender::util::CuckooFilter::Load` rejects a serialized filter whose table size, bucket count, tag width or overflow slot are inconsistent, including a `bits_per_tag` of 64, which earlier versions accepted. A filter written by an earlier version is loaded as one that may have dropped items.

### Changed and fixed

- Every shipped parameter set names its `plain_modulus` outright rather than a bit count, which pins the noise budget as well as the item size. `plain_modulus_bits` is still accepted.
- A receiving process creates no thread pool.
- `SenderDB` holds its lock across the whole of each operation, so hashing no longer runs outside it. Concurrent updates block queries for longer than before. Moving a `SenderDB` must not overlap any other use of it.
- An exception thrown from a `PowersDag::parallel_apply` callback now propagates to the caller instead of hanging the thread pool.
- Fixed the vendored FourQ sources reading and writing field elements through a `uint128_t` pointer, which produced wrong curve points under GCC 16.

### Build

- Declared Microsoft GSL as a dependency of the exported CMake package, and stopped exporting the FourQ and AVX build flags, `APSI_DEBUG`, and `APSI_BUILD_TYPE`.
- `APSI_BUILD_CLI=ON` with `APSI_USE_ZMQ=OFF` is now rejected at configure time, as is a platform for which no FourQ target can be selected.
- Fixed `APSI_USE_ASM` being honored on architectures with no FourQ assembly, which broke the link on aarch64 Linux.
- Fixed the vendored FourQ sources and Microsoft SEAL each declaring a different `uint128_t` in the global namespace, which broke the build with GCC or Clang on any architecture outside x64 and ARM64, where FourQ falls back to its generic implementation.
- APSI builds with GCC on Windows (MinGW).

## Version 0.13.1

- Updated the vcpkg baseline to build against Microsoft SEAL 4.4.0.
- The global logger is now a never-destroyed ("immortal") singleton, which avoids a static-destruction-order issue when another library logs through APSI during process teardown. As a consequence the logger's handlers are no longer invoked automatically at exit, so the built-in console and file loggers now flush on every write. Custom buffering loggers should be flushed and closed via `apsi::CloseLogger()` (see [Logging](README.md#logging)).
- Fixed some issues in [CMakePresets.json](CMakePresets.json).

## Version 0.13.0

- Numerous bug fixes.
- Replaced the `apsi::Log` class with free functions in the `apsi` namespace (`SetLogLevel`, `GetLogLevel`, `SetLogger`, `GetLogger`, `CloseLogger`, and the new `ResetDefaultLogger`); the level enum is now `apsi::LogLevel` (was `apsi::Log::Level`). The optional `log4cplus` dependency and the `APSI_USE_LOG4CPLUS` option are removed in favor of a built-in logger (see [Logging](README.md#logging)). `Log::SetLogFile` and `Log::SetConsoleDisabled` are gone; use `SetLogger(NewFileLogger(...))` and `SetLogger(Logger::Create({}, {}, {}))`. The `APSI_LOG_*` macros are unchanged at call sites.
- Renamed the log levels to `trace` (most verbose, with a new `APSI_LOG_TRACE` macro), `debug`, `info`, `warning`, `error`, and `suppress` (previously named `off`). The `SetLogLevel(std::string)` and CLI `--logLevel` values change accordingly.
- Removed `Item::get_as<T>` and `receiver::LabelData::get_as<T>`. Use `Item::value()` / `LabelData::value()` instead. `LabelData::to_string()` is now a non-template returning `std::string`.
- Changed the receiver's label-key vectors from `std::vector<LabelKey>` to `apsi::LabelKeyVector`, whose allocator zeroes the buffer before freeing it so per-item label keys do not linger in the heap.
- APSI requires now C++17 or newer. The `APSI_USE_CXX17` option and macro are removed.
- vcpkg is now consumed in manifest mode (`vcpkg.json` at the project root), and the CMake minimum is raised from 3.16 to 3.25.
- The library comes now with CMake presets ([CMakePresets.json](CMakePresets.json)).

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
