# List of Changes

## Version 2.0.0

### Breaking changes

- Required Microsoft SEAL 4.7.0 or a newer 4.x release; see [Microsoft SEAL 4.7.0](README.md#microsoft-seal-470).
- Re-tuned every parameter set in `parameters/` under its old name, so a deployment that loads a shipped file by name gets new parameters. To keep its parameters, it must keep the file from APSI 1.1.0; to move to the new set, it must rebuild its `SenderDB` from the original items. 32 of the 36 sets use match tags, which APSI 1.x cannot use. See [Upgrading from APSI 1.x](README.md#upgrading-from-apsi-1x).
- The receiver bit-packs its queries by default. A sender built with Microsoft SEAL older than 4.6, as APSI 1.x senders usually are, cannot load such a query and drops it, so the receiver waits out its timeout. To query such a sender, call `Receiver::set_compr_mode(seal::compr_mode_type::zstd)`, or pass `--compression zstd` to `receiver_cli`.
- A query carries a fingerprint of the parameters it was created for, and a sender refuses a query created for other parameters. A query without a fingerprint, as receivers of APSI 1.x send, is still answered for parameters without match tags.
- A compressed `SenderDB`, the default, bit-packs its plaintexts or keeps them uncompressed, where it used Zstandard. APSI 1.x usually cannot serve a compressed `SenderDB` that APSI 2.0 saves: it loads it and then fails every query, or may crash. To save one that APSI 1.x can serve, pass `SenderDB::PlaintextSaveMode::apsi_1x` to `SenderDB::save`. APSI 2.0 loads the `SenderDB`s APSI 1.x saves, except as the next entry describes.
- `SenderDB::set_data` throws `std::logic_error` for a stripped `SenderDB`, and so does `SenderDB::strip` for one that is stripped already. The `SenderDB` constructor that takes an OPRF key throws `std::invalid_argument` for a key of zero, and `SenderDB::Load` refuses a `SenderDB` that is not stripped but holds a key of zero, which APSI 1.1.0 could save after `SenderDB::clear` or `SenderDB::set_data` on a stripped `SenderDB`; such a `SenderDB` must be rebuilt.
- `network::Channel` has a new virtual member function, `receive_result_for`, so code built against the headers of APSI 1.x must be recompiled.
- `network::ResultPackage::psi_result` is optional, since results with match tags have none. Code that loads result packages itself should use `network::Channel::receive_result_for`, or the overload of `network::ResultPackage::load` that takes the `PSIParams`.
- `network::SenderOperationQuery::load` keeps the ciphertexts of a query serialized, for `sender::Query` to load and check, so code that reads them itself must load them with `SEALObject::extract` and a `seal::SEALContext`. It refuses relinearization keys other than the single key set that `seal::KeyGenerator::create_relin_keys` makes, which is what every APSI receiver sends.

### Added

- Added match tags, an optional way of deciding matches, selected by a non-zero `tag_part_count` in `PSIParams::ItemParams` (`item_params.tag_part_count` in JSON, together with `"version": 2` at the top level). The sender stores a pseudorandom tag, derived from the item's label key, with every item, and the receiver accepts an item only when the sender returns exactly its tag. The false-positive probability then does not depend on `max_items_per_bin`, an item can be a single field element, and queries and responses are smaller with most parameter sets. With match tags, the receiver needs the label keys of its items even without labels. APSI 1.x refuses parameters with match tags. See [Match Tags](README.md#match-tags).
- Added `PSIParams::fingerprint`, which every query carries, and `network::SenderOperationQuery::ExtractParamsFingerprint`, which reads it from a serialized query, for an application that serves `SenderDB`s with different parameters.
- Added `SenderDB::insert_or_assign_hashed`, `SenderDB::set_data_hashed` and `SenderDB::remove_hashed`, which take items hashed already with `oprf::OPRFSender::ComputeHashes`, or with the new `oprf::OPRFSender::ComputeHashesAndMatchTags` for parameters with match tags, so that a `SenderDB` can be built where the OPRF key is not kept. Unless such a `SenderDB` holds the key the items were hashed with, it must be stripped before it is served with that key. See [SenderDB](README.md#senderdb).
- Added `apsi::ScopedParallelismLimit`, which, while it exists, limits how many tasks of the shared thread pool the APSI operations begun on the calling thread use at once. See [Per-Operation Limits](README.md#per-operation-limits).

### Hardened

- A sender checks how many ciphertexts and relinearization keys a query holds before loading them, and refuses ciphertexts that share bytes or would decompress to far more than their size, so that a small crafted query can no longer make it allocate gigabytes of memory.
- A receiver refuses result packages that a sender cannot have produced, such as ones whose ciphertexts are of the wrong size or level, share bytes, or would decompress to far more than their size, so that a malicious sender can no longer make it allocate far more memory than any result takes.
- `SenderDB::Load` no longer reserves memory for as many bin bundles as a file declares. It refuses a truncated file, and a bin bundle holding a polynomial without coefficients, which crashed a sender answering a query.

### Changed and fixed

- Compared with the APSI 1.x set of the same name, on the same build of APSI 2.0, no set in `parameters/` takes more bytes for a query and its results, or has a higher false-positive probability at the sizes its name gives, and none takes more of the sender's CPU time per query beyond measurement noise; many take much less. The false-positive probability is below 2^-40 for every set. Setting up a `SenderDB` takes longer with some of the largest sets.
- A sender answers queries much faster. Bit-packed and uncompressed plaintexts load much faster than ones compressed with Zstandard, uncompressed plaintexts are read in place, polynomials are evaluated with fewer operations, and the ciphertexts of a query are loaded in parallel.
- Setting up a labeled `SenderDB` is much faster, and so are small updates of a `SenderDB`, which used to compute the polynomials of every bin of the bin bundles they changed, and could hold off queries for seconds.
- Fixed `SenderDB::insert_or_assign` storing a second copy of an item when it replaced the item's label: queries could then return the old label, and `SenderDB::remove` left a copy behind. A `SenderDB` in which APSI 1.x replaced labels may hold such copies. Replacing the label again with APSI 2.0 gives every copy the new label, and removing the item and inserting it again, or rebuilding the `SenderDB`, removes the copies.
- Fixed `SenderDB::clear` and `SenderDB::set_data` making a stripped `SenderDB` usable again under its zeroed OPRF key, with which every item would have matched. `SenderDB::clear` now gives a stripped `SenderDB` a new key.
- `SenderDB::set_data` and `SenderDB::remove` change nothing when they refuse a batch, where `SenderDB::set_data` left the database empty and `SenderDB::remove` could apply part of the batch. An update that fails partway, as for lack of memory or because the log handler throws, no longer leaves the `SenderDB` refusing every later query.
- `oprf::OPRFSender::ComputeHashes` throws `std::invalid_argument` for a label longer than `label_byte_count`, which it used to truncate.
- Fixed `SenderDB::save` writing files that `SenderDB::Load` cannot read. It refuses, with `std::length_error` and before writing anything, a `SenderDB` that `SenderDB::Load` might not read: one with a bin bundle of more than about 2 GiB, which large parameters can produce, or one that is not stripped and holds more than about 134 million items.
- Fixed `SenderDB::Load` refusing a `SenderDB` with long labels and many bins, which could be saved but not loaded.
- Fixed the receiver reporting an item given more than once in a query only at its last index.
- Fixed undefined behavior in `util::field_elts_to_bits`, with which the receiver decodes labels.
- Fixed `sender::Query::deep_copy`, which made an invalid copy of a valid query.

### Build

- Fixed the build for targets for which FourQ has no optimized implementation, such as 64-bit RISC-V and 32-bit x86 Linux, which stopped with "Unsupported ARCHITECTURE".

## Version 1.1.0

- The installed paths no longer carry the version: headers go to `include/apsi`, the CMake package to `lib/cmake/APSI`, and the library is named `apsi`. Code can include `apsi/...` from the standard include directory alone. Consumers using `find_package(APSI)` and `APSI::apsi` need no change. Installing over APSI 1.0 leaves its versioned files in place; remove them first.
- Updated the vcpkg baseline so that Debug builds with the `hexl` feature link.

## Version 1.0.1

- Added a `NOTICE` file for bundled third-party sources. It and `LICENSE` are now installed with APSI.
- `sender/apsi/bin_bundle.cpp` reports the requirement for a Microsoft SEAL built with `SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF` with `#error` rather than an unconditional `static_assert`, once per translation unit rather than once per function.
- `ThreadPool::wait_until_nothing_in_flight` documents what it guarantees: the pool being idle rather than the calling thread's own tasks having finished.
- Fixed a sign-conversion warning in the receiver CLI, which appeared only in a Debug build.

## Version 1.0.0

### Breaking changes

- `Receiver::request_query` draws a new key pair for each query, so two queries no longer carry the same public keys for a sender to link them by. A caller using `Receiver::create_query` and `Receiver::process_result` instead must call `Receiver::reset_keys` between queries itself, at a point where none is in flight.
- Require Microsoft SEAL 4.4.5 or a newer 4.x release, and update the vcpkg baseline.
- The exported CMake package links `JsonCpp::JsonCpp` rather than `jsoncpp_static`, so APSI can be built against a shared jsoncpp. jsoncpp 1.9.5 or newer is now required.
- Retuned 31 of the 36 shipped parameter sets: twenty-seven were above the documented 2^-40 false-positive probability per query, and three more left only two or three bits of noise budget once their bins filled. Some sets now send more than before. A sender and a receiver must agree on their parameters, so both sides of a deployment want the new values.
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

- The ZeroMQ high water mark is 256 messages rather than 70000. It bounds what ZeroMQ retains for a peer that has stopped reading, which at the largest shipped parameter set is the difference between roughly a hundred megabytes and tens of gigabytes per peer.
- `oprf::OPRFKey` comparison reads both keys in full rather than stopping at the first difference, so its running time says nothing about where they differ.
- The receiver CLI escapes control characters in items and labels before printing them, quotes its CSV output, and emits color only to a terminal. A label is whatever the sender chose to store: an escape sequence in one could otherwise rewrite what had already appeared on the screen, and a comma could add a column to the output file.
- Hardened `PSIParams` and the receiver against a hostile sender: bounded waits, validated parameters, and duplicate or out-of-range result packages are ignored.
- `oprf::OPRFReceiver::process_responses` rejects a response outside the prime-order subgroup, and `oprf::ECPoint::load` rejects a non-canonical point encoding.
- An OPRF request is limited to `oprf::oprf_query_count_max` items.
- `SenderDB::insert_or_assign` validates a labeled batch before modifying anything, and refuses it if a label is longer than the `SenderDB` holds or if an item appears twice. Repeats in an unlabeled batch are collapsed rather than refused.
- `Sender::RunQuery` rejects a query that the `SenderDB` parameters no longer describe.
- `SenderDB::Load` rejects a serialized `SenderDB` that omits a required field.
- `sender::util::CuckooFilter::Load` rejects a serialized filter whose table size, bucket count, tag width or overflow slot are inconsistent, including a `bits_per_tag` of 64, which earlier versions accepted. A filter written by an earlier version is loaded as one that may have dropped items.

### Changed and fixed

- `Receiver::cuckoo_table_insert_attempts` is 8000 rather than 500.
- `PowersDag::configure` rejects a set of target powers it cannot decompose, rather than returning a DAG whose node names a parent that does not exist. The target powers APSI derives from a parameter set are always decomposable, so this is for a caller that builds a set of its own.
- Loading a JSON parameter file reports a value of the wrong type instead of reading it as a string, which threw or aborted depending on how jsoncpp was built.
- Every shipped parameter set names its `plain_modulus` outright rather than a bit count, which pins the noise budget as well as the item size. `plain_modulus_bits` is still accepted.
- A receiving process creates no thread pool.
- `SenderDB` holds its lock across the whole of each operation, so hashing no longer runs outside it. Concurrent updates block queries for longer than before. Moving a `SenderDB` must not overlap any other use of it.
- An exception thrown from a `PowersDag::parallel_apply` callback now propagates to the caller instead of hanging the thread pool.
- Fixed the vendored FourQ sources reading and writing field elements through a `uint128_t` pointer, which produced wrong curve points under GCC 16.

### Build

- `APSI_SECURE_COMPILE_OPTIONS` now hardens the build rather than doing nothing, and defaults to ON. GCC and Clang get stack protection, position-independent code and bounds-checked standard library containers, together with fortified libc calls and stack-clash protection away from Apple platforms and full RELRO with a non-executable stack on ELF targets; MSVC gets Control Flow Guard, the Spectre variant 1 mitigation, and shadow-stack marking on x64. See [Build Hardening](README.md#build-hardening) for what each toolchain receives. The options are not exported, so a consumer chooses its own.
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
