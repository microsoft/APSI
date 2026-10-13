# List of Changes

## Version 2.0.0

### Breaking changes

- Required Microsoft SEAL 4.6.2 or a newer 4.x release. Bit-packed serialization is new in Microsoft SEAL 4.6.0, 4.6.1 corrects wrong results with MSVC for ARM64, and 4.6.2 can be configured with an installed Microsoft GSL 5 (`SEAL_BUILD_DEPS=OFF`, as vcpkg builds it). `vcpkg.json` asks for `seal` 4.6.2 with the `zlib` feature as well as `zstd` and `no-throw-tran`, since a sender answers each query in the compression mode the query arrived in. If the vcpkg registry does not have Microsoft SEAL 4.6.2, configure with an overlay port for it; see [Microsoft SEAL 4.6.2](README.md#microsoft-seal-462).
- The receiver bit-packs its queries by default (`seal::compr_mode_type::bitpack`), where it used Zstandard. A sender built with Microsoft SEAL older than 4.6, as APSI 1.x senders usually are, cannot load such a query and drops it without answering, so the receiver waits out its timeout. To query one, call `Receiver::set_compr_mode(seal::compr_mode_type::zstd)`, or pass `--compression zstd` to `receiver_cli`.
- A query carries the fingerprint of the parameters it was created for, and a sender refuses a query whose fingerprint differs from that of its `SenderDB`'s parameters, where it used to answer any query of the right shape, with results the receiver read as no match. A query without a fingerprint, as receivers before 2.0 send, is still answered for parameters without match tags. Senders before 2.0 ignore the fingerprint.
- `network::Channel` has a new virtual member function, `receive_result_for`, with a default implementation. A class derived from `Channel` compiles unchanged, but code built against the headers of APSI 1.x has to be recompiled. A class that overrides `receive_result` should override `receive_result_for` too if it wants a package checked before its ciphertexts are loaded, as `network::StreamChannel` and `network::ZMQChannel` check it: the default implementation checks the package after loading it.
- `network::ResultPackage::psi_result` is optional in the schema, since a result for parameters with match tags has none, so `ResultPackage::load(in, context)` no longer guarantees that it is set, and `ResultPackage::save` leaves an empty one out. A caller that loads packages itself should use the new `ResultPackage::load(in, context, params)`, which before loading any ciphertext refuses a package without a `psi_result` for parameters without match tags, and one whose structure does not fit parameters with match tags; or `Channel::receive_result_for(context, params)`, which rejects such a package as a failed receive, so that `Receiver::request_query` aborts, as in APSI 1.x, rather than skipping it. `Receiver::process_result_part` and `Receiver::process_result` throw `std::runtime_error` for a package without a `psi_result` when the parameters have no match tags.
- Besides `ResultPackage.psi_result`, the FlatBuffers schemas no longer mark `BinBundleCache.felt_matching_polyns` and `BinBundleCache.batched_matching_polyn` required, and they gain optional fields at the ends of their tables: `PSIParams.tag_part_count`, `BinBundle.hashed_items` and `QueryRequest.params_fingerprint`. Making fields optional changes only what the verifiers accept, as APSI checks in code what the schemas no longer enforce. The new fields are written only for parameters with match tags, apart from `QueryRequest.params_fingerprint`, which every query from APSI 2.0 carries.

### Added

- Added match tags, an optional way of deciding matches, selected by a non-zero `PSIParams::ItemParams::tag_part_count` (`item_params.tag_part_count` in JSON). The sender stores with every item a pseudorandom tag of `tag_part_count` item-sized parts, derived with Blake2xb from the item's label key, as the first label parts of the item, and computes no matching polynomial. The receiver derives the tags of its own items from their label keys and accepts an item only when the sender returns exactly its tag. An item the sender does not hold then passes against a bin bundle with probability `2^-tag_bit_count`, whatever `max_items_per_bin` is, so an item can be a single field element, which makes queries and responses smaller for most parameter sets. With a `tag_part_count` of zero, the default, matches are decided as in APSI 1.x. See [Match Tags](README.md#match-tags).
- Added `PSIParams::tag_part_count`, `PSIParams::tag_bit_count` and `PSIParams::uses_tags`, and the constants `PSIParams::tag_bit_count_min` (40), `PSIParams::item_bit_count_min_with_tags` (8), `PSIParams::ItemParams::felts_per_item_min_with_tags` (1), `PSIParams::ItemParams::tag_part_count_max` (64) and `PSIParams::tag_serialization_version` (2). With match tags, `felts_per_item` may be 1 to 32 and the item bit count 8 to 128, the tag must have at least 40 bits, and `max_items_per_bin` may not exceed `2^item_bit_count_per_felt`; without them the rules are unchanged. `PSIParams::log2_fpp_per_bin_bundle` returns `-min(tag_bit_count, 128)` with match tags, as a tag is derived from a 128-bit key, and `SenderDB::log2_fpp` builds on it as before. `PSIParams::to_string` shows the tag part count when there is one.
- Parameters with match tags are serialized with version 2, `PSIParams::tag_serialization_version`, and their tag part count appended to the `PSIParams` table, and a JSON file with match tags must name `"version": 2` at the top level. APSI 1.x refuses both, and with them every `SenderDB` and parameter response holding such parameters, rather than misreading them. Parameters without match tags are written with version 1 and no tag part count, exactly as before. `PSIParams::Load` refuses a version that disagrees with the tag part count, whichever way.
- With match tags, a `SenderDB` stores the tag of every item, labeled or not, as its first label parts, ahead of the parts of its encrypted label. Two items can then share their field elements in a bin, so a `BinBundle` that is not stripped keeps the full `HashedItem` of every item it holds, and every update and removal, and `SenderDB::get_label`, finds an item by that alone. A bin holds up to `max_items_per_bin` items, one more than without match tags, and `Sender::RunQuery` answers with the tag and label results alone. `SenderDB::Load` checks that a saved `BinBundle` has one `HashedItem` for each of its items, but not that they agree with the `SenderDB`'s set of items: a saved `SenderDB` is trusted input, and a crafted one can make queries fail or answer wrongly.
- With match tags, the receiver needs the label keys of its items whether or not the sender's items have labels: `Receiver::request_query`, `Receiver::process_result` and `Receiver::process_result_part` throw `std::invalid_argument` without one per item, `Receiver::request_query` before sending anything. It encodes an empty location of its cuckoo table as `2^item_bit_count_per_felt` in every slot, a value no field element of the sender's can take, instead of zero. It decrypts every ciphertext of every result package, and for each of its items at the package's bundle index compares every field element of the tag and, in labeled mode, decodes and decrypts the label, which it keeps only for a match. The work for a package thus grows with the number of those items but, apart from recording the matches, does not depend on which of them matched. A null result package, or one whose structure does not fit the parameters, aborts the query with `std::runtime_error`, since skipping it could hide a match. The noise budget of the tag results is logged at debug level as "Tag result noise budget".
- Added `util::compute_match_tag`, which derives the tag of an item from its label key, and `oprf::OPRFSender::ComputeHashesAndMatchTags`, which computes OPRF hashes and tags together and wipes the label keys. Added `util::TaggedAlgItemLabel` and `util::algebraize_item_tag_label`, a `tag_part_count` argument to the `BinBundle` constructor, and the `BinBundle` operations for match tags, which take a `TaggedAlgItemLabel` or a `HashedItem`.
- Added `network::Channel::receive_result_for`, which receives a result package for given parameters and refuses, as a failed receive, one that cannot be a result for them; `network::StreamChannel` and `network::ZMQChannel` check the serialized package before loading any ciphertext in it. Added `network::ResultPackage::check_tag_structure`, an overload of `network::ResultPackage::load` that takes the parameters, and `network::ResultPackage::extract_tag_result` and `network::ResultPackage::extract_label_result`, which decrypt the tag parts and the label parts separately.
- Added `Receiver::set_compr_mode`, `Receiver::get_compr_mode` and `Receiver::default_compr_mode`, which select the compression of queries; the sender answers in the mode of the query, as before. `set_compr_mode` accepts any mode the Microsoft SEAL build supports and throws `std::invalid_argument` otherwise. `receiver_cli` takes `--compression` with `none`, `zlib`, `zstd`, or `bitpack`, the default, as far as Microsoft SEAL supports them. Added `network::compr_mode_str`.
- Added `PSIParams::fingerprint`, the Blake2b-256 hash of a canonical encoding of the parameter values that does not depend on how they are serialized, with `PSIParams::Fingerprint` and `PSIParams::fingerprint_byte_count`. A receiver sends it with every query, in `network::SenderOperationQuery::params_fingerprint`, and a sender checks it when it constructs a `sender::Query` and again in `Sender::RunQuery`; `Query::params_fingerprint` and `Query::check_params_fingerprint` expose it. A `SenderDB` with match tags refuses a query without one.
- Added `network::SenderOperationQuery::ExtractParamsFingerprint`, which reads the fingerprint of a serialized query without loading anything else, for an application that serves several `SenderDB`s with different parameters. The fingerprint identifies parameters, not a `SenderDB`.
- Added `BinBundle::multi_contains`, which tells, without changing a `BinBundle`, whether it holds an item.
- Added `util::newton_interpolate_polyns`, which interpolates several value vectors at the same points.

### Hardened

- `network::ResultPackage::load`, with or without parameters, refuses with `std::runtime_error` a result ciphertext that a sender cannot have produced: one that is not in coefficient form, not at the last level of the modulus chain, or of a size other than 2 or 3. It checks each ciphertext as soon as it is loaded, before loading the next. It used to load any ciphertext Microsoft SEAL accepts, of size up to 16 at any level, and since a ciphertext of zeros compresses to almost nothing, a malicious sender could make a receiver hold many times the memory any result takes. Senders, of this version and of earlier ones, give every result in exactly this shape, of size 3 only where the parameters do not allow relinearization, so honest results are unaffected; a test or tool that passes fresh encryptions through `ResultPackage::load` must first mod-switch them to the last level.
- `network::ResultPackage::load` also refuses, before loading any ciphertext, a package whose ciphertexts share bytes, or together take less than 1/64 of what they load to, or that has more label parts than its label and nonce take: for parameters without match tags, `ceil(8 * (label_byte_count + nonce_byte_count) / item_bit_count)`, or none without a label, though fewer are accepted, as by APSI 1.x. Without these checks, a package of 16.5 kB whose label parts all pointed at one ciphertext made a receiver load 770 MB. Given the parameters, it also refuses a package for a bundle index they do not have, so that through `network::StreamChannel` or `network::ZMQChannel` it fails the query, where APSI 1.x ignored it.

### Changed and fixed

- Setting up a labeled `SenderDB` is 2 to 23 times faster with the labeled parameter sets of APSI 1.x. With 8 threads, for example, 131072 items took 8.5 s instead of 198 s with the `1M-256-288` set of APSI 1.x, and a million items 20 s instead of 408 s with its `1M-4096-32`. A `BinBundle` computes the matching polynomial and the label polynomials of a bin together, with one modular inversion per item in the bin, where the Newton interpolation of each label part needed one for every divided difference. The polynomials are the same as before, so neither query results nor the polynomials a saved `SenderDB` holds change. Setup without labels or match tags is unchanged. `util::newton_interpolate_polyn` uses the same method.
- Fixed `SenderDB::insert_or_assign` storing an item a second time when it gave the item a new label. It tried the bin bundles at the item's location from the newest down, and inserted the item into the first that had room even when an older one held it; the old copy kept answering queries, so a receiver kept whichever match arrived first, `SenderDB::get_label` kept returning the old label, and `SenderDB::remove` left the new copy behind. An update now finds the bin bundles that hold the item before changing anything, overwrites the label there, and never inserts.
- A `SenderDB` in which APSI 1.x overwrote labels may hold stale copies of items with their old labels, left by the bug above, and a query for such an item gets either label, depending on which result package the receiver processes first. Overwriting the item again with APSI 2.0 updates every copy and logs a warning naming how many there are; a query then still gets one matching result package per copy, and the receiver keeps the first and logs an error. Removing the item and inserting it again, or rebuilding the `SenderDB` from the source data, removes the stale copies.
- `SenderDB::remove` removed items from the set of items before removing them from the bin bundles, so a removal that failed partway left the two disagreeing, and the bin bundles it had changed with stale caches that refused every later query. It now checks that every item is in the database, and in a bin bundle at each of its locations, before removing anything, and updates the set of items only once the bin bundles are done. It removes every copy of an item, and removes an item given more than once in a batch once, where it threw after applying part of the batch. Removing an item that is not in the database still throws `std::logic_error`, but before anything has been removed.
- Results a sender saves in `none`, `zlib` or `zstd` mode can be read by receivers built with Microsoft SEAL 4.0, which cannot read what Microsoft SEAL 4.1 to 4.4 save: Microsoft SEAL 4.5 and later record in what they save the serialization format version, 4.0 for these results, rather than their own version. A serialized `PSIParams`, or an uncompressed `SenderDB`, without match tags therefore differs from what APSI 1.1.0 writes with Microsoft SEAL 4.4 only in these version bytes, and both versions load both.

### Build

- The configure step reports whether Microsoft SEAL was built with zlib and Zstandard.
- `apsi/util/match_tag.h` is installed with the other headers.

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

- `APSI_SECURE_COMPILE_OPTIONS` now hardens the build rather than doing nothing, and defaults to ON. GCC and Clang get stack protection, position-independent code and bounds-checked standard library containers, together with fortified libc calls and stack-clash protection away from Apple platforms and full RELRO with a non-executable stack on ELF targets; MSVC gets Control Flow Guard, the Spectre variant 1 mitigation, EH continuation metadata on a 64-bit target, and shadow-stack marking on x64. See [Build Hardening](README.md#build-hardening) for what each toolchain receives. The options are not exported, so a consumer chooses its own.
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
