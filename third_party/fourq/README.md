# FourQlib reference implementation

This directory contains the upstream-vendored Microsoft FourQlib reference
implementation used by APSI's OPRF (`common/apsi/oprf/ecpoint.cpp`).

- **Upstream:** https://github.com/microsoft/FourQlib
- **Pinned commit:** see `cgmanifest.json` in this directory.
- **License:** the upstream files carry their own MIT copyright headers; do not
  re-license.

The sources are pristine upstream plus [`apsi-changes.patch`](apsi-changes.patch),
and nothing else. Re-pinning is therefore: copy the new sources from
`FourQ_64bit_and_portable/` over this directory, then apply that patch. Its
header explains each change and how much it matters; read it before bumping the
pinned commit. Reversing it reproduces the upstream sources byte for byte, which
is the check to run afterwards:

```
git apply --check --reverse third_party/fourq/apsi-changes.patch
```

Do not reformat these files. They are excluded from clang-format and clang-tidy,
and reformatting would bury the real delta in thousands of lines of noise, which
is what makes a transcription error in a constant table invisible.

Only the subset APSI compiles is vendored, so upstream files that nothing here
calls are absent rather than carried dead. The `AMD64/`, `ARM64/` and `generic/`
directories hold arch-specific field arithmetic and are selected at configure
time. `CMakeLists.txt` copies the headers to
`${CMAKE_BINARY_DIR}/common/apsi/fourq/` at configure time, which is how the
`apsi/fourq/` include prefix resolves.

## Two things that look like bugs and are not

GCC reports `'fp2neg1271' accessing 32 bytes in a region of size 16` in `decode`
(`crypto_util.c`) on every build. It is a false positive, and it is upstream's
shape rather than anything APSI changed. Passing `P->x[0]`, which is one 16-byte
`felm_t`, to `mod1271` narrows what GCC believes is reachable through `P->x`, so
the 32-byte `f2elm_t` access that follows looks like an overrun. `P->x` is a whole
`f2elm_t` in every caller, so those 32 bytes are always there. Reducing only the
first half, which is what upstream does, is enough on its own to provoke it, and
it reproduces in nine lines that contain no FourQ code: declare the `felm_t`,
`f2elm_t` and `point_affine` types, call a `felm_t` function on `P->x[0]`, then
call an `f2elm_t` function on `P->x`.

Microsoft SEAL also declares `uint128_t`, as `unsigned __int128`, wherever it has
`__int128`. The generic implementation here declares that same name as
`uint64_t[2]`, so a translation unit including both will not compile where both
apply, and `common/apsi/oprf/ecpoint.cpp` includes both. No configuration APSI
builds reaches it: the generic implementation is selected for ARM64 Windows,
which builds with MSVC, where SEAL declares no `uint128_t` at all, and for 32-bit
x86, which has no `__int128` either. It would collide only if the generic
implementation were built by GCC or Clang for a 64-bit target.
