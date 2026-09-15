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
