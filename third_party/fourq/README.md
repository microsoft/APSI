# FourQlib reference implementation

This directory contains the upstream-vendored Microsoft FourQlib reference
implementation used by APSI's OPRF (`common/apsi/oprf/ecpoint.cpp`).

- **Upstream:** https://github.com/microsoft/FourQlib
- **Pinned commit:** see `cgmanifest.json` in this directory.
- **License:** the upstream files carry their own MIT copyright headers; do not
  re-license.

These files are vendored with minor APSI-specific edits — primarily, internal
`#include` paths use the `apsi/fourq/` prefix (e.g., `#include
"apsi/fourq/FourQ_internal.h"`) so that the headers resolve through APSI's
mirrored build-tree layout (see `CMakeLists.txt`). Files in `amd64/`, `arm64/`,
and `generic/` are arch-specific field-arithmetic implementations selected at
configure time.

These files are excluded from project-wide clang-tidy via the per-directory
`.clang-tidy` in `third_party/`, and from project-wide clang-format by virtue
of not being added to the formatter's input list.
