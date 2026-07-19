#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

BASE_DIR=$(dirname "$0")
APSI_ROOT_DIR=$(cd "$BASE_DIR/../.." && pwd)

# Format all C/C++ sources and headers, skipping vendored code under third_party/.
find "$APSI_ROOT_DIR" \
    -type d -name third_party -prune -o \
    -type f \( -name '*.h' -o -name '*.c' -o -name '*.cpp' \) -print0 |
    xargs -0 clang-format -i
