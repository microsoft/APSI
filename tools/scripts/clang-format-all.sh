#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

BASE_DIR=$(dirname "$0")
APSI_ROOT_DIR=$BASE_DIR/../../
shopt -s globstar
clang-format -i $APSI_ROOT_DIR/common/**/*.h
clang-format -i $APSI_ROOT_DIR/common/**/*.cpp
clang-format -i $APSI_ROOT_DIR/receiver/**/*.h
clang-format -i $APSI_ROOT_DIR/receiver/**/*.cpp
clang-format -i $APSI_ROOT_DIR/sender/**/*.h
clang-format -i $APSI_ROOT_DIR/sender/**/*.cpp
clang-format -i $APSI_ROOT_DIR/tests/**/*.h
clang-format -i $APSI_ROOT_DIR/tests/**/*.cpp