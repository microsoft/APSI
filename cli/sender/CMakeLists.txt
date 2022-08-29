# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
# link_directories(/opt/homebrew/Cellar/flatbuffers/2.0.6/lib)

target_sources(sender_cli
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/sender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sender_utils.cpp
)
# target_link_libraries(sender_cli flatbuffers)