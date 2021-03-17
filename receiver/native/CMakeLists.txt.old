# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Create the CMake config file
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${PROJECT_CONFIG_IN_FILENAME} ${PROJECT_CONFIG_FILENAME}
    INSTALL_DESTINATION ${PROJECT_CONFIG_INSTALL_DIR})

# Export the targets
export(EXPORT APSIReceiverTargets
    FILE ${PROJECT_TARGETS_FILENAME}
    NAMESPACE APSI::)

# Create the CMake config file
configure_file(${PROJECT_CONFIG_IN_FILENAME} ${PROJECT_CONFIG_FILENAME} @ONLY)

# Install the export
install(
    EXPORT APSIReceiverTargets
    NAMESPACE APSI::
    DESTINATION ${PROJECT_CONFIG_INSTALL_DIR})

# Version file; we require exact version match for downstream
write_basic_package_version_file(
    ${PROJECT_CONFIG_VERSION_FILENAME}
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY ExactVersion)

# Install config and module files
install(
    FILES
        ${PROJECT_CONFIG_FILENAME}
        ${PROJECT_CONFIG_VERSION_FILENAME}
    DESTINATION ${PROJECT_CONFIG_INSTALL_DIR})

# We export APSIReceiverTargets from the build tree so it can be used by other projects
# without requiring an install.
export(
    EXPORT APSIReceiverTargets
    NAMESPACE APSI::
    FILE ${PROJECT_TARGETS_FILENAME})
