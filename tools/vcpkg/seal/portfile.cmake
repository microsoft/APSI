vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

vcpkg_from_git(
    OUT_SOURCE_PATH SOURCE_PATH
    URL https://msrcrypto@dev.azure.com/msrcrypto/SEAL/_git/SEAL
    REF 6325a24d31cf6d56258cc657b923e1c0c9caf0d9
)

vcpkg_check_features(OUT_FEATURE_OPTIONS FEATURE_OPTIONS
    FEATURES
    ms-gsl SEAL_USE_MSGSL
    zlib SEAL_USE_ZLIB
    zstd SEAL_USE_ZSTD

    INVERTED_FEATURES
    no-throw-tran SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
)

vcpkg_configure_cmake(
    SOURCE_PATH ${SOURCE_PATH}
    PREFER_NINJA
    DISABLE_PARALLEL_CONFIGURE
    OPTIONS
        -DSEAL_BUILD_DEPS=OFF
        -DSEAL_BUILD_EXAMPLES=OFF
        -DSEAL_BUILD_TESTS=OFF
        -DSEAL_BUILD_SEAL_C=OFF
        ${FEATURE_OPTIONS}
)

vcpkg_build_cmake(TARGET seal LOGFILE_ROOT build)

vcpkg_install_cmake()

file(GLOB CONFIG_PATH RELATIVE "${CURRENT_PACKAGES_DIR}" "${CURRENT_PACKAGES_DIR}/lib/cmake/SEAL-*")
if(NOT CONFIG_PATH)
    message(FATAL_ERROR "Could not find installed cmake config files.")
endif()

vcpkg_fixup_cmake_targets(CONFIG_PATH "${CONFIG_PATH}")

vcpkg_fixup_pkgconfig()

file(REMOVE_RECURSE ${CURRENT_PACKAGES_DIR}/debug/include)

# Handle copyright
file(INSTALL ${SOURCE_PATH}/LICENSE DESTINATION ${CURRENT_PACKAGES_DIR}/share/${PORT} RENAME copyright)

vcpkg_copy_pdbs()
