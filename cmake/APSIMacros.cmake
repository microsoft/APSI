# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Set the C++ language version
macro(apsi_set_language target)
    if(APSI_USE_CXX17)
        target_compile_features(${target} PUBLIC cxx_std_17)
    else()
        target_compile_features(${target} PUBLIC cxx_std_14)
    endif()
endmacro()

# Set the VERSION property
macro(apsi_set_version target)
    set_target_properties(${target} PROPERTIES VERSION ${APSI_VERSION})
endmacro()

# Set the library filename to reflect version
macro(apsi_set_version_filename target)
    set_target_properties(${target} PROPERTIES OUTPUT_NAME ${target}-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
endmacro()

# Set the SOVERSION property
macro(apsi_set_soversion target)
    set_target_properties(${target} PROPERTIES SOVERSION ${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
endmacro()

# Link a thread library
macro(apsi_link_threads target)
    # Require thread library
    if(NOT TARGET Threads::Threads)
        set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
        set(THREADS_PREFER_PTHREAD_FLAG TRUE)
        find_package(Threads REQUIRED)
    endif()

    # Link Threads
    target_link_libraries(${target} PUBLIC Threads::Threads)
endmacro()

# Include target to given export
macro(apsi_install_target target export)
    install(TARGETS ${target} EXPORT ${export}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endmacro()

# Add secure compile options
macro(apsi_set_secure_compile_options target scope)
    if(MSVC)
        # Build debug symbols for static analysis tools
        target_link_options(${target} ${scope} /DEBUG)

        # Control Flow Guard / Spectre
        target_compile_options(${target} ${scope} /guard:cf)
        target_compile_options(${target} ${scope} /Qspectre)
        target_link_options(${target} ${scope} /guard:cf)
        target_link_options(${target} ${scope} /DYNAMICBASE)
    endif()
endmacro()
