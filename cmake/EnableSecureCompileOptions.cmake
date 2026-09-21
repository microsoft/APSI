# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Security hardening for the code built in this tree. The options are directory-scoped so that they
# reach the vendored FourQ sources and the CLI and test executables alike, and they are deliberately
# not part of the installed target's interface: a consumer chooses its own.
#
# APSI installs a static library, so every link-stage option here applies only to the executables
# built in this tree. Control Flow Guard is the one to know about: the compile flag instruments the
# objects, but enforcement comes from the final link, which for a consumer of the installed library
# is theirs to pass.

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckCXXSourceCompiles)

# Probes whether the compiler truly honors a flag. Warnings count as rejection, because a compiler
# that parses a flag and then ignores it reports only an unused argument: Clang does this with
# -fstack-clash-protection on AArch64, and MSVC does it with /Qspectre when the Spectre-mitigated
# runtime libraries are not installed. Taking such a flag warns on every source file and hardens
# nothing.
function(apsi_check_compile_option flag out_var)
    set(saved_flags "${CMAKE_REQUIRED_FLAGS}")
    if(MSVC)
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} /WX")
    else()
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -Werror")
    endif()
    check_cxx_compiler_flag("${flag}" ${out_var})
    set(CMAKE_REQUIRED_FLAGS "${saved_flags}")
    set(${out_var} ${${out_var}} PARENT_SCOPE)
endfunction()

if(MSVC)
    # Control Flow Guard.
    add_compile_options(/guard:cf)
    add_link_options(/guard:cf)

    # Spectre variant 1 mitigation. This needs a Visual Studio component of its own, and the probe
    # above rejects the flag when that component is missing.
    apsi_check_compile_option(/Qspectre APSI_HAS_QSPECTRE)
    if(APSI_HAS_QSPECTRE)
        add_compile_options(/Qspectre)
    endif()

    # The two options below depend on the target, and neither the generator platform variables nor
    # check_linker_flag can gate them reliably on MSVC, so each probe asks the compiler's own target
    # macros and rejects everything it does not name.
    check_cxx_source_compiles("
#if defined(_M_X64) || defined(_M_ARM64) || defined(_M_ARM64EC)
int main() { return 0; }
#else
#error Not a 64-bit target.
#endif
" APSI_MSVC_TARGET_IS_64BIT)

    # EH continuation metadata, which matters here because APSI unwinds across the C boundary of
    # the vendored FourQ sources.
    if(APSI_MSVC_TARGET_IS_64BIT)
        apsi_check_compile_option(/guard:ehcont APSI_HAS_GUARD_EHCONT)
        if(APSI_HAS_GUARD_EHCONT)
            add_compile_options(/guard:ehcont)
            add_link_options(/guard:ehcont)
        endif()
    endif()

    # Shadow-stack marking is x64 only. ARM64EC has to be excluded by name because it defines
    # _M_X64 as well, being x64-compatible by design.
    check_cxx_source_compiles("
#if defined(_M_X64) && !defined(_M_ARM64EC)
int main() { return 0; }
#else
#error Not an x64 target.
#endif
" APSI_MSVC_TARGET_IS_X64)

    if(APSI_MSVC_TARGET_IS_X64)
        add_link_options(/CETCOMPAT)
    endif()
else()
    # Gate the compile flags to the C-family languages so that they reach the vendored FourQ C
    # sources as well as APSI's own C++.
    set(APSI_C_FAMILY_LANGS "$<COMPILE_LANGUAGE:C,CXX>")

    # Stack canaries.
    add_compile_options($<${APSI_C_FAMILY_LANGS}:-fstack-protector-strong>)

    # Stack-clash protection. Apple Clang accepts the flag and ignores it, so it is skipped there
    # rather than warning on every source file; elsewhere the probe covers compilers too old for it.
    if(NOT APPLE)
        apsi_check_compile_option(-fstack-clash-protection APSI_HAS_STACK_CLASH_PROTECTION)
        if(APSI_HAS_STACK_CLASH_PROTECTION)
            add_compile_options($<${APSI_C_FAMILY_LANGS}:-fstack-clash-protection>)
        endif()
    endif()

    # Position-independent code, so that a consumer may link the static library into a shared one.
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)

    # Bounds-checked standard library containers, outside Debug where the containers check anyway.
    add_compile_definitions(
        $<$<AND:$<NOT:$<CONFIG:Debug>>,${APSI_C_FAMILY_LANGS}>:_GLIBCXX_ASSERTIONS>
        $<$<AND:$<NOT:$<CONFIG:Debug>>,${APSI_C_FAMILY_LANGS}>:_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST>)

    # Full RELRO, immediate binding, and a non-executable stack. ELF only.
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Android")
        add_link_options(-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
    endif()

    # Fortified libc calls. These need an optimizing build, and warn when the toolchain has defined
    # the macro already, so the macro is undefined first and left out of Debug. Apple's libc does
    # not implement the fortified entry points, so it is skipped there.
    if(NOT APPLE)
        add_compile_options(
            $<$<AND:$<NOT:$<CONFIG:Debug>>,${APSI_C_FAMILY_LANGS}>:-U_FORTIFY_SOURCE>)
        add_compile_definitions(
            $<$<AND:$<NOT:$<CONFIG:Debug>>,${APSI_C_FAMILY_LANGS}>:_FORTIFY_SOURCE=2>)
    endif()
endif()
