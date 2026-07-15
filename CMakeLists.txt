# Builds the dash_pkc C++ library: the dash-pkc-binds Rust staticlib
# (BLS features only) plus the header-only C++20 wrapper, installed
# as one combined package (libdash_pkc.a + headers).
#
# Cross builds (e.g. Dash Core's depends system) parameterize the
# cargo invocation instead of the CMake toolchain: the wrapper is
# header-only and the Rust artifact is a staticlib (never linked
# here), so no C/C++ compiler is required unless tests are enabled.
#   -DDASH_PKC_CARGO=/path/to/cargo   cargo executable
#   -DDASH_PKC_RUST_TARGET=<triple>   rust target (aarch64-apple-darwin, ...)
#   -DDASH_PKC_VENDOR_DIR=<dir>       vendored crates; enables --offline
#   -DDASH_PKC_MACOS_MIN=<ver>        MACOSX_DEPLOYMENT_TARGET for cargo
cmake_minimum_required(VERSION 3.20)
project(dash_pkc VERSION 0.0.0 LANGUAGES NONE)

option(DASH_PKC_PORTABLE "Use blst's portable backend (no ADX autodetect); required for distributable x86_64 binaries" OFF)
option(DASH_PKC_BUILD_TESTS "Build the C++ smoke tests" ON)
set(DASH_PKC_CARGO "cargo" CACHE STRING "cargo executable used to build the Rust staticlib")
set(DASH_PKC_RUST_TARGET "" CACHE STRING "Rust target triple; empty builds for the build machine")
set(DASH_PKC_VENDOR_DIR "" CACHE PATH "Directory of vendored crates; enables offline cargo builds")
set(DASH_PKC_MACOS_MIN "" CACHE STRING "Minimum macOS version exported as MACOSX_DEPLOYMENT_TARGET")

set(DASH_PKC_BINDS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/pkgs/pkc/binds)

# Rust staticlib. Only the crate's default (bls) features are ever
# enabled; the workspace release profile adds LTO and panic=abort.
set(DASH_PKC_CARGO_TARGET_DIR ${CMAKE_BINARY_DIR}/cargo)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(DASH_PKC_CARGO_PROFILE_DIR debug)
  set(DASH_PKC_CARGO_PROFILE_FLAG "")
else()
  set(DASH_PKC_CARGO_PROFILE_DIR release)
  set(DASH_PKC_CARGO_PROFILE_FLAG --release)
endif()

set(DASH_PKC_CARGO_ARGS "")
set(DASH_PKC_RUST_LIB_DIR ${DASH_PKC_CARGO_TARGET_DIR})
if(DASH_PKC_RUST_TARGET)
  list(APPEND DASH_PKC_CARGO_ARGS --target ${DASH_PKC_RUST_TARGET})
  set(DASH_PKC_RUST_LIB_DIR ${DASH_PKC_CARGO_TARGET_DIR}/${DASH_PKC_RUST_TARGET})
endif()
if(DASH_PKC_VENDOR_DIR)
  list(APPEND DASH_PKC_CARGO_ARGS --offline
       --config "source.crates-io.replace-with='vendored-sources'"
       --config "source.vendored-sources.directory='${DASH_PKC_VENDOR_DIR}'")
endif()
if(DASH_PKC_PORTABLE)
  list(APPEND DASH_PKC_CARGO_ARGS --features bls-portable)
endif()

set(DASH_PKC_CARGO_ENV CARGO_TARGET_DIR=${DASH_PKC_CARGO_TARGET_DIR})
if(DASH_PKC_MACOS_MIN)
  list(APPEND DASH_PKC_CARGO_ENV MACOSX_DEPLOYMENT_TARGET=${DASH_PKC_MACOS_MIN})
endif()

set(DASH_PKC_RUST_LIB
    ${DASH_PKC_RUST_LIB_DIR}/${DASH_PKC_CARGO_PROFILE_DIR}/libdash_pkc_binds.a)

# Always invoke cargo; it is a fast no-op when nothing changed and
# tracks the Rust source dependencies itself.
add_custom_target(dash_pkc_cargo ALL
  COMMAND ${CMAKE_COMMAND} -E env ${DASH_PKC_CARGO_ENV}
          ${DASH_PKC_CARGO} build ${DASH_PKC_CARGO_PROFILE_FLAG} -p dash-pkc-binds ${DASH_PKC_CARGO_ARGS}
  BYPRODUCTS ${DASH_PKC_RUST_LIB}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "cargo build dash-pkc-binds (${DASH_PKC_CARGO_PROFILE_DIR})"
  VERBATIM)

add_library(dash_pkc_rust STATIC IMPORTED GLOBAL)
set_target_properties(dash_pkc_rust PROPERTIES IMPORTED_LOCATION ${DASH_PKC_RUST_LIB})
add_dependencies(dash_pkc_rust dash_pkc_cargo)

# The C++20 wrapper is header-only: the dash_pkc target carries the
# include paths (wrapper, diplomat-generated, vendored tl::expected)
# and links the Rust staticlib.
add_library(dash_pkc INTERFACE)
target_include_directories(dash_pkc INTERFACE
  $<BUILD_INTERFACE:${DASH_PKC_BINDS_DIR}/include>
  $<BUILD_INTERFACE:${DASH_PKC_BINDS_DIR}/gen>
  $<BUILD_INTERFACE:${DASH_PKC_BINDS_DIR}/third_party>
  $<INSTALL_INTERFACE:include>)
target_link_libraries(dash_pkc INTERFACE dash_pkc_rust)
if(UNIX AND NOT APPLE)
  target_link_libraries(dash_pkc INTERFACE pthread dl m)
endif()

# Install: one combined library plus all headers the wrapper needs.
include(GNUInstallDirs)
install(FILES ${DASH_PKC_RUST_LIB}
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RENAME ${CMAKE_STATIC_LIBRARY_PREFIX}dash_pkc${CMAKE_STATIC_LIBRARY_SUFFIX})
install(DIRECTORY ${DASH_PKC_BINDS_DIR}/include/dash_pkc
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY ${DASH_PKC_BINDS_DIR}/gen/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.hpp")
install(DIRECTORY ${DASH_PKC_BINDS_DIR}/third_party/tl
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Minimal CMake package so consumers can find_package(dash_pkc).
include(CMakePackageConfigHelpers)
set(DASH_PKC_CONFIG_IN "\
include(CMakeFindDependencyMacro)\n\
add_library(dash_pkc::rust STATIC IMPORTED)\n\
set_target_properties(dash_pkc::rust PROPERTIES\n\
  IMPORTED_LOCATION \"\${CMAKE_CURRENT_LIST_DIR}/../../${CMAKE_STATIC_LIBRARY_PREFIX}dash_pkc${CMAKE_STATIC_LIBRARY_SUFFIX}\")\n\
add_library(dash_pkc::dash_pkc INTERFACE IMPORTED)\n\
set_target_properties(dash_pkc::dash_pkc PROPERTIES\n\
  INTERFACE_INCLUDE_DIRECTORIES \"\${CMAKE_CURRENT_LIST_DIR}/../../../${CMAKE_INSTALL_INCLUDEDIR}\"\n\
  INTERFACE_COMPILE_FEATURES cxx_std_20\n\
  INTERFACE_LINK_LIBRARIES dash_pkc::rust)\n\
if(UNIX AND NOT APPLE)\n\
  set_property(TARGET dash_pkc::dash_pkc APPEND PROPERTY INTERFACE_LINK_LIBRARIES pthread dl m)\n\
endif()\n")
file(GENERATE OUTPUT ${CMAKE_BINARY_DIR}/dash_pkc-config.cmake CONTENT "${DASH_PKC_CONFIG_IN}")
write_basic_package_version_file(${CMAKE_BINARY_DIR}/dash_pkc-config-version.cmake
  VERSION ${PROJECT_VERSION} COMPATIBILITY ExactVersion)
install(FILES ${CMAKE_BINARY_DIR}/dash_pkc-config.cmake ${CMAKE_BINARY_DIR}/dash_pkc-config-version.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/dash_pkc)

if(DASH_PKC_BUILD_TESTS)
  enable_language(CXX)
  target_compile_features(dash_pkc INTERFACE cxx_std_20)
  enable_testing()
  add_executable(dash_pkc_smoke_test ${DASH_PKC_BINDS_DIR}/tests/cpp/smoke_test.cpp)
  target_link_libraries(dash_pkc_smoke_test PRIVATE dash_pkc)
  add_test(NAME dash_pkc_smoke_test COMMAND dash_pkc_smoke_test)
endif()
