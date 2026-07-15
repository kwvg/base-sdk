# Builds the dashpkc C++ library: the dash-pkc-cxx Rust staticlib
# (BLS features only) plus the compiled C++20 wrapper, merged into
# one installed archive (libdash_pkc.a) with the public headers
# under include/dashpkc.
#
# Cross builds (e.g. Dash Core's depends system) parameterize the
# cargo invocation:
#   -DDASH_PKC_CARGO=/path/to/cargo   cargo executable
#   -DDASH_PKC_RUST_TARGET=<triple>   rust target (aarch64-apple-darwin, ...)
#   -DDASH_PKC_VENDOR_DIR=<dir>       vendored crates; enables --offline
#   -DDASH_PKC_MACOS_MIN=<ver>        MACOSX_DEPLOYMENT_TARGET for cargo
cmake_minimum_required(VERSION 3.20)
project(dash_pkc VERSION 0.0.0 LANGUAGES C CXX)

option(DASH_PKC_PORTABLE "Use blst's portable backend (no ADX autodetect); required for distributable x86_64 binaries" OFF)
option(DASH_PKC_BUILD_TESTS "Build the Boost.Test suites (needs Boost headers)" ON)
option(DASH_PKC_BUILD_EXAMPLES "Build the example applications" ON)
set(DASH_PKC_CARGO "cargo" CACHE STRING "cargo executable used to build the Rust staticlib")
set(DASH_PKC_RUST_TARGET "" CACHE STRING "Rust target triple; empty builds for the build machine")
set(DASH_PKC_VENDOR_DIR "" CACHE PATH "Directory of vendored crates; enables offline cargo builds")
set(DASH_PKC_MACOS_MIN "" CACHE STRING "Minimum macOS version exported as MACOSX_DEPLOYMENT_TARGET")

set(DASH_PKC_CXX_DIR ${CMAKE_CURRENT_SOURCE_DIR}/pkgs/pkc/binds/cxx)

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
    ${DASH_PKC_RUST_LIB_DIR}/${DASH_PKC_CARGO_PROFILE_DIR}/libdash_pkc_cxx.a)

# Always invoke cargo; it is a fast no-op when nothing changed and
# tracks the Rust source dependencies itself.
add_custom_target(dash_pkc_cargo
  COMMAND ${CMAKE_COMMAND} -E env ${DASH_PKC_CARGO_ENV}
          ${DASH_PKC_CARGO} build ${DASH_PKC_CARGO_PROFILE_FLAG} -p dash-pkc-cxx ${DASH_PKC_CARGO_ARGS}
  BYPRODUCTS ${DASH_PKC_RUST_LIB}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "cargo build dash-pkc-cxx (${DASH_PKC_CARGO_PROFILE_DIR})"
  VERBATIM)

# The compiled C++20 wrapper. The diplomat-generated headers under
# src/diplomat are a private implementation detail.
add_library(dash_pkc_wrapper STATIC
  ${DASH_PKC_CXX_DIR}/src/elements.cpp
  ${DASH_PKC_CXX_DIR}/src/expected.cpp
  ${DASH_PKC_CXX_DIR}/src/ies.cpp
  ${DASH_PKC_CXX_DIR}/src/privatekey.cpp
  ${DASH_PKC_CXX_DIR}/src/schemes.cpp
  ${DASH_PKC_CXX_DIR}/src/session.cpp
  ${DASH_PKC_CXX_DIR}/src/threshold.cpp)
target_compile_features(dash_pkc_wrapper PUBLIC cxx_std_20)
target_include_directories(dash_pkc_wrapper
  PUBLIC $<BUILD_INTERFACE:${DASH_PKC_CXX_DIR}/include> $<INSTALL_INTERFACE:include>
  PRIVATE ${DASH_PKC_CXX_DIR}/src)
add_dependencies(dash_pkc_wrapper dash_pkc_cargo)

# Merge the Rust core and the wrapper into one archive so consumers
# link a single -ldash_pkc.
set(DASH_PKC_MERGED_LIB ${CMAKE_BINARY_DIR}/libdash_pkc.a)
if(APPLE)
  set(DASH_PKC_MERGE_COMMAND
      libtool -static -o ${DASH_PKC_MERGED_LIB}
      $<TARGET_FILE:dash_pkc_wrapper> ${DASH_PKC_RUST_LIB})
  add_custom_command(OUTPUT ${DASH_PKC_MERGED_LIB}
    COMMAND ${DASH_PKC_MERGE_COMMAND}
    DEPENDS dash_pkc_wrapper dash_pkc_cargo ${DASH_PKC_RUST_LIB}
    COMMENT "libtool merge libdash_pkc.a"
    VERBATIM)
else()
  set(DASH_PKC_MRI ${CMAKE_BINARY_DIR}/dash_pkc.mri)
  file(GENERATE OUTPUT ${DASH_PKC_MRI} CONTENT
"create ${DASH_PKC_MERGED_LIB}
addlib $<TARGET_FILE:dash_pkc_wrapper>
addlib ${DASH_PKC_RUST_LIB}
save
end
")
  add_custom_command(OUTPUT ${DASH_PKC_MERGED_LIB}
    COMMAND ${CMAKE_AR} -M < ${DASH_PKC_MRI}
    DEPENDS dash_pkc_wrapper dash_pkc_cargo ${DASH_PKC_RUST_LIB} ${DASH_PKC_MRI}
    COMMENT "ar merge libdash_pkc.a"
    VERBATIM)
endif()
add_custom_target(dash_pkc_merged ALL DEPENDS ${DASH_PKC_MERGED_LIB})

# Consumable target for in-tree tests/examples: public headers plus
# the merged archive.
add_library(dash_pkc INTERFACE)
target_compile_features(dash_pkc INTERFACE cxx_std_20)
target_include_directories(dash_pkc INTERFACE
  $<BUILD_INTERFACE:${DASH_PKC_CXX_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_link_libraries(dash_pkc INTERFACE ${DASH_PKC_MERGED_LIB})
if(UNIX AND NOT APPLE)
  target_link_libraries(dash_pkc INTERFACE pthread dl m)
endif()
add_dependencies(dash_pkc dash_pkc_merged)

# Install: the merged library and the public headers (including the
# vendored tl::expected the public API depends on).
include(GNUInstallDirs)
install(FILES ${DASH_PKC_MERGED_LIB} DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY ${DASH_PKC_CXX_DIR}/include/dashpkc
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Minimal CMake package so consumers can find_package(dash_pkc).
include(CMakePackageConfigHelpers)
set(DASH_PKC_CONFIG_IN "\
add_library(dash_pkc::dash_pkc STATIC IMPORTED)\n\
set_target_properties(dash_pkc::dash_pkc PROPERTIES\n\
  IMPORTED_LOCATION \"\${CMAKE_CURRENT_LIST_DIR}/../../libdash_pkc.a\"\n\
  INTERFACE_INCLUDE_DIRECTORIES \"\${CMAKE_CURRENT_LIST_DIR}/../../../${CMAKE_INSTALL_INCLUDEDIR}\"\n\
  INTERFACE_COMPILE_FEATURES cxx_std_20)\n\
if(UNIX AND NOT APPLE)\n\
  set_property(TARGET dash_pkc::dash_pkc APPEND PROPERTY INTERFACE_LINK_LIBRARIES pthread dl m)\n\
endif()\n")
file(GENERATE OUTPUT ${CMAKE_BINARY_DIR}/dash_pkc-config.cmake CONTENT "${DASH_PKC_CONFIG_IN}")
write_basic_package_version_file(${CMAKE_BINARY_DIR}/dash_pkc-config-version.cmake
  VERSION ${PROJECT_VERSION} COMPATIBILITY ExactVersion)
install(FILES ${CMAKE_BINARY_DIR}/dash_pkc-config.cmake ${CMAKE_BINARY_DIR}/dash_pkc-config-version.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/dash_pkc)

if(DASH_PKC_BUILD_TESTS)
  find_path(DASH_PKC_BOOST_INCLUDE boost/test/included/unit_test.hpp)
  if(DASH_PKC_BOOST_INCLUDE)
    enable_testing()
    foreach(suite bls session ies)
      add_executable(dash_pkc_test_${suite} ${DASH_PKC_CXX_DIR}/test/test_${suite}.cpp)
      target_link_libraries(dash_pkc_test_${suite} PRIVATE dash_pkc)
      target_include_directories(dash_pkc_test_${suite} PRIVATE ${DASH_PKC_BOOST_INCLUDE})
      add_test(NAME dash_pkc_test_${suite} COMMAND dash_pkc_test_${suite})
    endforeach()
  else()
    message(STATUS "Boost headers not found; skipping dashpkc tests")
  endif()
endif()

if(DASH_PKC_BUILD_EXAMPLES)
  foreach(demo ies_encrypt llmq_threshold)
    add_executable(dash_pkc_example_${demo} ${DASH_PKC_CXX_DIR}/example/${demo}.cpp)
    target_link_libraries(dash_pkc_example_${demo} PRIVATE dash_pkc)
  endforeach()
endif()
