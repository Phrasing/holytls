cmake_minimum_required(VERSION 3.20)

# Enable new MSVC runtime library selection (must be before project())
cmake_policy(SET CMP0091 NEW)

# Use static MSVC runtime (/MT instead of /MD) for standalone executables
# Must be set before project() to affect all targets including dependencies
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project(holytls VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build type defaults to Release
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to 'Release' as none was specified.")
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# Options
option(HOLYTLS_BUILD_TESTS "Build tests" ON)
option(HOLYTLS_BUILD_BENCHMARKS "Build benchmarks" ON)
option(HOLYTLS_ASAN "Enable AddressSanitizer" OFF)
option(HOLYTLS_TSAN "Enable ThreadSanitizer" OFF)

# Include custom cmake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(CompilerFlags)
include(FetchBoringSSL)
include(FetchNghttp2)
include(FetchLibuv)
include(FetchZstd)
include(FetchBrotli)
include(FetchZlib)
include(FetchRapidJSON)
include(FetchPicoHTTPParser)

# Find threading library (cross-platform)
find_package(Threads REQUIRED)

# Main library
add_library(holytls STATIC
  src/holytls/core/reactor.cc
  src/holytls/core/reactor_manager.cc
  src/holytls/core/timer.cc
  src/holytls/core/io_buffer.cc
  src/holytls/core/connection.cc
  src/holytls/util/socket_utils.cc
  src/holytls/memory/slab_allocator.cc
  src/holytls/memory/buffer_pool.cc
  src/holytls/tls/tls_context.cc
  src/holytls/tls/tls_connection.cc
  src/holytls/tls/chrome_profile.cc
  src/holytls/tls/session_cache.cc
  src/holytls/http1/h1_session.cc
  src/holytls/http2/h2_session.cc
  src/holytls/http2/h2_stream.cc
  src/holytls/http2/chrome_h2_profile.cc
  src/holytls/http2/chrome_header_profile.cc
  src/holytls/http2/sec_ch_ua.cc
  src/holytls/http2/chrome_header_builder.cc
  src/holytls/http2/header_ids.cc
  src/holytls/http2/packed_headers.cc
  src/holytls/pool/connection_pool.cc
  src/holytls/pool/host_pool.cc
  src/holytls/client/http_client.cc
  src/holytls/util/dns_resolver.cc
  src/holytls/util/url_parser.cc
  src/holytls/util/decompressor.cc
  src/holytls/util/async_decompressor.cc
  src/holytls/util/platform.cc
)

target_include_directories(holytls
  PUBLIC
    ${CMAKE_SOURCE_DIR}/include
  PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(holytls
  PUBLIC
    boringssl::ssl
    boringssl::crypto
    nghttp2::nghttp2
    libuv::libuv
    Threads::Threads
  PRIVATE
    brotli::brotlidec
    brotli::brotlicommon
    zstd::zstd
    zlib::zlib
  PUBLIC
    picohttpparser::picohttpparser
)

# Platform-specific libraries
if(WIN32)
  target_link_libraries(holytls PUBLIC ws2_32 iphlpapi crypt32)
endif()

# Apply our strict compiler flags only to our code
target_compile_options(holytls PRIVATE ${HOLYTLS_COMMON_FLAGS})

# Windows-specific compile definitions to prevent header conflicts
if(WIN32)
  target_compile_definitions(holytls
    PUBLIC
      WIN32_LEAN_AND_MEAN  # Exclude rarely-used Windows headers
      NOMINMAX             # Prevent Windows from defining min/max macros
      NOGDI                # Prevent GDI definitions
      _CRT_SECURE_NO_WARNINGS  # Disable MSVC secure function warnings
  )
endif()

# Tests
if(HOLYTLS_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# Benchmarks
if(HOLYTLS_BUILD_BENCHMARKS)
  add_executable(bench_core bench/bench_core.cc)
  target_include_directories(bench_core PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/bench
  )
  target_link_libraries(bench_core PRIVATE holytls)
  if(MSVC)
    target_compile_options(bench_core PRIVATE /O2)
  else()
    target_compile_options(bench_core PRIVATE -O3 -march=native)
  endif()
endif()

# Examples
add_executable(fingerprint_check examples/fingerprint_check.cc)
target_include_directories(fingerprint_check PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(fingerprint_check PRIVATE holytls)
target_compile_options(fingerprint_check PRIVATE ${HOLYTLS_COMMON_FLAGS})

add_executable(async_example examples/async_example.cc)
target_link_libraries(async_example PRIVATE holytls)
target_compile_options(async_example PRIVATE ${HOLYTLS_COMMON_FLAGS})

add_executable(custom_headers_example examples/custom_headers_example.cc)
target_link_libraries(custom_headers_example PRIVATE holytls)
target_compile_options(custom_headers_example PRIVATE ${HOLYTLS_COMMON_FLAGS})

add_executable(fingerprint_verify examples/fingerprint_verify.cc)
target_link_libraries(fingerprint_verify PRIVATE holytls rapidjson::rapidjson)
# RapidJSON headers have const-assignment issues with strict flags, use relaxed flags
if(MSVC)
  target_compile_options(fingerprint_verify PRIVATE /W3)
else()
  target_compile_options(fingerprint_verify PRIVATE -Wall -Wextra -Wno-error)
endif()

add_executable(http1_test examples/http1_test.cc)
target_link_libraries(http1_test PRIVATE holytls)
target_compile_options(http1_test PRIVATE ${HOLYTLS_COMMON_FLAGS})

# Install targets
install(TARGETS holytls
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(DIRECTORY include/holytls
  DESTINATION include
)
