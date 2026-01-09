cmake_minimum_required(VERSION 3.20)
project(chad-tls VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
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
option(CHAD_BUILD_TESTS "Build tests" ON)
option(CHAD_BUILD_BENCHMARKS "Build benchmarks" ON)
option(CHAD_ASAN "Enable AddressSanitizer" OFF)
option(CHAD_TSAN "Enable ThreadSanitizer" OFF)

# Include custom cmake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(CompilerFlags)
include(FetchBoringSSL)
include(FetchNghttp2)
include(FetchLibuv)

# Find Brotli for certificate compression
find_package(PkgConfig REQUIRED)
pkg_check_modules(BROTLI REQUIRED libbrotlidec)

# Main library
add_library(chad-tls STATIC
  src/core/reactor.cc
  src/core/timer.cc
  src/core/io_buffer.cc
  src/core/connection.cc
  src/util/socket_utils.cc
  src/memory/slab_allocator.cc
  src/memory/buffer_pool.cc
  src/tls/tls_context.cc
  src/tls/tls_connection.cc
  src/tls/chrome_profile.cc
  src/http2/h2_session.cc
  src/http2/h2_stream.cc
  src/http2/chrome_h2_profile.cc
  src/http2/header_ids.cc
  src/http2/packed_headers.cc
  src/pool/connection_pool.cc
  src/pool/host_pool.cc
  src/client/http_client.cc
  src/client/request.cc
  src/client/response.cc
  src/util/dns_resolver.cc
  src/util/url_parser.cc
)

target_include_directories(chad-tls
  PUBLIC
    ${CMAKE_SOURCE_DIR}/include
  PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${BROTLI_INCLUDE_DIRS}
)

target_link_libraries(chad-tls
  PUBLIC
    boringssl::ssl
    boringssl::crypto
    nghttp2::nghttp2
    libuv::libuv
    pthread
  PRIVATE
    ${BROTLI_LIBRARIES}
)

# Apply our strict compiler flags only to our code
target_compile_options(chad-tls PRIVATE ${CHAD_COMMON_FLAGS})

# Main executable
add_executable(chad src/main.cc)
target_include_directories(chad PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(chad PRIVATE chad-tls)
target_compile_options(chad PRIVATE ${CHAD_COMMON_FLAGS})

# Tests
if(CHAD_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# Benchmarks
if(CHAD_BUILD_BENCHMARKS)
  add_executable(bench_core bench/bench_core.cc)
  target_include_directories(bench_core PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/bench
  )
  target_link_libraries(bench_core PRIVATE chad-tls)
  target_compile_options(bench_core PRIVATE -O3 -march=native)
endif()

# Examples
add_executable(fingerprint_check examples/fingerprint_check.cc)
target_include_directories(fingerprint_check PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(fingerprint_check PRIVATE chad-tls)
target_compile_options(fingerprint_check PRIVATE ${CHAD_COMMON_FLAGS})

# Install targets
install(TARGETS chad-tls chad
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(DIRECTORY include/chad
  DESTINATION include
)
