# Fetch and build nghttp3 - HTTP/3 library
# nghttp3 provides HTTP/3 protocol implementation on top of QUIC
# Works with ngtcp2 for the underlying QUIC transport

include(FetchContent)

message(STATUS "Fetching nghttp3...")

FetchContent_Declare(
  nghttp3
  GIT_REPOSITORY https://github.com/ngtcp2/nghttp3.git
  GIT_TAG        v1.6.0
  GIT_SHALLOW    TRUE
  GIT_PROGRESS   TRUE
)

FetchContent_GetProperties(nghttp3)
if(NOT nghttp3_POPULATED)
  FetchContent_Populate(nghttp3)

  # Configure nghttp3 build options
  set(ENABLE_SHARED_LIB OFF CACHE BOOL "" FORCE)
  set(ENABLE_STATIC_LIB ON CACHE BOOL "" FORCE)
  set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
  set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)

  # Patch CMakeLists.txt to rename "check" target that conflicts with nghttp2
  file(READ "${nghttp3_SOURCE_DIR}/CMakeLists.txt" _nghttp3_cmake_content)
  string(REPLACE
    "add_custom_target(check COMMAND"
    "add_custom_target(nghttp3_check COMMAND"
    _nghttp3_cmake_content "${_nghttp3_cmake_content}")
  file(WRITE "${nghttp3_SOURCE_DIR}/CMakeLists.txt" "${_nghttp3_cmake_content}")

  add_subdirectory(${nghttp3_SOURCE_DIR} ${nghttp3_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

# Create alias targets for consistency
if(TARGET nghttp3_static)
  add_library(nghttp3::nghttp3 ALIAS nghttp3_static)
endif()

message(STATUS "nghttp3 configured")
