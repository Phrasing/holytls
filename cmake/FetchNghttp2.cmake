# Fetch and build nghttp2 HTTP/2 library

include(FetchContent)

message(STATUS "Fetching nghttp2...")

FetchContent_Declare(
  nghttp2
  GIT_REPOSITORY https://github.com/nghttp2/nghttp2.git
  GIT_TAG        v1.64.0
  GIT_SHALLOW    TRUE
  GIT_PROGRESS   TRUE
)

FetchContent_GetProperties(nghttp2)
if(NOT nghttp2_POPULATED)
  FetchContent_Populate(nghttp2)

  # Force static library build - must use CACHE INTERNAL to override option() defaults
  set(ENABLE_LIB_ONLY ON CACHE INTERNAL "")
  set(ENABLE_STATIC_LIB ON CACHE INTERNAL "")
  set(ENABLE_SHARED_LIB OFF CACHE INTERNAL "")
  set(ENABLE_DOC OFF CACHE INTERNAL "")
  set(ENABLE_EXAMPLES OFF CACHE INTERNAL "")
  set(ENABLE_FAILMALLOC OFF CACHE INTERNAL "")
  set(ENABLE_HTTP3 OFF CACHE INTERNAL "")
  set(ENABLE_APP OFF CACHE INTERNAL "")
  set(ENABLE_HPACK_TOOLS OFF CACHE INTERNAL "")
  set(ENABLE_ASIO_LIB OFF CACHE INTERNAL "")
  set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
  set(BUILD_STATIC_LIBS ON CACHE INTERNAL "")

  add_subdirectory(${nghttp2_SOURCE_DIR} ${nghttp2_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

# nghttp2 creates nghttp2_static when ENABLE_STATIC_LIB is ON
if(TARGET nghttp2_static)
  if(NOT TARGET nghttp2::nghttp2)
    add_library(nghttp2::nghttp2 ALIAS nghttp2_static)
  endif()
  message(STATUS "nghttp2 configured (static library: nghttp2_static)")
elseif(TARGET nghttp2)
  # If only shared was built, we still need to use it (will require DLL)
  if(NOT TARGET nghttp2::nghttp2)
    add_library(nghttp2::nghttp2 ALIAS nghttp2)
  endif()
  message(STATUS "nghttp2 configured (shared library: nghttp2)")
else()
  message(FATAL_ERROR "nghttp2 target not found")
endif()

message(STATUS "nghttp2 include dir: ${nghttp2_SOURCE_DIR}/lib/includes")
