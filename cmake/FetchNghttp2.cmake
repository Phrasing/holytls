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

  # Configure nghttp2 - library only, no tools
  set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
  set(ENABLE_STATIC_LIB ON CACHE BOOL "" FORCE)
  set(ENABLE_SHARED_LIB OFF CACHE BOOL "" FORCE)
  set(ENABLE_DOC OFF CACHE BOOL "" FORCE)
  set(ENABLE_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(ENABLE_FAILMALLOC OFF CACHE BOOL "" FORCE)
  set(ENABLE_HTTP3 OFF CACHE BOOL "" FORCE)
  set(ENABLE_APP OFF CACHE BOOL "" FORCE)
  set(ENABLE_HPACK_TOOLS OFF CACHE BOOL "" FORCE)
  set(ENABLE_ASIO_LIB OFF CACHE BOOL "" FORCE)

  add_subdirectory(${nghttp2_SOURCE_DIR} ${nghttp2_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

# nghttp2 creates different targets for static/shared
# We want static to avoid DLL dependencies on Windows
if(TARGET nghttp2_static)
  # Use static library target
  if(NOT TARGET nghttp2::nghttp2)
    add_library(nghttp2::nghttp2 ALIAS nghttp2_static)
  endif()
  message(STATUS "nghttp2 configured (static library)")
elseif(TARGET nghttp2::nghttp2)
  message(STATUS "nghttp2 configured (nghttp2::nghttp2)")
elseif(TARGET nghttp2)
  # Older versions might just have 'nghttp2' target
  add_library(nghttp2::nghttp2 ALIAS nghttp2)
  message(STATUS "nghttp2 configured (aliased from nghttp2)")
else()
  message(FATAL_ERROR "nghttp2 target not found")
endif()

message(STATUS "nghttp2 include dir: ${nghttp2_SOURCE_DIR}/lib/includes")
