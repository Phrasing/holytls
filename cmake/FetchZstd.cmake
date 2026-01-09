# Fetch and build zstd

include(FetchContent)

message(STATUS "Fetching zstd...")

FetchContent_Declare(
  zstd
  GIT_REPOSITORY https://github.com/facebook/zstd.git
  GIT_TAG        v1.5.6
  GIT_SHALLOW    TRUE
  GIT_PROGRESS   TRUE
  SOURCE_SUBDIR  build/cmake
)

# Set zstd options before fetching
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(zstd)

# Create an alias target for consistent naming
add_library(zstd::zstd ALIAS libzstd_static)

# Export include directory
get_target_property(ZSTD_INCLUDE_DIR libzstd_static INTERFACE_INCLUDE_DIRECTORIES)
message(STATUS "zstd configured (zstd::zstd)")
message(STATUS "zstd include dir: ${ZSTD_INCLUDE_DIR}")
