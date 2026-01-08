# Fetch and build libuv

include(FetchContent)

message(STATUS "Fetching libuv...")

FetchContent_Declare(
  libuv
  GIT_REPOSITORY https://github.com/libuv/libuv.git
  GIT_TAG        v1.48.0
  GIT_SHALLOW    TRUE
  GIT_PROGRESS   TRUE
)

# Set libuv options before fetching
set(LIBUV_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LIBUV_BUILD_BENCH OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(libuv)

# Create an alias target for consistent naming
add_library(libuv::libuv ALIAS uv_a)

message(STATUS "libuv configured successfully")
