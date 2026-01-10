# Fetch and build zlib as static library

include(FetchContent)

message(STATUS "Fetching zlib...")

FetchContent_Declare(
  zlib
  GIT_REPOSITORY https://github.com/madler/zlib.git
  GIT_TAG        v1.3.1
  GIT_SHALLOW    TRUE
  GIT_PROGRESS   TRUE
)

FetchContent_MakeAvailable(zlib)

# zlib creates 'zlibstatic' target for static library
# Create alias for consistent naming
if(TARGET zlibstatic)
  add_library(zlib::zlib ALIAS zlibstatic)
  # Ensure include directories are set
  target_include_directories(zlibstatic PUBLIC
    $<BUILD_INTERFACE:${zlib_SOURCE_DIR}>
    $<BUILD_INTERFACE:${zlib_BINARY_DIR}>
  )
  message(STATUS "zlib configured (zlib::zlib via zlibstatic)")
elseif(TARGET zlib)
  # Some versions might create 'zlib' target
  add_library(zlib::zlib ALIAS zlib)
  message(STATUS "zlib configured (zlib::zlib)")
else()
  message(FATAL_ERROR "zlib target not found after FetchContent")
endif()
