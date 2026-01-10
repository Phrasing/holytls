# Fetch and build brotli as static library

include(FetchContent)

message(STATUS "Fetching brotli...")

FetchContent_Declare(
  brotli
  GIT_REPOSITORY https://github.com/google/brotli.git
  GIT_TAG        v1.1.0
  GIT_SHALLOW    TRUE
  GIT_PROGRESS   TRUE
)

# Disable brotli tests and shared libs
set(BROTLI_DISABLE_TESTS ON CACHE BOOL "" FORCE)
set(BROTLI_BUNDLED_MODE ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(brotli)

# Create alias targets for consistent naming
# brotli builds: brotlicommon, brotlidec, brotlienc (static by default with BUNDLED_MODE)
add_library(brotli::brotlidec ALIAS brotlidec)
add_library(brotli::brotlicommon ALIAS brotlicommon)

message(STATUS "brotli configured (brotli::brotlidec)")
