# Fetch picohttpparser (tiny HTTP parser)

include(FetchContent)

message(STATUS "Fetching picohttpparser...")

FetchContent_Declare(
  picohttpparser
  GIT_REPOSITORY https://github.com/h2o/picohttpparser.git
  GIT_TAG        master
  GIT_SHALLOW    TRUE
  GIT_PROGRESS   TRUE
)

FetchContent_MakeAvailable(picohttpparser)

# picohttpparser is just 2 files - create a static library
add_library(picohttpparser STATIC
  ${picohttpparser_SOURCE_DIR}/picohttpparser.c
)

# Make include directory available to all consumers
target_include_directories(picohttpparser
  PUBLIC
    $<BUILD_INTERFACE:${picohttpparser_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

# Alias for consistent naming
add_library(picohttpparser::picohttpparser ALIAS picohttpparser)

message(STATUS "picohttpparser configured (picohttpparser::picohttpparser)")
