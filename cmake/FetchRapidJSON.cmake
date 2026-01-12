# Fetch RapidJSON (header-only)

include(FetchContent)

message(STATUS "Fetching RapidJSON...")

FetchContent_Declare(
  rapidjson
  GIT_REPOSITORY https://github.com/Tencent/rapidjson.git
  GIT_TAG        master
  GIT_SHALLOW    TRUE
  GIT_PROGRESS   TRUE
)

# RapidJSON options
set(RAPIDJSON_BUILD_DOC OFF CACHE BOOL "" FORCE)
set(RAPIDJSON_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(RAPIDJSON_BUILD_TESTS OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(rapidjson)

# Create interface library for header-only usage
add_library(rapidjson::rapidjson INTERFACE IMPORTED GLOBAL)
set_target_properties(rapidjson::rapidjson PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${rapidjson_SOURCE_DIR}/include"
)

message(STATUS "RapidJSON configured (rapidjson::rapidjson)")
