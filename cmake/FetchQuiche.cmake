# Fetch and build Google quiche (via Bilibili's CMake fork)
# This provides QUIC, HTTP/2 (oghttp2), and HTTP/3 support

include(FetchContent)

message(STATUS "Fetching Bilibili/quiche (Google quiche with CMake)...")

# Option to skip quiche (for faster builds during development)
option(HOLYTLS_BUILD_QUICHE "Build with QUIC/HTTP3 support via quiche" ON)

if(NOT HOLYTLS_BUILD_QUICHE)
  message(STATUS "Skipping quiche build (HOLYTLS_BUILD_QUICHE=OFF)")
  return()
endif()

FetchContent_Declare(
  quiche
  GIT_REPOSITORY https://github.com/bilibili/quiche.git
  GIT_TAG        main
  GIT_SHALLOW    TRUE
  GIT_PROGRESS   TRUE
)

FetchContent_GetProperties(quiche)
if(NOT quiche_POPULATED)
  FetchContent_Populate(quiche)

  message(STATUS "Quiche source: ${quiche_SOURCE_DIR}")
  message(STATUS "Quiche binary: ${quiche_BINARY_DIR}")

  # Bilibili's quiche includes its own third_party dependencies
  # We need to initialize git submodules for it
  message(STATUS "Initializing quiche submodules...")
  execute_process(
    COMMAND git submodule update --init --recursive
    WORKING_DIRECTORY ${quiche_SOURCE_DIR}
    RESULT_VARIABLE quiche_submodule_result
  )

  if(NOT quiche_submodule_result EQUAL 0)
    message(WARNING "Quiche submodule init returned ${quiche_submodule_result}, continuing anyway...")
  endif()

  # Configure quiche build
  # Bilibili's quiche uses C++17 and has its own dependencies bundled
  set(QUICHE_CMAKE_ARGS
    -G "${CMAKE_GENERATOR}"
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    -DENABLE_LINK_TCMALLOC=OFF
  )

  # Pass MSVC runtime settings
  if(MSVC AND CMAKE_MSVC_RUNTIME_LIBRARY)
    list(APPEND QUICHE_CMAKE_ARGS
      -DCMAKE_POLICY_DEFAULT_CMP0091=NEW
      -DCMAKE_MSVC_RUNTIME_LIBRARY=${CMAKE_MSVC_RUNTIME_LIBRARY}
    )
  endif()

  # Pass generator platform for Visual Studio
  if(CMAKE_GENERATOR_PLATFORM)
    list(APPEND QUICHE_CMAKE_ARGS -A ${CMAKE_GENERATOR_PLATFORM})
  endif()

  message(STATUS "Configuring quiche...")
  message(STATUS "Quiche cmake args: ${QUICHE_CMAKE_ARGS}")

  execute_process(
    COMMAND ${CMAKE_COMMAND}
      ${QUICHE_CMAKE_ARGS}
      ${quiche_SOURCE_DIR}
    WORKING_DIRECTORY ${quiche_BINARY_DIR}
    RESULT_VARIABLE quiche_config_result
    OUTPUT_VARIABLE quiche_config_output
    ERROR_VARIABLE quiche_config_error
  )

  if(NOT quiche_config_result EQUAL 0)
    message(STATUS "Quiche config output: ${quiche_config_output}")
    message(STATUS "Quiche config error: ${quiche_config_error}")
    message(FATAL_ERROR "Quiche configuration failed with code ${quiche_config_result}")
  endif()

  # Build quiche library
  message(STATUS "Building quiche...")
  include(ProcessorCount)
  ProcessorCount(NPROC)
  if(NPROC EQUAL 0)
    set(NPROC 4)
  endif()

  execute_process(
    COMMAND ${CMAKE_COMMAND} --build . --target quiche --parallel ${NPROC}
    WORKING_DIRECTORY ${quiche_BINARY_DIR}
    RESULT_VARIABLE quiche_build_result
    OUTPUT_VARIABLE quiche_build_output
    ERROR_VARIABLE quiche_build_error
  )

  if(NOT quiche_build_result EQUAL 0)
    message(STATUS "Quiche build output: ${quiche_build_output}")
    message(STATUS "Quiche build error: ${quiche_build_error}")
    message(FATAL_ERROR "Quiche build failed with code ${quiche_build_result}")
  endif()

  message(STATUS "Quiche build complete")
endif()

# Create imported target for quiche
add_library(quiche::quiche STATIC IMPORTED GLOBAL)

# Find the built library
if(WIN32)
  set(QUICHE_LIB_PATH "${quiche_BINARY_DIR}/quiche.lib")
else()
  set(QUICHE_LIB_PATH "${quiche_BINARY_DIR}/libquiche.a")
endif()

if(NOT EXISTS "${QUICHE_LIB_PATH}")
  message(FATAL_ERROR "Quiche library not found at ${QUICHE_LIB_PATH}")
endif()

# Set up include directories
# Bilibili's quiche has headers in multiple locations
set(QUICHE_INCLUDE_DIRS
  "${quiche_SOURCE_DIR}"
  "${quiche_SOURCE_DIR}/quiche"
  "${quiche_SOURCE_DIR}/platform"
  "${quiche_SOURCE_DIR}/third_party/abseil-cpp"
  "${quiche_SOURCE_DIR}/third_party/boringssl/include"
  "${quiche_SOURCE_DIR}/third_party/googleurl"
)

set_target_properties(quiche::quiche PROPERTIES
  IMPORTED_LOCATION "${QUICHE_LIB_PATH}"
  INTERFACE_INCLUDE_DIRECTORIES "${QUICHE_INCLUDE_DIRS}"
)

# Quiche depends on several libraries that are built alongside it
# These need to be linked as well
# TODO: Add abseil, protobuf, zlib dependencies

message(STATUS "Quiche library: ${QUICHE_LIB_PATH}")
message(STATUS "Quiche includes: ${QUICHE_INCLUDE_DIRS}")
