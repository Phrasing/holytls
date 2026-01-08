# Fetch and build lexiforest/boringssl with Chrome impersonation patches

include(FetchContent)

message(STATUS "Fetching lexiforest/boringssl...")

FetchContent_Declare(
  boringssl
  GIT_REPOSITORY https://github.com/lexiforest/boringssl.git
  GIT_TAG        impersonate
  GIT_SHALLOW    TRUE
  GIT_PROGRESS   TRUE
)

# Check for Go (required for BoringSSL code generation)
find_program(GO_EXECUTABLE go REQUIRED)
message(STATUS "Found Go: ${GO_EXECUTABLE}")

FetchContent_GetProperties(boringssl)
if(NOT boringssl_POPULATED)
  FetchContent_Populate(boringssl)

  # Build BoringSSL
  message(STATUS "Configuring BoringSSL...")
  execute_process(
    COMMAND ${CMAKE_COMMAND}
      -G "${CMAKE_GENERATOR}"
      -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
      -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
      -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON
      -DCMAKE_C_FLAGS=-fPIC
      -DCMAKE_CXX_FLAGS=-fPIC
      ${boringssl_SOURCE_DIR}
    WORKING_DIRECTORY ${boringssl_BINARY_DIR}
    RESULT_VARIABLE boringssl_config_result
  )

  if(NOT boringssl_config_result EQUAL 0)
    message(FATAL_ERROR "BoringSSL configuration failed")
  endif()

  message(STATUS "Building BoringSSL...")
  include(ProcessorCount)
  ProcessorCount(NPROC)
  if(NPROC EQUAL 0)
    set(NPROC 4)
  endif()

  execute_process(
    COMMAND ${CMAKE_COMMAND} --build . --parallel ${NPROC}
    WORKING_DIRECTORY ${boringssl_BINARY_DIR}
    RESULT_VARIABLE boringssl_build_result
  )

  if(NOT boringssl_build_result EQUAL 0)
    message(FATAL_ERROR "BoringSSL build failed")
  endif()

  message(STATUS "BoringSSL build complete")
endif()

# Create imported targets
add_library(boringssl::crypto STATIC IMPORTED GLOBAL)
set_target_properties(boringssl::crypto PROPERTIES
  IMPORTED_LOCATION "${boringssl_BINARY_DIR}/crypto/libcrypto.a"
  INTERFACE_INCLUDE_DIRECTORIES "${boringssl_SOURCE_DIR}/include"
)

add_library(boringssl::ssl STATIC IMPORTED GLOBAL)
set_target_properties(boringssl::ssl PROPERTIES
  IMPORTED_LOCATION "${boringssl_BINARY_DIR}/ssl/libssl.a"
  INTERFACE_INCLUDE_DIRECTORIES "${boringssl_SOURCE_DIR}/include"
)
target_link_libraries(boringssl::ssl INTERFACE boringssl::crypto)

message(STATUS "BoringSSL include dir: ${boringssl_SOURCE_DIR}/include")
message(STATUS "BoringSSL libraries: ${boringssl_BINARY_DIR}/ssl/libssl.a, ${boringssl_BINARY_DIR}/crypto/libcrypto.a")
