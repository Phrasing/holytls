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

  # Apply MSVC-specific patches to BoringSSL source
  if(MSVC)
    message(STATUS "Applying MSVC patches to BoringSSL...")

    # Patch 1: Fix strdup -> _strdup in extensions.cc
    # Make idempotent: first normalize any previous patches, then apply
    file(READ "${boringssl_SOURCE_DIR}/ssl/extensions.cc" EXTENSIONS_CC)
    string(REPLACE "_strdup(" "strdup(" EXTENSIONS_CC "${EXTENSIONS_CC}")
    string(REPLACE "strdup(" "_strdup(" EXTENSIONS_CC "${EXTENSIONS_CC}")
    file(WRITE "${boringssl_SOURCE_DIR}/ssl/extensions.cc" "${EXTENSIONS_CC}")

    # Patch 2: Fix bssl::Span conversion in handshake_client.cc
    # MSVC 2026 is stricter about implicit pointer-to-Span conversion in ternary expressions
    # Only replace usages (followed by : or ;), not declarations (followed by [)
    file(READ "${boringssl_SOURCE_DIR}/ssl/handshake_client.cc" HANDSHAKE_CC)
    # Replace ternary branch usages (name followed by colon or semicolon with optional whitespace)
    string(REPLACE "kCiphersAESHardware :" "bssl::Span<const uint16_t>(kCiphersAESHardware) :" HANDSHAKE_CC "${HANDSHAKE_CC}")
    string(REPLACE "kCiphersAESHardware;" "bssl::Span<const uint16_t>(kCiphersAESHardware);" HANDSHAKE_CC "${HANDSHAKE_CC}")
    string(REPLACE "kCiphersFirefox :" "bssl::Span<const uint16_t>(kCiphersFirefox) :" HANDSHAKE_CC "${HANDSHAKE_CC}")
    string(REPLACE "kCiphersFirefox;" "bssl::Span<const uint16_t>(kCiphersFirefox);" HANDSHAKE_CC "${HANDSHAKE_CC}")
    string(REPLACE "kCiphersChrome :" "bssl::Span<const uint16_t>(kCiphersChrome) :" HANDSHAKE_CC "${HANDSHAKE_CC}")
    string(REPLACE "kCiphersChrome;" "bssl::Span<const uint16_t>(kCiphersChrome);" HANDSHAKE_CC "${HANDSHAKE_CC}")
    string(REPLACE "kCiphersEdge :" "bssl::Span<const uint16_t>(kCiphersEdge) :" HANDSHAKE_CC "${HANDSHAKE_CC}")
    string(REPLACE "kCiphersEdge;" "bssl::Span<const uint16_t>(kCiphersEdge);" HANDSHAKE_CC "${HANDSHAKE_CC}")
    string(REPLACE "kCiphersSafari :" "bssl::Span<const uint16_t>(kCiphersSafari) :" HANDSHAKE_CC "${HANDSHAKE_CC}")
    string(REPLACE "kCiphersSafari;" "bssl::Span<const uint16_t>(kCiphersSafari);" HANDSHAKE_CC "${HANDSHAKE_CC}")
    file(WRITE "${boringssl_SOURCE_DIR}/ssl/handshake_client.cc" "${HANDSHAKE_CC}")

    message(STATUS "MSVC patches applied")
  endif()

  # Platform-specific compiler flags for BoringSSL
  if(MSVC)
    # MSVC: Use standard flags
    set(BORINGSSL_C_FLAGS "")
    set(BORINGSSL_CXX_FLAGS "")
  else()
    # GCC/Clang: Use position-independent code
    set(BORINGSSL_C_FLAGS "-fPIC")
    set(BORINGSSL_CXX_FLAGS "-fPIC")
  endif()

  # Build BoringSSL
  message(STATUS "Configuring BoringSSL...")

  # Build command arguments
  set(BORINGSSL_CMAKE_ARGS
    -G "${CMAKE_GENERATOR}"
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    "-DCMAKE_C_FLAGS=${BORINGSSL_C_FLAGS}"
    "-DCMAKE_CXX_FLAGS=${BORINGSSL_CXX_FLAGS}"
  )

  # Pass MSVC runtime library setting to BoringSSL
  if(MSVC AND CMAKE_MSVC_RUNTIME_LIBRARY)
    list(APPEND BORINGSSL_CMAKE_ARGS
      -DCMAKE_POLICY_DEFAULT_CMP0091=NEW
      -DCMAKE_MSVC_RUNTIME_LIBRARY=${CMAKE_MSVC_RUNTIME_LIBRARY}
    )
    message(STATUS "BoringSSL using MSVC runtime: ${CMAKE_MSVC_RUNTIME_LIBRARY}")
  endif()

  # Pass generator platform for Visual Studio (x64, Win32, etc.)
  if(CMAKE_GENERATOR_PLATFORM)
    list(APPEND BORINGSSL_CMAKE_ARGS -A ${CMAKE_GENERATOR_PLATFORM})
  endif()

  execute_process(
    COMMAND ${CMAKE_COMMAND}
      ${BORINGSSL_CMAKE_ARGS}
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

  # Build BoringSSL
  # For multi-config generators (Visual Studio), build both Release and Debug
  # This ensures both /MT and /MTd runtime libraries are available
  if(CMAKE_GENERATOR MATCHES "Visual Studio")
    message(STATUS "Building BoringSSL Release...")
    execute_process(
      COMMAND ${CMAKE_COMMAND} --build . --config Release --parallel ${NPROC}
      WORKING_DIRECTORY ${boringssl_BINARY_DIR}
      RESULT_VARIABLE boringssl_release_result
    )
    if(NOT boringssl_release_result EQUAL 0)
      message(FATAL_ERROR "BoringSSL Release build failed")
    endif()

    message(STATUS "Building BoringSSL Debug...")
    execute_process(
      COMMAND ${CMAKE_COMMAND} --build . --config Debug --parallel ${NPROC}
      WORKING_DIRECTORY ${boringssl_BINARY_DIR}
      RESULT_VARIABLE boringssl_debug_result
    )
    if(NOT boringssl_debug_result EQUAL 0)
      message(FATAL_ERROR "BoringSSL Debug build failed")
    endif()
  else()
    # Single-config generators (Makefiles, Ninja)
    execute_process(
      COMMAND ${CMAKE_COMMAND} --build . --parallel ${NPROC}
      WORKING_DIRECTORY ${boringssl_BINARY_DIR}
      RESULT_VARIABLE boringssl_build_result
    )
    if(NOT boringssl_build_result EQUAL 0)
      message(FATAL_ERROR "BoringSSL build failed")
    endif()
  endif()

  message(STATUS "BoringSSL build complete")
endif()

# Create imported targets with proper paths for each configuration
add_library(boringssl::crypto STATIC IMPORTED GLOBAL)
add_library(boringssl::ssl STATIC IMPORTED GLOBAL)

if(WIN32)
  if(CMAKE_GENERATOR MATCHES "Visual Studio")
    # Multi-config generator: set up both Release and Debug locations
    # Visual Studio puts outputs in config-specific subdirectories
    set(BORINGSSL_CRYPTO_LIB_RELEASE "${boringssl_BINARY_DIR}/crypto/Release/crypto.lib")
    set(BORINGSSL_CRYPTO_LIB_DEBUG "${boringssl_BINARY_DIR}/crypto/Debug/crypto.lib")
    set(BORINGSSL_SSL_LIB_RELEASE "${boringssl_BINARY_DIR}/ssl/Release/ssl.lib")
    set(BORINGSSL_SSL_LIB_DEBUG "${boringssl_BINARY_DIR}/ssl/Debug/ssl.lib")

    set_target_properties(boringssl::crypto PROPERTIES
      IMPORTED_CONFIGURATIONS "Release;Debug"
      IMPORTED_LOCATION_RELEASE "${BORINGSSL_CRYPTO_LIB_RELEASE}"
      IMPORTED_LOCATION_DEBUG "${BORINGSSL_CRYPTO_LIB_DEBUG}"
      INTERFACE_INCLUDE_DIRECTORIES "${boringssl_SOURCE_DIR}/include"
    )
    set_target_properties(boringssl::ssl PROPERTIES
      IMPORTED_CONFIGURATIONS "Release;Debug"
      IMPORTED_LOCATION_RELEASE "${BORINGSSL_SSL_LIB_RELEASE}"
      IMPORTED_LOCATION_DEBUG "${BORINGSSL_SSL_LIB_DEBUG}"
      INTERFACE_INCLUDE_DIRECTORIES "${boringssl_SOURCE_DIR}/include"
    )

    set(BORINGSSL_CRYPTO_LIB "${BORINGSSL_CRYPTO_LIB_RELEASE}")
    set(BORINGSSL_SSL_LIB "${BORINGSSL_SSL_LIB_RELEASE}")
  else()
    # Single-config generator on Windows (Ninja, etc.)
    set(BORINGSSL_CRYPTO_LIB "${boringssl_BINARY_DIR}/crypto/crypto.lib")
    set(BORINGSSL_SSL_LIB "${boringssl_BINARY_DIR}/ssl/ssl.lib")
    set_target_properties(boringssl::crypto PROPERTIES
      IMPORTED_LOCATION "${BORINGSSL_CRYPTO_LIB}"
      INTERFACE_INCLUDE_DIRECTORIES "${boringssl_SOURCE_DIR}/include"
    )
    set_target_properties(boringssl::ssl PROPERTIES
      IMPORTED_LOCATION "${BORINGSSL_SSL_LIB}"
      INTERFACE_INCLUDE_DIRECTORIES "${boringssl_SOURCE_DIR}/include"
    )
  endif()
else()
  # Unix
  set(BORINGSSL_CRYPTO_LIB "${boringssl_BINARY_DIR}/crypto/libcrypto.a")
  set(BORINGSSL_SSL_LIB "${boringssl_BINARY_DIR}/ssl/libssl.a")
  set_target_properties(boringssl::crypto PROPERTIES
    IMPORTED_LOCATION "${BORINGSSL_CRYPTO_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${boringssl_SOURCE_DIR}/include"
  )
  set_target_properties(boringssl::ssl PROPERTIES
    IMPORTED_LOCATION "${BORINGSSL_SSL_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${boringssl_SOURCE_DIR}/include"
  )
endif()

target_link_libraries(boringssl::ssl INTERFACE boringssl::crypto)

message(STATUS "BoringSSL include dir: ${boringssl_SOURCE_DIR}/include")
message(STATUS "BoringSSL libraries: ${BORINGSSL_SSL_LIB}, ${BORINGSSL_CRYPTO_LIB}")
