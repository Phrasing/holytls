# Fetch and build ngtcp2 - QUIC transport library
# ngtcp2 provides the QUIC protocol implementation
# It has native BoringSSL support via libngtcp2_crypto_boringssl

include(FetchContent)

message(STATUS "Fetching ngtcp2...")

FetchContent_Declare(
  ngtcp2
  GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git
  GIT_TAG        v1.9.1
  GIT_SHALLOW    TRUE
  GIT_PROGRESS   TRUE
)

FetchContent_GetProperties(ngtcp2)
if(NOT ngtcp2_POPULATED)
  FetchContent_Populate(ngtcp2)

  # Configure ngtcp2 build options
  set(ENABLE_SHARED_LIB OFF CACHE BOOL "" FORCE)
  set(ENABLE_STATIC_LIB ON CACHE BOOL "" FORCE)
  set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
  set(ENABLE_GNUTLS OFF CACHE BOOL "" FORCE)
  set(ENABLE_OPENSSL OFF CACHE BOOL "" FORCE)
  set(ENABLE_BORINGSSL ON CACHE BOOL "" FORCE)
  set(ENABLE_PICOTLS OFF CACHE BOOL "" FORCE)
  set(ENABLE_WOLFSSL OFF CACHE BOOL "" FORCE)

  # Point ngtcp2 to our BoringSSL
  set(BORINGSSL_INCLUDE_DIR "${boringssl_SOURCE_DIR}/include" CACHE PATH "" FORCE)
  set(BORINGSSL_LIBRARIES "boringssl::ssl;boringssl::crypto" CACHE STRING "" FORCE)

  # Patch CMakeLists.txt to rename "check" target that conflicts with nghttp2
  file(READ "${ngtcp2_SOURCE_DIR}/CMakeLists.txt" _ngtcp2_cmake_content)
  string(REPLACE
    "add_custom_target(check COMMAND"
    "add_custom_target(ngtcp2_check COMMAND"
    _ngtcp2_cmake_content "${_ngtcp2_cmake_content}")
  file(WRITE "${ngtcp2_SOURCE_DIR}/CMakeLists.txt" "${_ngtcp2_cmake_content}")

  add_subdirectory(${ngtcp2_SOURCE_DIR} ${ngtcp2_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

# Create alias targets for consistency
if(TARGET ngtcp2_static)
  add_library(ngtcp2::ngtcp2 ALIAS ngtcp2_static)
endif()

if(TARGET ngtcp2_crypto_boringssl_static)
  add_library(ngtcp2::crypto_boringssl ALIAS ngtcp2_crypto_boringssl_static)
endif()

message(STATUS "ngtcp2 configured with BoringSSL support")
