# Compiler flags following Google C++ Style Guide recommendations

# Platform-specific common flags (applied via target_compile_options)
if(MSVC)
  # MSVC flags
  set(HOLYTLS_COMMON_FLAGS
    /W4                # Warning level 4
    /permissive-       # Strict conformance mode
    /utf-8             # UTF-8 source and execution charset
    /Zc:__cplusplus    # Report correct __cplusplus macro
    /GR-               # Disable RTTI
    /EHs-c-            # Disable C++ exceptions
  )

  # Release flags for MSVC
  set(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /DNDEBUG")
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")

  # Debug flags for MSVC
  set(CMAKE_CXX_FLAGS_DEBUG "/Od /Zi")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")

  # RelWithDebInfo for MSVC
  set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/O2 /Zi /DNDEBUG")
  set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")

else()
  # GCC/Clang flags
  set(HOLYTLS_COMMON_FLAGS
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
    -Wformat=2
    -Wshadow
    -Wunused
    -Wimplicit-fallthrough
    -fno-common
    -fno-exceptions
    -fno-rtti
  )

  # GCC-specific flags
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    list(APPEND HOLYTLS_COMMON_FLAGS
      -Wmisleading-indentation
      -Wduplicated-cond
      -Wlogical-op
    )
  endif()

  # Release flags
  set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native -mtune=native")
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")

  # Debug flags
  set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g3 -fno-omit-frame-pointer")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")

  # RelWithDebInfo
  set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG -fno-omit-frame-pointer")
  set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
endif()

# NOTE: We do NOT use add_compile_options() globally because that applies
# to ALL targets including dependencies like nghttp2 and boringssl.
# Instead, flags are applied only to holytls targets in CMakeLists.txt.

# Sanitizer support (GCC/Clang only)
if(NOT MSVC)
  if(HOLYTLS_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
  endif()

  if(HOLYTLS_TSAN)
    add_compile_options(-fsanitize=thread)
    add_link_options(-fsanitize=thread)
  endif()
endif()
